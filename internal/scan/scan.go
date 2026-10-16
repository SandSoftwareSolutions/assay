// Package scan walks a folder and hashes its files.
package scan

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/SandSoftwareSolutions/hallmark/internal/ignore"
	"github.com/SandSoftwareSolutions/hallmark/internal/manifest"
)

// Options control a scan.
type Options struct {
	Root      string
	Algorithm string
	Ignore    *ignore.Matcher
	// Skip lists relative paths (slash separated) that are never scanned, such as the manifest itself.
	Skip    []string
	Workers int
	// Progress is called with the number of files hashed so far (from several goroutines).
	Progress func(done, total int)
}

// Problem is a path that could not be read.
type Problem struct {
	Path string
	Err  error
}

// Result is the outcome of a scan.
type Result struct {
	Files      []manifest.Entry
	Unreadable []Problem
	// Skipped lists entries that are neither regular files nor directories (symlinks, sockets, ...).
	Skipped []string
}

// Scan hashes every regular file below opts.Root that is not ignored. Symbolic links are not
// followed and are reported as skipped. Files that cannot be read are collected in Unreadable;
// the scan carries on.
func Scan(ctx context.Context, opts Options) (*Result, error) {
	if _, err := manifest.NewHash(opts.Algorithm); err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, s := range opts.Skip {
		skip[s] = true
	}
	res := &Result{}
	var rels []string
	err := filepath.WalkDir(opts.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(opts.Root, p)
			res.Unreadable = append(res.Unreadable, Problem{Path: filepath.ToSlash(rel), Err: err})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(opts.Root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if skip[rel] || opts.Ignore.Match(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			res.Skipped = append(res.Skipped, rel)
			return nil
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(rels)

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(rels) && len(rels) > 0 {
		workers = len(rels)
	}
	type outcome struct {
		entry manifest.Entry
		err   error
	}
	results := make([]outcome, len(rels))
	jobs := make(chan int)
	var done int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				entry, err := hashFile(opts.Root, rels[i], opts.Algorithm)
				results[i] = outcome{entry: entry, err: err}
				if opts.Progress != nil {
					opts.Progress(int(atomic.AddInt64(&done, 1)), len(rels))
				}
			}
		}()
	}
send:
	for i := range rels {
		select {
		case <-ctx.Done():
			break send
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, r := range results {
		if r.err != nil {
			res.Unreadable = append(res.Unreadable, Problem{Path: rels[i], Err: r.err})
			continue
		}
		res.Files = append(res.Files, r.entry)
	}
	sort.Slice(res.Unreadable, func(i, j int) bool { return res.Unreadable[i].Path < res.Unreadable[j].Path })
	sort.Strings(res.Skipped)
	return res, nil
}

func hashFile(root, rel, algorithm string) (manifest.Entry, error) {
	h, err := manifest.NewHash(algorithm)
	if err != nil {
		return manifest.Entry{}, err
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return manifest.Entry{}, err
	}
	defer f.Close()
	n, err := io.Copy(h, f)
	if err != nil {
		return manifest.Entry{}, fmt.Errorf("read: %w", err)
	}
	return manifest.Entry{Path: rel, Size: n, Hash: hex.EncodeToString(h.Sum(nil))}, nil
}
