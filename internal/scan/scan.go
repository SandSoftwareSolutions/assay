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

	"github.com/SandSoftwareSolutions/assay/internal/ignore"
	"github.com/SandSoftwareSolutions/assay/internal/manifest"
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
	// Cache, when set, lets files with an unchanged size and modification time reuse their earlier hash.
	Cache *Cache
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
	// Reused is the number of hashes taken from the cache instead of reading the file.
	Reused int
	// CacheEntries describes every hashed file, to be saved for the next scan.
	CacheEntries map[string]CacheEntry
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
		entry  manifest.Entry
		err    error
		cached bool
		cache  CacheEntry
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
				entry, ce, cached, err := hashFile(opts.Root, rels[i], opts.Algorithm, opts.Cache)
				results[i] = outcome{entry: entry, err: err, cached: cached, cache: ce}
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
		if r.cached {
			res.Reused++
		}
		if res.CacheEntries == nil {
			res.CacheEntries = map[string]CacheEntry{}
		}
		res.CacheEntries[rels[i]] = r.cache
	}
	sort.Slice(res.Unreadable, func(i, j int) bool { return res.Unreadable[i].Path < res.Unreadable[j].Path })
	sort.Strings(res.Skipped)
	return res, nil
}

func hashFile(root, rel, algorithm string, cache *Cache) (manifest.Entry, CacheEntry, bool, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	st, err := os.Stat(path)
	if err != nil {
		return manifest.Entry{}, CacheEntry{}, false, err
	}
	size, modNs := st.Size(), st.ModTime().UnixNano()
	if hash, ok := cache.lookup(rel, size, modNs); ok {
		return manifest.Entry{Path: rel, Size: size, Hash: hash}, CacheEntry{Size: size, ModNs: modNs, Hash: hash}, true, nil
	}
	h, err := manifest.NewHash(algorithm)
	if err != nil {
		return manifest.Entry{}, CacheEntry{}, false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest.Entry{}, CacheEntry{}, false, err
	}
	defer f.Close()
	n, err := io.Copy(h, f)
	if err != nil {
		return manifest.Entry{}, CacheEntry{}, false, fmt.Errorf("read: %w", err)
	}
	hash := hex.EncodeToString(h.Sum(nil))
	// If the file changed while it was read, do not remember it: the cached values would not match the content.
	if after, err := os.Stat(path); err != nil || after.Size() != size || after.ModTime().UnixNano() != modNs {
		return manifest.Entry{Path: rel, Size: n, Hash: hash}, CacheEntry{Size: -1}, false, nil
	}
	return manifest.Entry{Path: rel, Size: n, Hash: hash}, CacheEntry{Size: size, ModNs: modNs, Hash: hash}, false, nil
}
