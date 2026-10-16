// Package check seals folders and checks them against manifests. It ties scanning, comparing and
// signatures together and is used by the command line and by tests.
package check

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/SandSoftwareSolutions/assay/internal/compare"
	"github.com/SandSoftwareSolutions/assay/internal/ignore"
	"github.com/SandSoftwareSolutions/assay/internal/manifest"
	"github.com/SandSoftwareSolutions/assay/internal/scan"
	"github.com/SandSoftwareSolutions/assay/internal/sign"
)

// IgnoreFile is the optional file with ignore patterns, read when sealing.
const IgnoreFile = ".assayignore"

// SealOptions configure Seal.
type SealOptions struct {
	Dir          string
	ManifestPath string // empty: <Dir>/.assay.json
	Algorithm    string // empty: sha256
	Exclude      []string
	Key          ed25519.PrivateKey // optional: sign the manifest
	Workers      int
	Now          time.Time
	Progress     func(done, total int)
	// Fast reuses hashes of files whose size and modification time did not change since the last run (see
	// scan.Cache). CacheFile overrides where that memory is kept.
	Fast      bool
	CacheFile string
}

// SealResult is what Seal produced.
type SealResult struct {
	Manifest     *manifest.Manifest
	ManifestPath string
	Scan         *scan.Result
	// Previous is the diff against the manifest that was there before, when there was a valid one.
	Previous *compare.Diff
	// Reused is the number of file hashes taken from the fast-mode cache.
	Reused int
}

func manifestPath(dir, given string) string {
	if given != "" {
		return given
	}
	return filepath.Join(dir, manifest.DefaultFile)
}

// skipPaths returns the manifest's path relative to dir when it lives inside dir.
func skipPaths(dir, mpath string) []string {
	absDir, err1 := filepath.Abs(dir)
	absM, err2 := filepath.Abs(mpath)
	if err1 != nil || err2 != nil {
		return nil
	}
	rel, err := filepath.Rel(absDir, absM)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return nil
	}
	return []string{filepath.ToSlash(rel)}
}

// Seal hashes dir and writes the manifest.
func Seal(ctx context.Context, o SealOptions) (*SealResult, error) {
	if o.Algorithm == "" {
		o.Algorithm = manifest.DefaultAlgorithm
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if _, err := statDir(o.Dir); err != nil {
		return nil, err
	}
	mpath := manifestPath(o.Dir, o.ManifestPath)
	patterns, err := readPatterns(o.Dir)
	if err != nil {
		return nil, err
	}
	patterns = append(patterns, o.Exclude...)
	matcher := ignore.New(patterns...)

	cachePath := ""
	var cache *scan.Cache
	if o.Fast {
		cachePath = fastCachePath(o.Dir, o.Algorithm, o.CacheFile)
		cache = scan.LoadCache(cachePath, o.Algorithm)
	}
	res, err := scan.Scan(ctx, scan.Options{Root: o.Dir, Algorithm: o.Algorithm, Ignore: matcher,
		Skip: skipPaths(o.Dir, mpath), Workers: o.Workers, Progress: o.Progress, Cache: cache})
	if err != nil {
		return nil, err
	}
	if len(res.Unreadable) > 0 {
		p := res.Unreadable[0]
		return nil, fmt.Errorf("cannot read %s: %v (and %d more); fix the permissions or exclude it", p.Path, p.Err, len(res.Unreadable)-1)
	}
	m, err := manifest.New(o.Algorithm, o.Now.UTC().Format(time.RFC3339), res.Files)
	if err != nil {
		return nil, err
	}
	m.Ignore = patterns
	if o.Key != nil {
		pub := o.Key.Public().(ed25519.PublicKey)
		m.Signature = &manifest.Signature{
			Alg:   sign.Algorithm,
			KeyID: sign.KeyID(pub),
			Value: sign.Sign(o.Key, m.Algorithm, m.Root, manifest.IgnoreDigest(m.Ignore)),
		}
	}
	out := &SealResult{Manifest: m, ManifestPath: mpath, Scan: res, Reused: res.Reused}
	if o.Fast {
		_ = scan.Save(cachePath, o.Algorithm, res.CacheEntries, o.Now) // best effort: a cache only speeds things up
	}
	if prev, err := manifest.Read(mpath); err == nil {
		d := compare.Compare(prev.Files, m.Files)
		out.Previous = &d
	}
	if err := manifest.Write(mpath, m); err != nil {
		return nil, fmt.Errorf("cannot write manifest: %w", err)
	}
	return out, nil
}

func readPatterns(dir string) ([]string, error) {
	return ignore.ReadPatterns(dir, IgnoreFile)
}

func statDir(dir string) (fs.FileInfo, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	return st, nil
}

// SignatureStatus tells what is known about the manifest signature.
type SignatureStatus string

// Possible signature states.
const (
	SigNone       SignatureStatus = "none"       // the manifest is not signed
	SigUnverified SignatureStatus = "unverified" // signed, but no public key was given
	SigValid      SignatureStatus = "valid"
	SigInvalid    SignatureStatus = "invalid"
)

// Options configure Check.
type Options struct {
	Dir          string
	ManifestPath string
	PublicKey    ed25519.PublicKey // optional
	Workers      int
	Now          time.Time
	Progress     func(done, total int)
	Fast         bool
	CacheFile    string
}

// Result is the outcome of a check.
type Result struct {
	ManifestPath string
	Manifest     *manifest.Manifest
	Diff         compare.Diff
	Unreadable   []scan.Problem
	Skipped      []string
	// RootDamaged is true when the manifest's own root hash does not match its file list.
	RootDamaged bool
	Signature   SignatureStatus
	KeyID       string
	CheckedAt   time.Time
	// Reused is the number of file hashes taken from the fast-mode cache.
	Reused int
}

// OK reports whether the folder matches the manifest and nothing is wrong with the manifest.
func (r *Result) OK() bool {
	return r.Diff.Clean() && !r.RootDamaged && len(r.Unreadable) == 0 && r.Signature != SigInvalid
}

// Check compares dir with its manifest.
func Check(ctx context.Context, o Options) (*Result, error) {
	if _, err := statDir(o.Dir); err != nil {
		return nil, err
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	mpath := manifestPath(o.Dir, o.ManifestPath)
	m, err := manifest.Read(mpath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no manifest at %s; create one with: assay seal %s", mpath, o.Dir)
	}
	if err != nil {
		return nil, err
	}
	cachePath := ""
	var cache *scan.Cache
	if o.Fast {
		cachePath = fastCachePath(o.Dir, m.Algorithm, o.CacheFile)
		cache = scan.LoadCache(cachePath, m.Algorithm)
	}
	res, err := scan.Scan(ctx, scan.Options{Root: o.Dir, Algorithm: m.Algorithm, Ignore: ignore.New(m.Ignore...),
		Skip: skipPaths(o.Dir, mpath), Workers: o.Workers, Progress: o.Progress, Cache: cache})
	if err != nil {
		return nil, err
	}
	if o.Fast {
		_ = scan.Save(cachePath, m.Algorithm, res.CacheEntries, o.Now)
	}
	r := &Result{
		ManifestPath: mpath, Manifest: m, Diff: compare.Compare(m.Files, res.Files),
		Unreadable: res.Unreadable, Skipped: res.Skipped, RootDamaged: !m.RootMatches(),
		Signature: SigNone, CheckedAt: o.Now, Reused: res.Reused,
	}
	// Unreadable files must not be reported as removed: they are there, we just cannot see them.
	if len(res.Unreadable) > 0 {
		bad := map[string]bool{}
		for _, p := range res.Unreadable {
			bad[p.Path] = true
		}
		r.Diff = dropRemoved(r.Diff, bad)
	}
	if m.Signature != nil {
		r.KeyID = m.Signature.KeyID
		r.Signature = SigUnverified
		if o.PublicKey != nil {
			ok := m.Signature.Alg == sign.Algorithm &&
				m.Signature.KeyID == sign.KeyID(o.PublicKey) &&
				!r.RootDamaged &&
				sign.Verify(o.PublicKey, m.Algorithm, m.Root, manifest.IgnoreDigest(m.Ignore), m.Signature.Value)
			if ok {
				r.Signature = SigValid
			} else {
				r.Signature = SigInvalid
			}
		}
	} else if o.PublicKey != nil {
		r.Signature = SigInvalid // a key was given but the manifest is not signed: do not let that pass silently
	}
	return r, nil
}

func dropRemoved(d compare.Diff, unreadable map[string]bool) compare.Diff {
	var removed []string
	for _, p := range d.Removed {
		if !unreadable[p] {
			removed = append(removed, p)
		}
	}
	d.Removed = removed
	return d
}

// fastCachePath is where the fast-mode memory of a folder lives: the given file, or a file in the user's cache
// folder named after the folder and the algorithm, so different folders never share one.
func fastCachePath(dir, algorithm, explicit string) string {
	if explicit != "" {
		return explicit
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs + "\x00" + algorithm))
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "assay", hex.EncodeToString(sum[:8])+".json")
}
