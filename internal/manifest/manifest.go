// Package manifest defines the sealed state of a folder: a hash for every file, a root hash over
// all of them and an optional signature.
package manifest

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Format is the manifest format version written by this release.
const Format = 1

// DefaultFile is the manifest name inside a sealed folder.
const DefaultFile = ".hallmark.json"

// DefaultAlgorithm is used when none is chosen.
const DefaultAlgorithm = "sha256"

var algorithms = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// Algorithms lists the supported hash algorithms.
func Algorithms() []string {
	names := make([]string, 0, len(algorithms))
	for n := range algorithms {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NewHash returns a new hash for the named algorithm.
func NewHash(algorithm string) (hash.Hash, error) {
	f, ok := algorithms[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm %q (supported: %s)", algorithm, strings.Join(Algorithms(), ", "))
	}
	return f(), nil
}

// Entry describes one file.
type Entry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Hash string `json:"hash"`
}

// Signature is an Ed25519 signature over the root hash.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// Manifest is the content of a manifest file.
//
// It holds no per-file timestamps, so sealing an unchanged folder twice gives the same entries
// and the same root, which keeps manifests friendly to version control.
type Manifest struct {
	Format    int    `json:"format"`
	Tool      string `json:"tool"`
	Algorithm string `json:"algorithm"`
	Created   string `json:"created"`
	Root      string `json:"root"`
	// Ignore holds the patterns that were in effect when the folder was sealed. Checking uses these, so
	// a change of .hallmarkignore later cannot make files appear or disappear.
	Ignore    []string   `json:"ignore,omitempty"`
	Files     []Entry    `json:"files"`
	Signature *Signature `json:"signature,omitempty"`
}

// RootHash hashes the sorted "hash size path" lines of files.
func RootHash(algorithm string, files []Entry) (string, error) {
	h, err := NewHash(algorithm)
	if err != nil {
		return "", err
	}
	sorted := append([]Entry(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, e := range sorted {
		fmt.Fprintf(h, "%s %d %s\n", e.Hash, e.Size, e.Path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IgnoreDigest is a stable digest of the ignore patterns, covered by the signature.
func IgnoreDigest(patterns []string) string {
	sum := sha256.Sum256([]byte(strings.Join(patterns, "\n")))
	return hex.EncodeToString(sum[:])
}

// New builds a manifest for already hashed files.
func New(algorithm, created string, files []Entry) (*Manifest, error) {
	sorted := append([]Entry(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	root, err := RootHash(algorithm, sorted)
	if err != nil {
		return nil, err
	}
	return &Manifest{Format: Format, Tool: "hallmark", Algorithm: algorithm, Created: created, Root: root, Files: sorted}, nil
}

// RootMatches reports whether the stored root equals the root of the listed files.
func (m *Manifest) RootMatches() bool {
	root, err := RootHash(m.Algorithm, m.Files)
	return err == nil && root == m.Root
}

// Validate checks structure and content of a manifest that came from disk. A manifest is untrusted
// input: paths must stay inside the folder and hashes must have the right shape.
func (m *Manifest) Validate() error {
	if m.Tool != "hallmark" {
		return errors.New("not a hallmark manifest")
	}
	if m.Format != Format {
		return fmt.Errorf("unsupported manifest format %d (this version reads format %d)", m.Format, Format)
	}
	h, err := NewHash(m.Algorithm)
	if err != nil {
		return err
	}
	want := h.Size() * 2
	seen := make(map[string]bool, len(m.Files))
	for _, e := range m.Files {
		if err := checkPath(e.Path); err != nil {
			return fmt.Errorf("entry %q: %w", e.Path, err)
		}
		if seen[e.Path] {
			return fmt.Errorf("entry %q appears twice", e.Path)
		}
		seen[e.Path] = true
		if len(e.Hash) != want || !isHex(e.Hash) {
			return fmt.Errorf("entry %q: hash is not a %d character hex string", e.Path, want)
		}
		if e.Size < 0 {
			return fmt.Errorf("entry %q: negative size", e.Path)
		}
	}
	if len(m.Root) != want || !isHex(m.Root) {
		return errors.New("root hash is not a valid hex string")
	}
	return nil
}

func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case strings.Contains(p, `\`):
		return errors.New("path must use forward slashes")
	case strings.HasPrefix(p, "/") || filepath.IsAbs(p) || (len(p) > 1 && p[1] == ':'):
		return errors.New("path must be relative")
	case path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../"):
		return errors.New("path must be clean and stay inside the folder")
	case strings.ContainsAny(p, "\n\r\x00"):
		return errors.New("path contains a control character")
	}
	return nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Read loads and validates a manifest file.
func Read(p string) (*Manifest, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", p, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &m, nil
}

// Write stores a manifest atomically (temporary file, then rename).
func Write(p string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(p), ".hallmark-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, p); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
