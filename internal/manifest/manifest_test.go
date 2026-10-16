package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func entries() []Entry {
	h := strings.Repeat("a", 64)
	return []Entry{{Path: "b.txt", Size: 1, Hash: h}, {Path: "a.txt", Size: 2, Hash: strings.Repeat("b", 64)}}
}

func TestNewSortsAndRootIsOrderIndependent(t *testing.T) {
	a, err := New("sha256", "t", entries())
	if err != nil {
		t.Fatal(err)
	}
	rev := entries()
	rev[0], rev[1] = rev[1], rev[0]
	b, _ := New("sha256", "t", rev)
	if a.Root != b.Root || a.Files[0].Path != "a.txt" {
		t.Fatalf("roots differ or not sorted: %s %s %v", a.Root, b.Root, a.Files)
	}
	if !a.RootMatches() {
		t.Fatal("fresh manifest must match its root")
	}
}

func TestRootChangesWithAnyField(t *testing.T) {
	base, _ := New("sha256", "t", entries())
	for name, mutate := range map[string]func([]Entry){
		"path": func(e []Entry) { e[0].Path = "z.txt" },
		"size": func(e []Entry) { e[0].Size++ },
		"hash": func(e []Entry) { e[0].Hash = strings.Repeat("c", 64) },
	} {
		e := entries()
		mutate(e)
		m, _ := New("sha256", "t", e)
		if m.Root == base.Root {
			t.Errorf("root did not change when %s changed", name)
		}
	}
	m, _ := New("sha512", "t", []Entry{})
	if len(m.Root) != 128 {
		t.Fatalf("sha512 root length %d", len(m.Root))
	}
}

func TestValidateRejectsHostileManifests(t *testing.T) {
	good, _ := New("sha256", "t", entries())
	if err := good.Validate(); err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	cases := map[string]func(m *Manifest){
		"parent path":     func(m *Manifest) { m.Files[0].Path = "../../etc/passwd" },
		"absolute path":   func(m *Manifest) { m.Files[0].Path = "/etc/passwd" },
		"drive path":      func(m *Manifest) { m.Files[0].Path = "C:/x" },
		"backslash":       func(m *Manifest) { m.Files[0].Path = `a\b` },
		"unclean":         func(m *Manifest) { m.Files[0].Path = "a/./b" },
		"newline in path": func(m *Manifest) { m.Files[0].Path = "a\nb" },
		"empty path":      func(m *Manifest) { m.Files[0].Path = "" },
		"duplicate":       func(m *Manifest) { m.Files[1].Path = m.Files[0].Path },
		"short hash":      func(m *Manifest) { m.Files[0].Hash = "abc" },
		"uppercase hash":  func(m *Manifest) { m.Files[0].Hash = strings.Repeat("A", 64) },
		"negative size":   func(m *Manifest) { m.Files[0].Size = -1 },
		"bad algorithm":   func(m *Manifest) { m.Algorithm = "md5" },
		"bad format":      func(m *Manifest) { m.Format = 99 },
		"wrong tool":      func(m *Manifest) { m.Tool = "other" },
		"bad root":        func(m *Manifest) { m.Root = "xyz" },
	}
	for name, mutate := range cases {
		m, _ := New("sha256", "t", entries())
		mutate(m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestWriteReadRoundTripAndAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	m, _ := New("sha256", "2026-01-01T00:00:00Z", entries())
	m.Ignore = []string{"*.log"}
	if err := Write(p, m); err != nil {
		t.Fatal(err)
	}
	got, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != m.Root || len(got.Files) != 2 || got.Ignore[0] != "*.log" {
		t.Fatalf("round trip: %+v", got)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".assay-*.tmp"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file must fail")
	}
	p := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(p, []byte("{nope"), 0o644)
	if _, err := Read(p); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("got %v", err)
	}
}

func TestIgnoreDigestIsStable(t *testing.T) {
	if IgnoreDigest([]string{"a", "b"}) == IgnoreDigest([]string{"b", "a"}) {
		t.Fatal("order must matter")
	}
	if IgnoreDigest(nil) != IgnoreDigest([]string{}) {
		t.Fatal("nil and empty must be equal")
	}
}

// FuzzValidate checks that no input makes manifest parsing or validation panic.
func FuzzValidate(f *testing.F) {
	good, _ := New("sha256", "t", entries())
	seed, _ := json.Marshal(good)
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":1,"tool":"assay","algorithm":"sha256","files":[{"path":"../x","size":-1,"hash":"zz"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m Manifest
		if json.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.Validate()
		_ = m.RootMatches()
	})
}
