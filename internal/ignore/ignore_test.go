package ignore

import (
	"path/filepath"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		isDir    bool
		want     bool
	}{
		{"base name at any depth", []string{"*.log"}, "a/b/c.log", false, true},
		{"no match", []string{"*.log"}, "a/b/c.txt", false, false},
		{"directory only pattern ignores directory", []string{"build/"}, "build", true, true},
		{"directory only pattern ignores nothing for a file", []string{"build/"}, "build", false, false},
		{"children of an ignored directory", []string{"node_modules/"}, "node_modules/x/y.js", false, true},
		{"anchored with leading slash", []string{"/dist"}, "dist", true, true},
		{"anchored does not match deeper", []string{"/dist"}, "src/dist", true, false},
		{"pattern with a slash is anchored", []string{"docs/*.md"}, "docs/a.md", false, true},
		{"pattern with a slash does not match deeper", []string{"docs/*.md"}, "x/docs/a.md", false, false},
		{"double star in the middle", []string{"a/**/z.txt"}, "a/b/c/z.txt", false, true},
		{"double star matches zero directories", []string{"a/**/z.txt"}, "a/z.txt", false, true},
		{"leading double star", []string{"**/cache"}, "x/y/cache", true, true},
		{"trailing double star", []string{"out/**"}, "out/a/b", false, true},
		{"negation re-includes a file", []string{"*.md", "!README.md"}, "README.md", false, false},
		{"negation keeps others ignored", []string{"*.md", "!README.md"}, "CHANGES.md", false, true},
		{"last rule wins", []string{"!keep.txt", "*.txt"}, "keep.txt", false, true},
		{"question mark", []string{"file?.txt"}, "file1.txt", false, true},
		{"character class", []string{"[ab].txt"}, "b.txt", false, true},
		{"negated character class", []string{"[!ab].txt"}, "a.txt", false, false},
		{"dotfiles", []string{".*"}, ".env", false, true},
		{"comment and blank lines are skipped", []string{"# note", "", "x.tmp"}, "x.tmp", false, true},
		{"root is never ignored", []string{"*"}, ".", true, false},
		{"dot slash prefix", []string{"a.txt"}, "./a.txt", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.patterns...).Match(tt.path, tt.isDir); got != tt.want {
				t.Fatalf("Match(%q) = %v, want %v (patterns %v)", tt.path, got, tt.want, tt.patterns)
			}
		})
	}
}

func TestZeroValueIgnoresNothing(t *testing.T) {
	var m *Matcher
	if m.Match("anything", false) {
		t.Fatal("nil matcher must ignore nothing")
	}
	if (&Matcher{}).Match("anything", false) {
		t.Fatal("empty matcher must ignore nothing")
	}
}

func TestPrependLetsUserRulesOverrideDefaults(t *testing.T) {
	user := New("!build/")
	m := user.Prepend("build/", "node_modules/")
	if m.Match("build", true) {
		t.Fatal("user negation must override the default")
	}
	if !m.Match("node_modules", true) {
		t.Fatal("defaults must still apply")
	}
}

func TestInvalidPatternDoesNotPanic(t *testing.T) {
	m := New("[", "a(b", "ok.txt")
	if !m.Match("ok.txt", false) {
		t.Fatal("later valid pattern must still work")
	}
}

// FuzzMatch checks that arbitrary patterns and paths never panic.
func FuzzMatch(f *testing.F) {
	f.Add("*.log", "a/b.log", false)
	f.Add("**/x/", "x", true)
	f.Add("[", "a", false)
	f.Fuzz(func(t *testing.T, pattern, path string, isDir bool) {
		New(pattern).Match(path, isDir)
	})
}

// On Windows a backslash is a path separator; elsewhere it is an ordinary file name character.
func TestNativeSeparator(t *testing.T) {
	m := New("docs/*.md")
	if !m.Match(filepath.Join("docs", "a.md"), false) {
		t.Fatal("a path built with the native separator must match")
	}
}
