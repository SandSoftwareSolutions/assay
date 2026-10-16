// Package ignore implements a small subset of gitignore semantics for .foundryignore files.
//
// Supported: comments (#), blank lines, negation (!), a trailing / (directories only), a leading /
// (anchored to the template root), * ? [..] and ** (any number of directories). As in git, a file
// below an ignored directory is ignored too and cannot be re-included on its own.
package ignore

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type rule struct {
	re       *regexp.Regexp
	negate   bool
	dirOnly  bool
	anchored bool // pattern contains a slash: match the whole relative path, not just the base name
}

// Matcher decides whether a relative path is ignored. The zero value ignores nothing.
type Matcher struct {
	rules []rule
}

// New builds a Matcher from pattern lines.
func New(patterns ...string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.add(p)
	}
	return m
}

// Parse reads patterns from r, one per line.
func Parse(r io.Reader) (*Matcher, error) {
	m := &Matcher{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m.add(sc.Text())
	}
	return m, sc.Err()
}

// Load reads the ignore file called name in root. A missing file gives an empty Matcher.
func Load(root, name string) (*Matcher, error) {
	f, err := os.Open(filepath.Join(root, name))
	if errors.Is(err, fs.ErrNotExist) {
		return &Matcher{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Add appends further patterns; later patterns take precedence.
func (m *Matcher) Add(patterns ...string) {
	for _, p := range patterns {
		m.add(p)
	}
}

// Prepend returns a new Matcher in which defaults come first, so that the receiver's rules
// (for example a user's "!build/") can override them.
func (m *Matcher) Prepend(defaults ...string) *Matcher {
	out := New(defaults...)
	out.rules = append(out.rules, m.rules...)
	return out
}

func (m *Matcher) add(line string) {
	line = strings.TrimRight(strings.TrimSpace(line), "\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	r := rule{}
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if strings.HasPrefix(line, "/") {
		r.anchored = true
		line = strings.TrimLeft(line, "/")
	}
	if line == "" {
		return
	}
	if strings.Contains(line, "/") {
		r.anchored = true
	}
	re, err := regexp.Compile("^" + globToRegexp(filepath.ToSlash(line)) + "$")
	if err != nil {
		return // an invalid pattern matches nothing rather than breaking the run
	}
	r.re = re
	m.rules = append(m.rules, r)
}

// globToRegexp translates a glob into a regular expression body.
func globToRegexp(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				// "**/" matches zero or more directories; a trailing "**" matches everything below.
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(glob[i:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := glob[i+1 : i+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += end
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

func (m *Matcher) evaluate(rel string, isDir bool) bool {
	ignored := false
	for _, r := range m.rules {
		if r.dirOnly && !isDir {
			continue
		}
		target := rel
		if !r.anchored {
			target = path.Base(rel)
		}
		if r.re.MatchString(target) {
			ignored = !r.negate
		}
	}
	return ignored
}

// Match reports whether the slash- or backslash-separated relative path is ignored.
// isDir says whether the path is a directory.
func (m *Matcher) Match(rel string, isDir bool) bool {
	if m == nil || len(m.rules) == 0 {
		return false
	}
	rel = path.Clean(filepath.ToSlash(rel))
	rel = strings.TrimPrefix(rel, "./")
	if rel == "." || rel == "" {
		return false
	}
	// An ignored parent directory ignores everything below it.
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		if m.evaluate(strings.Join(parts[:i], "/"), true) {
			return true
		}
	}
	return m.evaluate(rel, isDir)
}

// ReadPatterns returns the pattern lines of the ignore file called name in root (comments and blank
// lines removed). A missing file gives no patterns.
func ReadPatterns(root, name string) ([]string, error) {
	f, err := os.Open(filepath.Join(root, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
