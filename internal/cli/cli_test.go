package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type run struct {
	code        int
	out, errOut string
}

func assay(t *testing.T, args ...string) run {
	t.Helper()
	var out, errOut bytes.Buffer
	off := false
	app := &App{Out: &out, Err: &errOut, Color: &off}
	code := app.Run(context.Background(), args)
	return run{code: code, out: out.String(), errOut: errOut.String()}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func folder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "a.txt", "alpha")
	write(t, dir, "sub/b.txt", "bravo")
	return dir
}

func TestSealCheckExitCodes(t *testing.T) {
	dir := folder(t)
	if r := assay(t, "check", dir); r.code != ExitError || !strings.Contains(r.errOut, "assay seal") {
		t.Fatalf("check without manifest: %+v", r)
	}
	if r := assay(t, "seal", dir); r.code != ExitOK || !strings.Contains(r.out, "Sealed 2 files") {
		t.Fatalf("seal: %+v", r)
	}
	if r := assay(t, "check", dir); r.code != ExitOK || !strings.Contains(r.out, "OK: all 2 files are unchanged") {
		t.Fatalf("check clean: %+v", r)
	}
	write(t, dir, "a.txt", "alpha edited!")
	write(t, dir, "new.txt", "n")
	r := assay(t, "check", dir)
	if r.code != ExitChanged || !strings.Contains(r.out, "modified  a.txt (5 B -> 13 B)") || !strings.Contains(r.out, "added     new.txt") {
		t.Fatalf("check changed: %+v", r)
	}
}

func TestFlagsMayFollowTheFolder(t *testing.T) {
	dir := folder(t)
	mpath := filepath.Join(t.TempDir(), "m.json")
	if r := assay(t, "seal", dir, "-m", mpath, "--exclude", "sub/"); r.code != ExitOK {
		t.Fatalf("seal: %+v", r)
	}
	if r := assay(t, "check", "-m", mpath, dir); r.code != ExitOK || !strings.Contains(r.out, "all 1 files") {
		t.Fatalf("check: %+v", r)
	}
}

func TestQuietAndJSON(t *testing.T) {
	dir := folder(t)
	assay(t, "seal", dir, "-q")
	if r := assay(t, "check", dir, "-q"); r.code != ExitOK || r.out != "" {
		t.Fatalf("quiet clean: %+v", r)
	}
	write(t, dir, "a.txt", "changed")
	r := assay(t, "check", dir, "--json")
	if r.code != ExitChanged {
		t.Fatalf("code %d", r.code)
	}
	var rep struct {
		OK       bool `json:"ok"`
		Modified []struct{ Path string }
		Added    []string
	}
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
	if rep.OK || len(rep.Modified) != 1 || rep.Modified[0].Path != "a.txt" || rep.Added == nil {
		t.Fatalf("report = %+v", rep)
	}
}

func TestSignedWorkflow(t *testing.T) {
	dir := folder(t)
	keys := filepath.Join(t.TempDir(), "k")
	if r := assay(t, "keygen", "-o", keys); r.code != ExitOK || !strings.Contains(r.out, "Key id:") {
		t.Fatalf("keygen: %+v", r)
	}
	if r := assay(t, "keygen", "-o", keys); r.code != ExitError {
		t.Fatalf("keygen must not overwrite: %+v", r)
	}
	if r := assay(t, "seal", dir, "--key", keys+".key"); r.code != ExitOK || !strings.Contains(r.out, "signed with key") {
		t.Fatalf("seal: %+v", r)
	}
	if r := assay(t, "check", dir, "--pubkey", keys+".pub"); r.code != ExitOK || !strings.Contains(r.out, "signature valid") {
		t.Fatalf("check: %+v", r)
	}
	if r := assay(t, "check", dir); !strings.Contains(r.out, "not verified") {
		t.Fatalf("unverified: %+v", r)
	}
	if r := assay(t, "check", dir, "--require-signature"); r.code != ExitChanged {
		t.Fatalf("--require-signature without a key must fail: %+v", r)
	}
	// An unsigned re-seal by an attacker.
	write(t, dir, "a.txt", "evil")
	assay(t, "seal", dir, "-q")
	if r := assay(t, "check", dir, "--pubkey", keys+".pub"); r.code != ExitChanged || !strings.Contains(r.out, "SIGNATURE INVALID") {
		t.Fatalf("forged manifest: %+v", r)
	}
}

func TestDiffAndExport(t *testing.T) {
	dir := folder(t)
	m1 := filepath.Join(t.TempDir(), "1.json")
	m2 := filepath.Join(t.TempDir(), "2.json")
	assay(t, "seal", dir, "-m", m1)
	write(t, dir, "sub/b.txt", "bravo2")
	write(t, dir, "c.txt", "c")
	assay(t, "seal", dir, "-m", m2)
	r := assay(t, "diff", m1, m2)
	if r.code != ExitChanged || !strings.Contains(r.out, "1 modified, 1 added") {
		t.Fatalf("diff: %+v", r)
	}
	if r := assay(t, "diff", m1, m1); r.code != ExitOK {
		t.Fatalf("diff same: %+v", r)
	}
	r = assay(t, "export", "-m", m1)
	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	if r.code != ExitOK || len(lines) != 2 || !strings.HasSuffix(lines[0], "  a.txt") || len(strings.Fields(lines[0])[0]) != 64 {
		t.Fatalf("export: %+v", r)
	}
}

func TestReportHTML(t *testing.T) {
	dir := folder(t)
	assay(t, "seal", dir, "-q")
	write(t, dir, "a.txt", "<script>alert(1)</script>")
	out := filepath.Join(t.TempDir(), "r.html")
	r := assay(t, "report", dir, "-o", out)
	if r.code != ExitChanged {
		t.Fatalf("report: %+v", r)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if !strings.Contains(html, "Changes found") || !strings.Contains(html, "a.txt") {
		t.Fatalf("html: %s", html)
	}
	if r := assay(t, "report", dir); r.code != ExitError {
		t.Fatalf("report without -o: %+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"seal", "a", "b"}, {"diff", "x"}, {"check", "--watch", "-1s", "."}, {"seal", "--algo", "md5", "."}} {
		if r := assay(t, args...); r.code != ExitError {
			t.Errorf("%v: exit %d, want %d", args, r.code, ExitError)
		}
	}
	if r := assay(t, "version"); r.code != ExitOK || !strings.HasPrefix(r.out, "assay ") {
		t.Fatalf("version: %+v", r)
	}
	if r := assay(t, "help"); r.code != ExitOK || !strings.Contains(r.out, "assay seal") {
		t.Fatalf("help: %+v", r)
	}
}

func TestHostileManifestIsRefused(t *testing.T) {
	dir := folder(t)
	assay(t, "seal", dir, "-q")
	p := filepath.Join(dir, ".assay.json")
	data, _ := os.ReadFile(p)
	evil := strings.Replace(string(data), `"path": "a.txt"`, `"path": "../../etc/passwd"`, 1)
	_ = os.WriteFile(p, []byte(evil), 0o644)
	if r := assay(t, "check", dir); r.code != ExitError || !strings.Contains(r.errOut, "inside the folder") {
		t.Fatalf("hostile manifest: %+v", r)
	}
}

func TestWatchStopsWithContextAndReportsChange(t *testing.T) {
	dir := folder(t)
	assay(t, "seal", dir, "-q")
	var out, errOut bytes.Buffer
	off := false
	app := &App{Out: &out, Err: &errOut, Color: &off}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- app.Run(ctx, []string{"check", dir, "--watch", "50ms"}) }()
	time.Sleep(200 * time.Millisecond)
	write(t, dir, "a.txt", "changed while watching")
	time.Sleep(400 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
	if !strings.Contains(out.String(), "OK: all") || !strings.Contains(out.String(), "modified  a.txt") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestFastModeReusesHashesAndSaysSo(t *testing.T) {
	dir := folder(t)
	old := time.Now().Add(-time.Hour)
	for _, f := range []string{"a.txt", "sub/b.txt"} {
		_ = os.Chtimes(filepath.Join(dir, filepath.FromSlash(f)), old, old)
	}
	cache := filepath.Join(t.TempDir(), "fast.json")
	if r := sealWith(t, dir, "--fast", "--cache-file", cache); r.code != ExitOK {
		t.Fatalf("seal: %+v", r)
	}
	r := assay(t, "check", dir, "--fast", "--cache-file", cache)
	if r.code != ExitOK || !strings.Contains(r.out, "fast mode: 2 of 2 file hashes were reused") {
		t.Fatalf("check --fast: %+v", r)
	}
	// Without --fast nothing is reused and nothing is said about it.
	if r := assay(t, "check", dir); strings.Contains(r.out, "fast mode") {
		t.Fatalf("normal check must not use the cache: %s", r.out)
	}
	// A real change is still found in fast mode.
	write(t, dir, "a.txt", "changed content")
	if r := assay(t, "check", dir, "--fast", "--cache-file", cache); r.code != ExitChanged || !strings.Contains(r.out, "modified  a.txt") {
		t.Fatalf("change not found: %+v", r)
	}
}

func sealWith(t *testing.T, dir string, extra ...string) run {
	t.Helper()
	return assay(t, append([]string{"seal", dir}, extra...)...)
}

func TestCompletionScriptsListRealCommandsAndFlags(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		r := assay(t, "completion", shell)
		if r.code != ExitOK {
			t.Fatalf("%s: %+v", shell, r)
		}
		wants := []string{"seal", "check", "report", "keygen", "--fast", "--pubkey", "--json"}
		if shell == "fish" { // fish spells long options as "-l name"
			wants = []string{"seal", "check", "report", "keygen", "-l fast", "-l pubkey", "-l json"}
		}
		for _, want := range wants {
			if !strings.Contains(r.out, want) {
				t.Errorf("%s completion lacks %q", shell, want)
			}
		}
	}
	if r := assay(t, "completion", "tcsh"); r.code != ExitError {
		t.Fatalf("unknown shell: %+v", r)
	}
	if r := assay(t, "completion"); r.code != ExitError {
		t.Fatalf("no shell: %+v", r)
	}
}

func TestCompletionKnowsWhichFlagsTakeFiles(t *testing.T) {
	var app App
	var check commandInfo
	for _, c := range app.commandInfos() {
		if c.Name == "check" {
			check = c
		}
	}
	flags := map[string]flagInfo{}
	for _, f := range check.Flags {
		flags[f.Name] = f
	}
	for _, name := range []string{"m", "pubkey", "json", "fast", "watch", "cache-file", "require-signature"} {
		if _, ok := flags[name]; !ok {
			t.Errorf("check should have flag %q (found %v)", name, flags)
		}
	}
	if !flags["pubkey"].File || !flags["m"].File || flags["json"].Arg || !flags["watch"].Arg {
		t.Errorf("wrong flag kinds: %+v", flags)
	}
}

func TestManPageMentionsEverything(t *testing.T) {
	r := assay(t, "man")
	if r.code != ExitOK || !strings.HasPrefix(r.out, ".TH ASSAY 1") {
		t.Fatalf("man: %+v", r.code)
	}
	for _, want := range []string{".SH NAME", ".SH EXIT STATUS", "seal", "completion", `\-\-fast`, ".SH FILES"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("man page lacks %q", want)
		}
	}
}
