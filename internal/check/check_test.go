package check

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/SandSoftwareSolutions/assay/internal/manifest"
	"github.com/SandSoftwareSolutions/assay/internal/sign"
)

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
	write(t, dir, "sub/c.txt", "charlie")
	return dir
}

func seal(t *testing.T, dir string, mutate func(*SealOptions)) *SealResult {
	t.Helper()
	o := SealOptions{Dir: dir}
	if mutate != nil {
		mutate(&o)
	}
	res, err := Seal(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func chk(t *testing.T, dir string, mutate func(*Options)) *Result {
	t.Helper()
	o := Options{Dir: dir}
	if mutate != nil {
		mutate(&o)
	}
	r, err := Check(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUnchangedFolderIsOK(t *testing.T) {
	dir := folder(t)
	seal(t, dir, nil)
	r := chk(t, dir, nil)
	if !r.OK() || r.Diff.Unchanged != 3 {
		t.Fatalf("%+v", r.Diff)
	}
}

func TestEveryKindOfChangeIsFound(t *testing.T) {
	dir := folder(t)
	seal(t, dir, nil)
	write(t, dir, "a.txt", "alpha EDITED")
	write(t, dir, "new.txt", "brand new")
	_ = os.Remove(filepath.Join(dir, "sub", "b.txt"))
	_ = os.Rename(filepath.Join(dir, "sub", "c.txt"), filepath.Join(dir, "sub", "c2.txt"))
	r := chk(t, dir, nil)
	d := r.Diff
	if len(d.Modified) != 1 || d.Modified[0].Path != "a.txt" ||
		!reflect.DeepEqual(d.Added, []string{"new.txt"}) ||
		!reflect.DeepEqual(d.Removed, []string{"sub/b.txt"}) ||
		len(d.Renamed) != 1 || d.Renamed[0].To != "sub/c2.txt" {
		t.Fatalf("diff = %+v", d)
	}
	if r.OK() {
		t.Fatal("must not be OK")
	}
}

func TestSealIsDeterministicAndManifestIsNotHashed(t *testing.T) {
	dir := folder(t)
	a := seal(t, dir, nil)
	b := seal(t, dir, nil) // the manifest from the first run is now in the folder
	if a.Manifest.Root != b.Manifest.Root || len(b.Manifest.Files) != 3 {
		t.Fatalf("roots %s vs %s, files %d", a.Manifest.Root, b.Manifest.Root, len(b.Manifest.Files))
	}
}

func TestIgnorePatternsAreStoredAndUsedAtCheckTime(t *testing.T) {
	dir := folder(t)
	write(t, dir, "debug.log", "noise")
	write(t, dir, ".assayignore", "# logs\n*.log\n")
	res := seal(t, dir, func(o *SealOptions) { o.Exclude = []string{"sub/"} })
	var paths []string
	for _, f := range res.Manifest.Files {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	if !reflect.DeepEqual(paths, []string{".assayignore", "a.txt"}) {
		t.Fatalf("files = %v", paths)
	}
	// Changing the ignore file later must not change what the old manifest means...
	write(t, dir, ".assayignore", "")
	r := chk(t, dir, nil)
	// ...but the ignore file itself is a sealed file, so the change is visible.
	if len(r.Diff.Modified) != 1 || r.Diff.Modified[0].Path != ".assayignore" || len(r.Diff.Added) != 0 {
		t.Fatalf("diff = %+v", r.Diff)
	}
	write(t, dir, "debug.log", "more noise") // still ignored
	write(t, dir, "sub/x.txt", "ignored dir")
	if r := chk(t, dir, nil); len(r.Diff.Added) != 0 {
		t.Fatalf("ignored files appeared: %+v", r.Diff.Added)
	}
}

func TestSignatureValidInvalidUnverified(t *testing.T) {
	dir := folder(t)
	pub, priv, _ := sign.Generate()
	seal(t, dir, func(o *SealOptions) { o.Key = priv })

	if r := chk(t, dir, nil); r.Signature != SigUnverified || !r.OK() {
		t.Fatalf("without key: %s ok=%v", r.Signature, r.OK())
	}
	if r := chk(t, dir, func(o *Options) { o.PublicKey = pub }); r.Signature != SigValid || !r.OK() {
		t.Fatalf("with key: %s ok=%v", r.Signature, r.OK())
	}
	otherPub, _, _ := sign.Generate()
	if r := chk(t, dir, func(o *Options) { o.PublicKey = otherPub }); r.Signature != SigInvalid || r.OK() {
		t.Fatalf("wrong key: %s ok=%v", r.Signature, r.OK())
	}
}

func TestAttackerWhoRewritesFilesAndManifestIsCaughtBySignature(t *testing.T) {
	dir := folder(t)
	pub, priv, _ := sign.Generate()
	seal(t, dir, func(o *SealOptions) { o.Key = priv })

	// Tamper with a file and re-seal without the key: files and manifest agree again...
	write(t, dir, "a.txt", "malicious")
	forged := seal(t, dir, nil)
	if forged.Manifest.Signature != nil {
		t.Fatal("test setup: forged manifest must be unsigned")
	}
	r := chk(t, dir, func(o *Options) { o.PublicKey = pub })
	// ...so the plain diff is clean, but the key holder's check fails.
	if !r.Diff.Clean() || r.Signature != SigInvalid || r.OK() {
		t.Fatalf("diff clean=%v signature=%s ok=%v", r.Diff.Clean(), r.Signature, r.OK())
	}
}

func TestEditedManifestIsDetected(t *testing.T) {
	dir := folder(t)
	res := seal(t, dir, nil)
	data, _ := os.ReadFile(res.ManifestPath)
	// Change a recorded size without updating the root.
	edited := strings.Replace(string(data), `"size": 5`, `"size": 6`, 1)
	if edited == string(data) {
		t.Fatal("test setup: nothing replaced")
	}
	_ = os.WriteFile(res.ManifestPath, []byte(edited), 0o644)
	r := chk(t, dir, nil)
	if !r.RootDamaged || r.OK() {
		t.Fatalf("damaged manifest not noticed: %+v", r)
	}
}

func TestIgnoreListEditedInManifestInvalidatesSignature(t *testing.T) {
	dir := folder(t)
	write(t, dir, "secret.txt", "s")
	pub, priv, _ := sign.Generate()
	res := seal(t, dir, func(o *SealOptions) { o.Key = priv })
	m, _ := manifest.Read(res.ManifestPath)
	m.Ignore = append(m.Ignore, "secret.txt") // hide a file by adding a pattern
	_ = manifest.Write(res.ManifestPath, m)
	r := chk(t, dir, func(o *Options) { o.PublicKey = pub })
	if r.Signature != SigInvalid {
		t.Fatalf("signature = %s", r.Signature)
	}
}

func TestManifestOutsideFolder(t *testing.T) {
	dir := folder(t)
	mpath := filepath.Join(t.TempDir(), "elsewhere.json")
	seal(t, dir, func(o *SealOptions) { o.ManifestPath = mpath })
	if _, err := os.Stat(filepath.Join(dir, manifest.DefaultFile)); err == nil {
		t.Fatal("must not create a manifest inside the folder")
	}
	if r := chk(t, dir, func(o *Options) { o.ManifestPath = mpath }); !r.OK() {
		t.Fatalf("%+v", r.Diff)
	}
}

func TestMissingManifestAndFolder(t *testing.T) {
	dir := folder(t)
	if _, err := Check(context.Background(), Options{Dir: dir}); err == nil || !strings.Contains(err.Error(), "assay seal") {
		t.Fatalf("got %v", err)
	}
	if _, err := Check(context.Background(), Options{Dir: filepath.Join(dir, "nope")}); err == nil {
		t.Fatal("missing folder must fail")
	}
	if _, err := Seal(context.Background(), SealOptions{Dir: filepath.Join(dir, "a.txt")}); err == nil {
		t.Fatal("a file is not a folder")
	}
}

func TestSha512(t *testing.T) {
	dir := folder(t)
	res := seal(t, dir, func(o *SealOptions) { o.Algorithm = "sha512" })
	if len(res.Manifest.Files[0].Hash) != 128 {
		t.Fatalf("hash length %d", len(res.Manifest.Files[0].Hash))
	}
	if r := chk(t, dir, nil); !r.OK() {
		t.Fatal("sha512 check failed")
	}
}

func TestEmptyFileAndBinaryFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "empty", "")
	write(t, dir, "bin", "\x00\x01\x02")
	seal(t, dir, nil)
	write(t, dir, "empty", "x")
	r := chk(t, dir, nil)
	if len(r.Diff.Modified) != 1 || r.Diff.Modified[0].Path != "empty" {
		t.Fatalf("%+v", r.Diff)
	}
}
