package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SandSoftwareSolutions/assay/internal/ignore"
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

func TestHashesMatchSha256AndAreSorted(t *testing.T) {
	root := t.TempDir()
	write(t, root, "z.txt", "zulu")
	write(t, root, "a/b.txt", "bravo")
	res, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 || res.Files[0].Path != "a/b.txt" || res.Files[1].Path != "z.txt" {
		t.Fatalf("files = %+v", res.Files)
	}
	sum := sha256.Sum256([]byte("zulu"))
	if res.Files[1].Hash != hex.EncodeToString(sum[:]) || res.Files[1].Size != 4 {
		t.Fatalf("entry = %+v", res.Files[1])
	}
}

func TestSkipAndIgnore(t *testing.T) {
	root := t.TempDir()
	write(t, root, "keep.txt", "k")
	write(t, root, ".assay.json", "{}")
	write(t, root, "node_modules/x.js", "x")
	write(t, root, "debug.log", "l")
	res, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256",
		Ignore: ignore.New("node_modules/", "*.log"), Skip: []string{".assay.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "keep.txt" {
		t.Fatalf("files = %+v", res.Files)
	}
}

func TestManyFilesParallelGivesSameResultAsSerial(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 200; i++ {
		write(t, root, fmt.Sprintf("d%d/f%03d.txt", i%7, i), fmt.Sprintf("content %d", i))
	}
	var calls int64
	par, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Workers: 8,
		Progress: func(done, total int) { atomic.AddInt64(&calls, 1) }})
	if err != nil {
		t.Fatal(err)
	}
	ser, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(par.Files, ser.Files) || len(par.Files) != 200 {
		t.Fatal("parallel and serial scans differ")
	}
	if calls != 200 {
		t.Fatalf("progress called %d times", calls)
	}
}

func TestSymlinksAreSkippedNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	root := t.TempDir()
	write(t, root, "real.txt", "r")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	_ = os.WriteFile(outside, []byte("secret"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Skip(err)
	}
	res, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || !reflect.DeepEqual(res.Skipped, []string{"link.txt"}) {
		t.Fatalf("files=%+v skipped=%v", res.Files, res.Skipped)
	}
}

func TestUnreadableFileIsReportedAndScanContinues(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced here")
	}
	root := t.TempDir()
	write(t, root, "ok.txt", "ok")
	write(t, root, "locked.txt", "no")
	_ = os.Chmod(filepath.Join(root, "locked.txt"), 0)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "locked.txt"), 0o644) })
	res, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || len(res.Unreadable) != 1 || res.Unreadable[0].Path != "locked.txt" {
		t.Fatalf("files=%+v unreadable=%+v", res.Files, res.Unreadable)
	}
}

func TestCancelledContextStops(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.txt", "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()}); err == nil {
		t.Fatal("expected a cancellation error")
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, err := Scan(context.Background(), Options{Root: t.TempDir(), Algorithm: "md5", Ignore: ignore.New()}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCacheReusesUnchangedFilesAndNotesTheTradeOff(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.txt", "alpha")
	write(t, root, "b.txt", "bravo")
	old := time.Now().Add(-time.Hour)
	for _, f := range []string{"a.txt", "b.txt"} {
		_ = os.Chtimes(filepath.Join(root, f), old, old)
	}
	first, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	if err != nil || first.Reused != 0 {
		t.Fatalf("first scan: %v reused=%d", err, first.Reused)
	}
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	if err := Save(cachePath, "sha256", first.CacheEntries, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Nothing changed: everything is reused and the result is identical.
	second, err := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Cache: LoadCache(cachePath, "sha256")})
	if err != nil || second.Reused != 2 || !reflect.DeepEqual(first.Files, second.Files) {
		t.Fatalf("second scan: %v reused=%d", err, second.Reused)
	}

	// A real change (new size and time) is hashed again.
	write(t, root, "a.txt", "alpha changed")
	third, _ := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Cache: LoadCache(cachePath, "sha256")})
	if third.Reused != 1 {
		t.Fatalf("only the unchanged file may be reused, got %d", third.Reused)
	}
	if third.Files[0].Hash == first.Files[0].Hash {
		t.Fatal("a changed file must get a new hash")
	}

	// The documented trade-off: same size and same modification time but different content is NOT noticed in
	// fast mode (a normal scan does see it).
	write(t, root, "b.txt", "BRAVO")
	_ = os.Chtimes(filepath.Join(root, "b.txt"), old, old)
	fast, _ := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Cache: LoadCache(cachePath, "sha256")})
	full, _ := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	if fast.Files[1].Hash != first.Files[1].Hash {
		t.Fatal("fast mode is expected to trust size and time")
	}
	if full.Files[1].Hash == first.Files[1].Hash {
		t.Fatal("a normal scan must see the changed content")
	}
}

func TestCacheDoesNotTrustRecentFilesOrOtherAlgorithmsOrDamage(t *testing.T) {
	root := t.TempDir()
	write(t, root, "new.txt", "just written") // modified "now": within the racy window
	first, _ := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New()})
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	_ = Save(cachePath, "sha256", first.CacheEntries, time.Now())
	again, _ := Scan(context.Background(), Options{Root: root, Algorithm: "sha256", Ignore: ignore.New(), Cache: LoadCache(cachePath, "sha256")})
	if again.Reused != 0 {
		t.Fatal("a file changed moments before the cache was written must be hashed again")
	}
	if c := LoadCache(cachePath, "sha512"); len(c.Entries) != 0 {
		t.Fatal("a cache of another algorithm must be ignored")
	}
	_ = os.WriteFile(cachePath, []byte("{broken"), 0o644)
	if c := LoadCache(cachePath, "sha256"); len(c.Entries) != 0 {
		t.Fatal("a damaged cache must be ignored, not fail")
	}
	if c := LoadCache(filepath.Join(t.TempDir(), "missing.json"), "sha256"); c == nil || len(c.Entries) != 0 {
		t.Fatal("a missing cache must be empty")
	}
}
