package compare

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SandSoftwareSolutions/assay/internal/manifest"
)

func e(path, content string) manifest.Entry {
	return manifest.Entry{Path: path, Size: int64(len(content)), Hash: strings.Repeat(string(rune('a'+len(content)%20)), 8) + content}
}

func TestCompare(t *testing.T) {
	sealed := []manifest.Entry{e("same.txt", "x"), e("edit.txt", "old"), e("gone.txt", "gone!"), e("move.txt", "movable")}
	current := []manifest.Entry{e("same.txt", "x"), e("edit.txt", "newer"), e("new.txt", "brandnew"), e("moved/move.txt", "movable")}
	d := Compare(sealed, current)
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d", d.Unchanged)
	}
	if len(d.Modified) != 1 || d.Modified[0].Path != "edit.txt" || d.Modified[0].OldSize != 3 || d.Modified[0].NewSize != 5 {
		t.Errorf("modified = %+v", d.Modified)
	}
	if !reflect.DeepEqual(d.Added, []string{"new.txt"}) || !reflect.DeepEqual(d.Removed, []string{"gone.txt"}) {
		t.Errorf("added=%v removed=%v", d.Added, d.Removed)
	}
	if !reflect.DeepEqual(d.Renamed, []Rename{{From: "move.txt", To: "moved/move.txt"}}) {
		t.Errorf("renamed = %+v", d.Renamed)
	}
	if d.Clean() || d.Changes() != 4 {
		t.Errorf("clean=%v changes=%d", d.Clean(), d.Changes())
	}
}

func TestIdenticalIsClean(t *testing.T) {
	files := []manifest.Entry{e("a", "1"), e("b", "22")}
	if d := Compare(files, files); !d.Clean() || d.Unchanged != 2 {
		t.Fatalf("%+v", d)
	}
}

func TestDuplicateContentIsMatchedOneToOne(t *testing.T) {
	sealed := []manifest.Entry{e("a.txt", "same"), e("b.txt", "same")}
	current := []manifest.Entry{e("c.txt", "same"), e("d.txt", "same"), e("e.txt", "same")}
	d := Compare(sealed, current)
	if len(d.Renamed) != 2 || len(d.Added) != 1 || len(d.Removed) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestSizeChangeWithSameHashStringIsStillModified(t *testing.T) {
	a := manifest.Entry{Path: "f", Size: 1, Hash: strings.Repeat("a", 64)}
	b := manifest.Entry{Path: "f", Size: 2, Hash: strings.Repeat("a", 64)}
	if d := Compare([]manifest.Entry{a}, []manifest.Entry{b}); len(d.Modified) != 1 {
		t.Fatalf("%+v", d)
	}
}
