// Package compare finds the differences between a manifest and the files that are there now.
package compare

import (
	"sort"

	"github.com/SandSoftwareSolutions/hallmark/internal/manifest"
)

// Rename is a file whose content is unchanged but whose path differs.
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Change describes a modified file.
type Change struct {
	Path    string `json:"path"`
	OldSize int64  `json:"old_size"`
	NewSize int64  `json:"new_size"`
}

// Diff is the result of a comparison. Every list is sorted by path.
type Diff struct {
	Modified  []Change `json:"modified"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	Renamed   []Rename `json:"renamed"`
	Unchanged int      `json:"unchanged"`
}

// Clean reports whether nothing differs.
func (d Diff) Clean() bool {
	return len(d.Modified) == 0 && len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Renamed) == 0
}

// Changes is the number of differing paths.
func (d Diff) Changes() int { return len(d.Modified) + len(d.Added) + len(d.Removed) + len(d.Renamed) }

// Compare compares sealed entries with current entries. A removed and an added file with the same
// content hash and size are reported as a rename, matched one to one in path order.
func Compare(sealed, current []manifest.Entry) Diff {
	old := make(map[string]manifest.Entry, len(sealed))
	for _, e := range sealed {
		old[e.Path] = e
	}
	seen := make(map[string]bool, len(current))
	var d Diff
	var added []manifest.Entry
	for _, c := range current {
		seen[c.Path] = true
		o, ok := old[c.Path]
		switch {
		case !ok:
			added = append(added, c)
		case o.Hash != c.Hash || o.Size != c.Size:
			d.Modified = append(d.Modified, Change{Path: c.Path, OldSize: o.Size, NewSize: c.Size})
		default:
			d.Unchanged++
		}
	}
	var removed []manifest.Entry
	for _, o := range sealed {
		if !seen[o.Path] {
			removed = append(removed, o)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Path < added[j].Path })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Path < removed[j].Path })

	byContent := map[string][]int{}
	for i, a := range added {
		key := a.Hash
		byContent[key] = append(byContent[key], i)
	}
	used := map[int]bool{}
	for _, r := range removed {
		matched := false
		for _, i := range byContent[r.Hash] {
			if !used[i] && added[i].Size == r.Size {
				used[i] = true
				d.Renamed = append(d.Renamed, Rename{From: r.Path, To: added[i].Path})
				matched = true
				break
			}
		}
		if !matched {
			d.Removed = append(d.Removed, r.Path)
		}
	}
	for i, a := range added {
		if !used[i] {
			d.Added = append(d.Added, a.Path)
		}
	}
	sort.Slice(d.Modified, func(i, j int) bool { return d.Modified[i].Path < d.Modified[j].Path })
	sort.Slice(d.Renamed, func(i, j int) bool { return d.Renamed[i].From < d.Renamed[j].From })
	return d
}
