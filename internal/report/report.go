// Package report renders check results as text, JSON or a self-contained HTML page.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/SandSoftwareSolutions/assay/internal/check"
	"github.com/SandSoftwareSolutions/assay/internal/compare"
)

// TextOptions control the text output.
type TextOptions struct {
	Color   bool
	Verbose bool // also list unchanged counts per folder and skipped entries
	Quiet   bool // print nothing when everything is fine
}

const (
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	bold   = "\x1b[1m"
	reset  = "\x1b[0m"
)

func paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + reset
}

// Text writes a human readable report.
func Text(w io.Writer, r *check.Result, o TextOptions) {
	if o.Quiet && r.OK() {
		return
	}
	c := o.Color
	total := len(r.Manifest.Files)
	fmt.Fprintf(w, "%s %d files against %s (sealed %s, %s)\n",
		paint(c, bold, "Checked"), total, r.ManifestPath, r.Manifest.Created, r.Manifest.Algorithm)

	if r.RootDamaged {
		fmt.Fprintln(w, paint(c, red, "  WARNING: the manifest does not match its own root hash; it was edited or damaged."))
	}
	switch r.Signature {
	case check.SigValid:
		fmt.Fprintf(w, "  %s signed by key %s\n", paint(c, green, "signature valid:"), r.KeyID)
	case check.SigInvalid:
		fmt.Fprintf(w, "  %s the manifest was not signed by the given key (or has no signature)\n", paint(c, red, "SIGNATURE INVALID:"))
	case check.SigUnverified:
		fmt.Fprintf(w, "  %s signed by key %s; give --pubkey to verify\n", paint(c, yellow, "signature not verified:"), r.KeyID)
	}
	for _, ch := range r.Diff.Modified {
		fmt.Fprintf(w, "  %s %s\n", paint(c, yellow, "modified "), describeChange(ch))
	}
	for _, p := range r.Diff.Added {
		fmt.Fprintf(w, "  %s %s\n", paint(c, green, "added    "), p)
	}
	for _, p := range r.Diff.Removed {
		fmt.Fprintf(w, "  %s %s\n", paint(c, red, "removed  "), p)
	}
	for _, rn := range r.Diff.Renamed {
		fmt.Fprintf(w, "  %s %s -> %s\n", paint(c, cyan, "renamed  "), rn.From, rn.To)
	}
	for _, p := range r.Unreadable {
		fmt.Fprintf(w, "  %s %s (%v)\n", paint(c, red, "unreadable"), p.Path, p.Err)
	}
	if o.Verbose {
		for _, p := range r.Skipped {
			fmt.Fprintf(w, "  skipped   %s (not a regular file)\n", p)
		}
	}
	fmt.Fprintln(w, summary(c, r))
}

func describeChange(ch compare.Change) string {
	if ch.OldSize == ch.NewSize {
		return fmt.Sprintf("%s (same size, different content)", ch.Path)
	}
	return fmt.Sprintf("%s (%s -> %s)", ch.Path, humanBytes(ch.OldSize), humanBytes(ch.NewSize))
}

func summary(color bool, r *check.Result) string {
	d := r.Diff
	if r.OK() {
		return paint(color, green, fmt.Sprintf("OK: all %d files are unchanged", d.Unchanged))
	}
	parts := []string{
		fmt.Sprintf("%d modified", len(d.Modified)), fmt.Sprintf("%d added", len(d.Added)),
		fmt.Sprintf("%d removed", len(d.Removed)), fmt.Sprintf("%d renamed", len(d.Renamed)),
	}
	if n := len(r.Unreadable); n > 0 {
		parts = append(parts, fmt.Sprintf("%d unreadable", n))
	}
	parts = append(parts, fmt.Sprintf("%d unchanged", d.Unchanged))
	return paint(color, red, "CHANGED: ") + strings.Join(parts, ", ")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// JSONReport is the machine readable form of a check.
type JSONReport struct {
	OK          bool             `json:"ok"`
	Manifest    string           `json:"manifest"`
	Algorithm   string           `json:"algorithm"`
	Sealed      string           `json:"sealed"`
	Root        string           `json:"root"`
	RootDamaged bool             `json:"root_damaged"`
	Signature   string           `json:"signature"`
	KeyID       string           `json:"key_id,omitempty"`
	Modified    []compare.Change `json:"modified"`
	Added       []string         `json:"added"`
	Removed     []string         `json:"removed"`
	Renamed     []compare.Rename `json:"renamed"`
	Unreadable  []string         `json:"unreadable"`
	Unchanged   int              `json:"unchanged"`
}

// ToJSON converts a result.
func ToJSON(r *check.Result) JSONReport {
	rep := JSONReport{
		OK: r.OK(), Manifest: r.ManifestPath, Algorithm: r.Manifest.Algorithm, Sealed: r.Manifest.Created,
		Root: r.Manifest.Root, RootDamaged: r.RootDamaged, Signature: string(r.Signature), KeyID: r.KeyID,
		Modified: r.Diff.Modified, Added: r.Diff.Added, Removed: r.Diff.Removed, Renamed: r.Diff.Renamed,
		Unchanged: r.Diff.Unchanged, Unreadable: []string{},
	}
	if rep.Modified == nil {
		rep.Modified = []compare.Change{}
	}
	if rep.Added == nil {
		rep.Added = []string{}
	}
	if rep.Removed == nil {
		rep.Removed = []string{}
	}
	if rep.Renamed == nil {
		rep.Renamed = []compare.Rename{}
	}
	for _, p := range r.Unreadable {
		rep.Unreadable = append(rep.Unreadable, p.Path)
	}
	return rep
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *check.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ToJSON(r))
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assay report</title>
<style>
  :root { color-scheme: light dark; --ok:#1a7f37; --bad:#cf222e; --warn:#9a6700; --muted:#6e7781; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { margin-bottom: .25rem; }
  .status { display:inline-block; padding:.25rem .75rem; border-radius:999px; color:#fff; font-weight:600; }
  .status.ok { background: var(--ok); } .status.bad { background: var(--bad); }
  dl { display:grid; grid-template-columns: max-content 1fr; gap:.25rem 1rem; margin: 1.5rem 0; }
  dt { color: var(--muted); } dd { margin:0; word-break: break-all; font-family: ui-monospace, monospace; }
  h2 { margin-top: 2rem; font-size: 1.1rem; }
  table { border-collapse: collapse; width: 100%; }
  td, th { text-align:left; padding:.35rem .5rem; border-bottom:1px solid #8883; font-family: ui-monospace, monospace; font-size:.9rem; }
  .muted { color: var(--muted); }
</style>
</head>
<body>
<h1>Assay report</h1>
<p><span class="status {{if .OK}}ok{{else}}bad{{end}}">{{if .OK}}All files unchanged{{else}}Changes found{{end}}</span></p>
<dl>
  <dt>Manifest</dt><dd>{{.Manifest}}</dd>
  <dt>Sealed</dt><dd>{{.Sealed}}</dd>
  <dt>Checked</dt><dd>{{.Checked}}</dd>
  <dt>Algorithm</dt><dd>{{.Algorithm}}</dd>
  <dt>Root hash</dt><dd>{{.Root}}</dd>
  <dt>Signature</dt><dd>{{.Signature}}{{if .KeyID}} (key {{.KeyID}}){{end}}</dd>
  <dt>Files</dt><dd>{{.Unchanged}} unchanged, {{len .Modified}} modified, {{len .Added}} added, {{len .Removed}} removed, {{len .Renamed}} renamed</dd>
</dl>
{{if .RootDamaged}}<p class="status bad">The manifest does not match its own root hash.</p>{{end}}
{{if .Modified}}<h2>Modified ({{len .Modified}})</h2><table>{{range .Modified}}<tr><td>{{.Path}}</td><td class="muted">{{.OldSize}} &rarr; {{.NewSize}} bytes</td></tr>{{end}}</table>{{end}}
{{if .Added}}<h2>Added ({{len .Added}})</h2><table>{{range .Added}}<tr><td>{{.}}</td></tr>{{end}}</table>{{end}}
{{if .Removed}}<h2>Removed ({{len .Removed}})</h2><table>{{range .Removed}}<tr><td>{{.}}</td></tr>{{end}}</table>{{end}}
{{if .Renamed}}<h2>Renamed ({{len .Renamed}})</h2><table>{{range .Renamed}}<tr><td>{{.From}}</td><td class="muted">&rarr; {{.To}}</td></tr>{{end}}</table>{{end}}
{{if .Unreadable}}<h2>Unreadable ({{len .Unreadable}})</h2><table>{{range .Unreadable}}<tr><td>{{.}}</td></tr>{{end}}</table>{{end}}
<p class="muted">Generated by assay. A hash shows that a file changed, not who changed it.</p>
</body>
</html>
`))

type htmlData struct {
	JSONReport
	Checked string
}

// HTML writes a self-contained HTML page.
func HTML(w io.Writer, r *check.Result) error {
	return htmlTemplate.Execute(w, htmlData{JSONReport: ToJSON(r), Checked: r.CheckedAt.UTC().Format("2006-01-02 15:04:05 UTC")})
}

// DiffText writes a comparison of two manifests.
func DiffText(w io.Writer, d compare.Diff, color bool) {
	for _, ch := range d.Modified {
		fmt.Fprintf(w, "  %s %s\n", paint(color, yellow, "modified "), describeChange(ch))
	}
	for _, p := range d.Added {
		fmt.Fprintf(w, "  %s %s\n", paint(color, green, "added    "), p)
	}
	for _, p := range d.Removed {
		fmt.Fprintf(w, "  %s %s\n", paint(color, red, "removed  "), p)
	}
	for _, rn := range d.Renamed {
		fmt.Fprintf(w, "  %s %s -> %s\n", paint(color, cyan, "renamed  "), rn.From, rn.To)
	}
	fmt.Fprintf(w, "%d modified, %d added, %d removed, %d renamed, %d unchanged\n",
		len(d.Modified), len(d.Added), len(d.Removed), len(d.Renamed), d.Unchanged)
}
