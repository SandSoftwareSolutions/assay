// Package cli implements the assay command line. It uses only the standard library.
package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SandSoftwareSolutions/assay/internal/check"
	"github.com/SandSoftwareSolutions/assay/internal/compare"
	"github.com/SandSoftwareSolutions/assay/internal/manifest"
	"github.com/SandSoftwareSolutions/assay/internal/report"
	"github.com/SandSoftwareSolutions/assay/internal/sign"
)

// Exit codes.
const (
	ExitOK      = 0
	ExitChanged = 1 // differences, a damaged manifest or an invalid signature
	ExitError   = 2 // usage errors and anything that stopped the command
)

// Version information, set at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

const usage = `assay: see whether files were changed.

Usage:
  assay seal   [folder] [flags]       record a hash of every file in a manifest
  assay check  [folder] [flags]       compare the folder with its manifest
  assay diff   <old.json> <new.json>  compare two manifests
  assay report [folder] -o file.html  write an HTML report of a check
  assay export [folder] [flags]       print the manifest as sha256sum lines
  assay keygen [-o prefix]            create an Ed25519 key pair for signing
  assay version

The folder defaults to the current directory, the manifest to <folder>/.assay.json.
Exit status of check: 0 nothing changed, 1 changes found, 2 error.

Run "assay <command> -h" for the flags of a command.
`

// App carries the streams so tests can capture them.
type App struct {
	Out, Err io.Writer
	// Color forces colors on or off; nil means: on when Out is a terminal and NO_COLOR is not set.
	Color *bool
}

// Run executes the command line and returns the exit status.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Err, usage)
		return ExitError
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := ExitOK
	switch cmd {
	case "seal":
		code, err = a.seal(ctx, rest)
	case "check":
		code, err = a.check(ctx, rest)
	case "diff":
		code, err = a.diff(rest)
	case "report":
		code, err = a.report(ctx, rest)
	case "export":
		code, err = a.export(rest)
	case "keygen":
		code, err = a.keygen(rest)
	case "version", "--version", "-v":
		fmt.Fprintf(a.Out, "assay %s (commit %s, built %s)\n", Version, Commit, Date)
	case "help", "-h", "--help":
		fmt.Fprint(a.Out, usage)
	default:
		fmt.Fprintf(a.Err, "assay: unknown command %q\n\n%s", cmd, usage)
		return ExitError
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(a.Err, "assay: %v\n", err)
		return ExitError
	}
	return code
}

func (a *App) color() bool {
	if a.Color != nil {
		return *a.Color
	}
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		return false
	}
	f, ok := a.Out.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// parse parses flags that may appear before or after the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func newFlagSet(a *App, name string) *flag.FlagSet {
	fs := flag.NewFlagSet("assay "+name, flag.ContinueOnError)
	fs.SetOutput(a.Err)
	return fs
}

func oneFolder(positional []string) (string, error) {
	switch len(positional) {
	case 0:
		return ".", nil
	case 1:
		return positional[0], nil
	}
	return "", fmt.Errorf("expected at most one folder, got %d arguments", len(positional))
}

// progress prints a one-line counter on stderr when it is a terminal.
func (a *App) progress(quiet bool) func(done, total int) {
	f, ok := a.Err.(*os.File)
	if quiet || !ok {
		return nil
	}
	if st, err := f.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	var mu sync.Mutex
	last := time.Now()
	return func(done, total int) {
		mu.Lock()
		defer mu.Unlock()
		if done != total && time.Since(last) < 100*time.Millisecond {
			return
		}
		last = time.Now()
		fmt.Fprintf(a.Err, "\rhashing %d/%d", done, total)
		if done == total {
			fmt.Fprint(a.Err, "\r\x1b[K")
		}
	}
}

func (a *App) seal(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "seal")
	var exclude stringList
	manifestFile := fs.String("m", "", "manifest `file` (default <folder>/.assay.json)")
	algo := fs.String("algo", manifest.DefaultAlgorithm, "hash algorithm: "+strings.Join(manifest.Algorithms(), ", "))
	keyFile := fs.String("key", "", "private key `file`: sign the manifest")
	workers := fs.Int("workers", 0, "number of parallel hash workers (default: number of CPUs)")
	quiet := fs.Bool("q", false, "print nothing but errors")
	fs.Var(&exclude, "exclude", "ignore `pattern` (repeatable; same rules as .gitignore)")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitError, err
	}
	dir, err := oneFolder(pos)
	if err != nil {
		return ExitError, err
	}
	var key ed25519.PrivateKey
	if *keyFile != "" {
		if key, err = sign.ReadPrivate(*keyFile); err != nil {
			return ExitError, err
		}
	}
	res, err := check.Seal(ctx, check.SealOptions{Dir: dir, ManifestPath: *manifestFile, Algorithm: *algo,
		Exclude: exclude, Key: key, Workers: *workers, Progress: a.progress(*quiet)})
	if err != nil {
		return ExitError, err
	}
	if *quiet {
		return ExitOK, nil
	}
	m := res.Manifest
	fmt.Fprintf(a.Out, "Sealed %d files -> %s\n", len(m.Files), res.ManifestPath)
	fmt.Fprintf(a.Out, "  algorithm %s, root %s\n", m.Algorithm, m.Root)
	if m.Signature != nil {
		fmt.Fprintf(a.Out, "  signed with key %s\n", m.Signature.KeyID)
	}
	if p := res.Previous; p != nil && !p.Clean() {
		fmt.Fprintf(a.Out, "  since the previous seal: %d modified, %d added, %d removed, %d renamed\n",
			len(p.Modified), len(p.Added), len(p.Removed), len(p.Renamed))
	}
	for _, s := range res.Scan.Skipped {
		fmt.Fprintf(a.Err, "assay: skipped %s (not a regular file; symbolic links are not followed)\n", s)
	}
	return ExitOK, nil
}

type checkFlags struct {
	manifest, pubkey   string
	requireSignature   bool
	workers            int
	quiet, verbose, js bool
	watch              time.Duration
}

func (a *App) check(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "check")
	var f checkFlags
	fs.StringVar(&f.manifest, "m", "", "manifest `file` (default <folder>/.assay.json)")
	fs.StringVar(&f.pubkey, "pubkey", "", "public key `file`: verify the signature")
	fs.BoolVar(&f.requireSignature, "require-signature", false, "fail when the manifest is not signed and verified")
	fs.IntVar(&f.workers, "workers", 0, "number of parallel hash workers (default: number of CPUs)")
	fs.BoolVar(&f.quiet, "q", false, "print nothing when everything is fine")
	fs.BoolVar(&f.verbose, "v", false, "also list skipped entries")
	fs.BoolVar(&f.js, "json", false, "print the result as JSON")
	fs.DurationVar(&f.watch, "watch", 0, "check again every `interval` (for example 10s) and report changes")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitError, err
	}
	dir, err := oneFolder(pos)
	if err != nil {
		return ExitError, err
	}
	if f.watch < 0 {
		return ExitError, errors.New("--watch must be positive")
	}
	if f.watch > 0 {
		return a.watch(ctx, dir, f)
	}
	return a.checkOnce(ctx, dir, f)
}

func (a *App) options(dir string, f checkFlags, progress bool) (check.Options, error) {
	o := check.Options{Dir: dir, ManifestPath: f.manifest, Workers: f.workers}
	if f.pubkey != "" {
		pub, err := sign.ReadPublic(f.pubkey)
		if err != nil {
			return o, err
		}
		o.PublicKey = pub
	}
	if progress {
		o.Progress = a.progress(f.quiet || f.js)
	}
	return o, nil
}

func (a *App) runCheck(ctx context.Context, dir string, f checkFlags, progress bool) (*check.Result, error) {
	o, err := a.options(dir, f, progress)
	if err != nil {
		return nil, err
	}
	r, err := check.Check(ctx, o)
	if err != nil {
		return nil, err
	}
	if f.requireSignature && r.Signature != check.SigValid {
		r.Signature = check.SigInvalid
	}
	return r, nil
}

func exitFor(r *check.Result) int {
	switch {
	case len(r.Unreadable) > 0 && r.Diff.Clean():
		return ExitError
	case !r.OK():
		return ExitChanged
	}
	return ExitOK
}

func (a *App) checkOnce(ctx context.Context, dir string, f checkFlags) (int, error) {
	r, err := a.runCheck(ctx, dir, f, true)
	if err != nil {
		return ExitError, err
	}
	if f.js {
		if err := report.JSON(a.Out, r); err != nil {
			return ExitError, err
		}
	} else {
		report.Text(a.Out, r, report.TextOptions{Color: a.color(), Verbose: f.verbose, Quiet: f.quiet})
	}
	return exitFor(r), nil
}

func (a *App) watch(ctx context.Context, dir string, f checkFlags) (int, error) {
	fmt.Fprintf(a.Err, "Watching %s every %s. Press Ctrl-C to stop.\n", dir, f.watch)
	lastKey := ""
	status := ExitOK
	for {
		r, err := a.runCheck(ctx, dir, f, false)
		if err != nil {
			if ctx.Err() != nil {
				return status, nil
			}
			return ExitError, err
		}
		key := fmt.Sprintf("%v|%d|%d|%d|%d|%d|%s", r.OK(), len(r.Diff.Modified), len(r.Diff.Added),
			len(r.Diff.Removed), len(r.Diff.Renamed), len(r.Unreadable), strings.Join(changedPaths(r.Diff), ","))
		if key != lastKey {
			lastKey = key
			fmt.Fprintf(a.Out, "[%s] ", time.Now().Format("15:04:05"))
			if f.js {
				if err := report.JSON(a.Out, r); err != nil {
					return ExitError, err
				}
			} else {
				report.Text(a.Out, r, report.TextOptions{Color: a.color(), Verbose: f.verbose})
			}
		}
		status = exitFor(r)
		select {
		case <-ctx.Done():
			return status, nil
		case <-time.After(f.watch):
		}
	}
}

func changedPaths(d compare.Diff) []string {
	var out []string
	for _, c := range d.Modified {
		out = append(out, "M"+c.Path)
	}
	for _, p := range d.Added {
		out = append(out, "A"+p)
	}
	for _, p := range d.Removed {
		out = append(out, "D"+p)
	}
	for _, r := range d.Renamed {
		out = append(out, "R"+r.From+">"+r.To)
	}
	return out
}

func (a *App) diff(args []string) (int, error) {
	fs := newFlagSet(a, "diff")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitError, err
	}
	if len(pos) != 2 {
		return ExitError, errors.New("usage: assay diff <old.json> <new.json>")
	}
	oldM, err := manifest.Read(pos[0])
	if err != nil {
		return ExitError, err
	}
	newM, err := manifest.Read(pos[1])
	if err != nil {
		return ExitError, err
	}
	if oldM.Algorithm != newM.Algorithm {
		return ExitError, fmt.Errorf("the manifests use different algorithms (%s and %s); seal both with the same one", oldM.Algorithm, newM.Algorithm)
	}
	d := compare.Compare(oldM.Files, newM.Files)
	if *asJSON {
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(nonNil(d)); err != nil {
			return ExitError, err
		}
	} else {
		report.DiffText(a.Out, d, a.color())
	}
	if d.Clean() {
		return ExitOK, nil
	}
	return ExitChanged, nil
}

func nonNil(d compare.Diff) compare.Diff {
	if d.Modified == nil {
		d.Modified = []compare.Change{}
	}
	if d.Added == nil {
		d.Added = []string{}
	}
	if d.Removed == nil {
		d.Removed = []string{}
	}
	if d.Renamed == nil {
		d.Renamed = []compare.Rename{}
	}
	return d
}

func (a *App) report(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "report")
	var f checkFlags
	out := fs.String("o", "", "output `file` (required), for example report.html")
	fs.StringVar(&f.manifest, "m", "", "manifest `file` (default <folder>/.assay.json)")
	fs.StringVar(&f.pubkey, "pubkey", "", "public key `file`: verify the signature")
	fs.IntVar(&f.workers, "workers", 0, "number of parallel hash workers")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitError, err
	}
	dir, err := oneFolder(pos)
	if err != nil {
		return ExitError, err
	}
	if *out == "" {
		return ExitError, errors.New("report needs -o <file.html>")
	}
	r, err := a.runCheck(ctx, dir, f, true)
	if err != nil {
		return ExitError, err
	}
	file, err := os.Create(*out)
	if err != nil {
		return ExitError, err
	}
	if err := report.HTML(file, r); err != nil {
		file.Close()
		return ExitError, err
	}
	if err := file.Close(); err != nil {
		return ExitError, err
	}
	fmt.Fprintf(a.Out, "Report written to %s\n", *out)
	return exitFor(r), nil
}

func (a *App) export(args []string) (int, error) {
	fs := newFlagSet(a, "export")
	manifestFile := fs.String("m", "", "manifest `file` (default <folder>/.assay.json)")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitError, err
	}
	dir, err := oneFolder(pos)
	if err != nil {
		return ExitError, err
	}
	path := *manifestFile
	if path == "" {
		path = filepath.Join(dir, manifest.DefaultFile)
	}
	m, err := manifest.Read(path)
	if err != nil {
		return ExitError, err
	}
	// The same format as sha256sum/sha512sum, so `sha256sum -c` can verify it.
	for _, e := range m.Files {
		fmt.Fprintf(a.Out, "%s  %s\n", e.Hash, e.Path)
	}
	return ExitOK, nil
}

func (a *App) keygen(args []string) (int, error) {
	fs := newFlagSet(a, "keygen")
	prefix := fs.String("o", "assay", "file name `prefix`: writes <prefix>.key and <prefix>.pub")
	force := fs.Bool("force", false, "overwrite existing files")
	if _, err := parse(fs, args); err != nil {
		return ExitError, err
	}
	privPath, pubPath := *prefix+".key", *prefix+".pub"
	if !*force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return ExitError, fmt.Errorf("%s already exists (use --force to overwrite)", p)
			}
		}
	}
	pub, priv, err := sign.Generate()
	if err != nil {
		return ExitError, err
	}
	if err := sign.WritePrivate(privPath, priv); err != nil {
		return ExitError, err
	}
	if err := sign.WritePublic(pubPath, pub); err != nil {
		return ExitError, err
	}
	fmt.Fprintf(a.Out, "Wrote %s (keep it secret) and %s (share it).\nKey id: %s\n", privPath, pubPath, sign.KeyID(pub))
	return ExitOK, nil
}
