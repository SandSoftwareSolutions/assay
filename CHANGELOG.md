# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions: [Semantic Versioning](https://semver.org/).

## [Unreleased]

First public version.

### Added
- Packaging: a checksum-verifying install script, `.deb` packages, Homebrew and Scoop manifests and
  build provenance attestations for every release.
- CI/CD: test matrix (Linux, macOS, Windows; oldest and newest Go) with the race detector and coverage,
  short fuzzing, gofmt, vet, `go mod tidy` check, staticcheck, govulncheck, cross-compile check, a
  dogfood job (assay seals and checks its own repository), CodeQL, Dependabot, and a tag-driven
  release workflow that builds archives, attests build provenance and creates a draft release.
- `seal`, `check`, `diff`, `report`, `export`, `keygen`, `version`.
- Detection of modified, added, removed and renamed files; parallel hashing; SHA-256 and SHA-512.
- Ed25519 signatures that cover the root hash, the algorithm and the ignore patterns.
- `.assayignore` and `--exclude` with `.gitignore` semantics; patterns are stored in the manifest.
- Text, JSON and HTML output; `--watch`; exit codes for scripts.
- Strict validation of manifests, fuzzed parsers, atomic manifest writes.
