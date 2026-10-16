# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions: [Semantic Versioning](https://semver.org/).

## [Unreleased]

First public version.

### Added
- `seal`, `check`, `diff`, `report`, `export`, `keygen`, `version`.
- Detection of modified, added, removed and renamed files; parallel hashing; SHA-256 and SHA-512.
- Ed25519 signatures that cover the root hash, the algorithm and the ignore patterns.
- `.hallmarkignore` and `--exclude` with `.gitignore` semantics; patterns are stored in the manifest.
- Text, JSON and HTML output; `--watch`; exit codes for scripts.
- Strict validation of manifests, fuzzed parsers, atomic manifest writes.
