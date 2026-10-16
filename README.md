# Assay

**See whether files were changed.** Seal a folder once, check it whenever you like.

```console
$ assay seal ./backups
Sealed 1204 files -> backups/.assay.json

$ assay check ./backups
Checked 1204 files against backups/.assay.json (sealed 2026-10-16T09:12:44Z, sha256)
  modified  db/users.sqlite (4.2 MiB -> 4.2 MiB)
  added     db/users.sqlite-wal
  removed   logs/2026-10-01.log
  renamed   notes.txt -> archive/notes.txt
CHANGED: 1 modified, 1 added, 1 removed, 1 renamed, 1200 unchanged
```

> *assay* (noun): the testing of a metal to find out whether it is what it claims to be. An assay
> office tests the metal and then stamps the hallmark on it.

Assay records a cryptographic hash of every file in a manifest and later tells you exactly what
differs: **modified**, **added**, **removed** or **renamed**. It is a single static binary with no
dependencies and no daemon.

## Why

`sha256sum -c` checks the files you listed and says nothing about files that appeared. Tripwire and
AIDE do the whole job but are built for system administrators. Assay sits in between:

| | `sha256sum -c` | AIDE / Tripwire | **Assay** |
| --- | :---: | :---: | :---: |
| Whole folder, finds **new** files | no | yes | **yes** |
| Recognises **renames** | no | partly | **yes** |
| One small binary, Linux macOS Windows | partly | no | **yes** |
| Manifest that diffs well in git | yes | no | **yes** |
| Signed manifests (Ed25519) | no | yes | **yes** |
| Readable output, `--json`, HTML report | no | partly | **yes** |
| Needs root or a database | no | yes | **no** |

Typical uses: verify backups and archives, detect tampering with deployed sites or release
directories, prove that a dataset or evidence folder did not change, check a build output, or find out
what a script really touched.

## Install

**Debian, Ubuntu and derivatives (apt):**

```console
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://sandsoftwaresolutions.github.io/apt/key.asc | sudo tee /etc/apt/keyrings/sandsoftwaresolutions.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/sandsoftwaresolutions.asc] https://sandsoftwaresolutions.github.io/apt stable main" | sudo tee /etc/apt/sources.list.d/sandsoftwaresolutions.list
sudo apt update
sudo apt install assay
```

Updates then arrive with `sudo apt upgrade`. The repository is signed; see
[SandSoftwareSolutions/apt](https://github.com/SandSoftwareSolutions/apt).

```console
go install github.com/SandSoftwareSolutions/assay@latest
```

Or one of these:

- **Install script** (Linux, macOS; checks the SHA-256 checksum, never uses sudo):
  `curl -fsSL https://raw.githubusercontent.com/SandSoftwareSolutions/assay/main/install.sh | sh`
- **Release archive** for Linux, macOS and Windows (amd64 and arm64) from the releases page. Check it
  with `SHA256SUMS`, and with `gh attestation verify` for the build provenance.
- **A single `.deb`** from the releases page, if you prefer not to add the apt repository.
- **From source:** `make build` (Go 1.22 or newer).

Check it works with `assay version`.

## Use

```console
assay seal [folder]                 # write folder/.assay.json
assay check [folder]                # compare; exit status 0 = unchanged, 1 = changes, 2 = error
assay check --json                  # machine readable
assay check --watch 30s             # keep checking, print when the picture changes
assay diff old.json new.json        # compare two seals (two points in time)
assay report -o report.html         # a self-contained HTML report
assay export > SHA256SUMS           # sha256sum -c compatible lines
```

Useful flags: `-m file` (manifest elsewhere, for example on another disk), `--exclude pattern`
(repeatable), `--algo sha512`, `-q` (quiet when fine), `--workers N`.

Put patterns in a `.assayignore` file in the folder (same rules as `.gitignore`) or pass
`--exclude`. The patterns in effect are stored in the manifest, so later changes to the ignore file
cannot silently change what a seal means.

In scripts:

```bash
assay check /srv/site -q || { echo "site changed!" | mail -s alert ops@example.com; }
```

## Sign it, so the manifest cannot be swapped

A hash tells you the files differ from the manifest. It cannot tell you the manifest is genuine:
whoever can change your files can also seal them again. A signature closes that gap.

```console
$ assay keygen -o release          # writes release.key (secret) and release.pub (share)
$ assay seal ./dist --key release.key
$ assay check ./dist --pubkey release.pub --require-signature
signature valid: signed by key 6f1c0a9e22b4d7a1
OK: all 38 files are unchanged
```

The signature covers the root hash (which covers every path, size and hash), the algorithm and the
ignore patterns. Keep the private key off the machine that holds the files.
See [docs/security-model.md](docs/security-model.md) for what Assay does and does not prove.

## How it works

- Every regular file is hashed with SHA-256 (or SHA-512) in parallel. Symbolic links are skipped,
  never followed.
- The manifest is a small JSON file: algorithm, ignore patterns, root hash and one
  `{path, size, hash}` per file, sorted. It has no timestamps per file, so sealing an unchanged
  folder twice gives byte for byte the same manifest apart from the creation time. See
  [docs/format.md](docs/format.md).
- `check` re-hashes the folder and compares. A removed and an added file with identical content are
  reported as a **rename**.
- A manifest is treated as untrusted input: paths that leave the folder, duplicate entries and
  malformed hashes are rejected.
- Unreadable files are reported and never mistaken for deleted ones.

## Exit status

| Code | Meaning |
| --- | --- |
| 0 | Everything matches |
| 1 | Differences found, a damaged manifest or an invalid signature |
| 2 | An error: bad usage, unreadable files, no manifest |

## Limits

- Assay detects changes. It cannot say who made them or prevent them.
- It compares content, size and path. File permissions, owners and timestamps are not recorded.
- Without a signature, the manifest is only as safe as the place you keep it.

## Development

```console
make check     # gofmt, vet, tests
make race      # tests with the race detector
make fuzz      # short fuzzing run of the parsers
make dist      # release archives and SHA256SUMS in dist/
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
