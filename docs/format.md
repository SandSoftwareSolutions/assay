# Manifest format (version 1)

A manifest is a UTF-8 JSON file, by default `.hallmark.json` in the sealed folder.

```json
{
  "format": 1,
  "tool": "hallmark",
  "algorithm": "sha256",
  "created": "2026-10-16T09:12:44Z",
  "root": "1a94f81b...",
  "ignore": ["*.log", "node_modules/"],
  "files": [
    { "path": "docs/readme.txt", "size": 1204, "hash": "e3b0c442..." }
  ],
  "signature": { "alg": "ed25519", "key_id": "6f1c0a9e22b4d7a1", "value": "base64..." }
}
```

| Field | Meaning |
| --- | --- |
| `format` | Always `1` in this version. A reader must refuse formats it does not know. |
| `tool` | Always `"hallmark"`. |
| `algorithm` | `sha256` or `sha512`. Decides the length of every hash. |
| `created` | When the seal was made (RFC 3339, UTC). Informative only. |
| `root` | Hash over all file entries, see below. |
| `ignore` | The ignore patterns in effect when sealing, in `.gitignore` syntax. Optional. |
| `files` | One entry per file, sorted by `path` (bytewise). |
| `signature` | Optional Ed25519 signature, see below. |

## Entries

- `path` is relative to the sealed folder, uses `/` on every platform, is clean (no `.`, `..`,
  doubled slashes), never starts with `/` or a drive letter and holds no control characters.
- `size` is the size in bytes.
- `hash` is the lowercase hex digest of the file content.

Symbolic links, sockets and other non-regular files are not recorded.

## Root hash

```
root = H( line(e1) || line(e2) || ... )      with entries sorted by path
line(e) = hash + " " + size + " " + path + "\n"
```

`H` is the manifest's algorithm. Because the root covers path, size and hash of every entry, changing
any of them, or adding or dropping an entry, changes the root.

## Signature

The signed message is these four lines, each ending in a newline:

```
hallmark/1
<algorithm>
<root>
<sha256 hex of the ignore patterns joined with "\n">
```

`alg` is `ed25519`, `key_id` is the first 8 bytes of the SHA-256 of the public key in hex, and
`value` is the base64 signature. A verifier must use a public key it obtained separately from the
manifest.

## Key files

A text file with one line: `hallmark-ed25519-private-key: <base64 seed>` or
`hallmark-ed25519-public-key: <base64 key>`.

## Export

`hallmark export` prints `<hash>  <path>` lines, the format of `sha256sum` and `sha512sum`, so
`cd folder && sha256sum -c SHA256SUMS` verifies the listed files with standard tools.
