# Security model

What a Assay check proves depends on whether the manifest is signed and where it is kept.

| Situation | What `check` tells you |
| --- | --- |
| Unsigned manifest stored with the files | The files are consistent with that manifest. An attacker who can write the folder can also replace the manifest, so this protects against accidents and sloppy tampering, not a determined attacker. |
| Unsigned manifest stored somewhere the attacker cannot write | The files are unchanged since the seal, as long as the manifest copy is safe. |
| Signed manifest, checked with `--pubkey` obtained separately | The files are what the holder of the private key sealed. Replacing the manifest breaks the signature. |

## What a signature covers

The root hash (every path, size and content hash), the hash algorithm and the ignore patterns.
Adding an ignore pattern to hide a file therefore invalidates the signature.

## What it does not cover

- **Who** made a change, and **when**.
- **Rollback of the whole folder** to an older, validly signed state. Keep a trail of seals (see
  `assay diff`) or put the signed manifest in version control or a timestamping service if replay
  is a concern.
- File permissions, owners and timestamps.
- Files outside the folder, and files hidden by ignore patterns the signer chose.
- Anything on a machine where the attacker controls the `assay` binary or your public key.

## Key handling

- Create the key pair on a machine you trust: `assay keygen`. The private key file is written with
  mode `0600` where the system supports it.
- Do not keep the private key on the machine that stores the sealed files.
- Share the public key through a channel the attacker does not control. `key_id` helps you see which
  key signed a manifest, but it is not a trust anchor.
- Keys are not password protected. Encrypt the disk or use your secret store.

## Input handling

A manifest is untrusted input. Assay rejects paths that leave the folder, duplicated entries,
malformed hashes and unknown formats before it touches the file system, and it never follows symbolic
links while scanning. The parsers are fuzzed.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
