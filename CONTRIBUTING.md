# Contributing

Hallmark does one thing. Changes that keep it small, predictable and dependency free are the easiest
to accept.

```console
git clone https://github.com/SandSoftwareSolutions/hallmark
cd hallmark
make check
```

Go 1.22 or newer is enough. The project has **no third-party dependencies** and wants to keep it that
way: use the standard library.

Before a pull request:

- `make check` passes; `make race` for concurrent code; `make lint` and `make vuln` run staticcheck and govulncheck as CI does.
- New behaviour has a test. Anything that parses untrusted input (manifests, key files, ignore
  patterns) needs a malformed-input test, ideally a fuzz target.
- User visible changes get a line in `CHANGELOG.md`.

Design rules:

1. **A manifest is untrusted input.** Validate before use.
2. **Never follow symbolic links** while scanning.
3. **Exit codes are an interface.** 0 clean, 1 changes, 2 error.
4. **Reproducible output.** Sorted, no per-file timestamps, no map iteration order.
5. **Say what is not proven.** Do not make the output sound stronger than it is.

By contributing you agree to license your contribution under AGPL-3.0-or-later.
