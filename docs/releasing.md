# Releasing

Releases are cut from `main` by pushing a tag. Nothing is published until a person presses *Publish*.

1. Make sure `main` is green (the `CI` workflow, including the `ci-ok` job).
2. Move the *Unreleased* entries in `CHANGELOG.md` under a new heading `## [X.Y.Z] - YYYY-MM-DD` and
   commit.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The `Release` workflow checks the tag is a version on `main`, runs the tests, builds archives for
   Linux, macOS and Windows (amd64 and arm64) and Linux `.deb` packages, writes `SHA256SUMS`, renders the
   Homebrew formula and Scoop manifest (`dist/packaging/`), attests the build provenance and creates a
   **draft** release with the changelog section as notes.
5. Review the draft, then publish it. Tags with a hyphen (`v1.2.3-rc.1`) become pre-releases.

`go install github.com/SandSoftwareSolutions/assay@vX.Y.Z` works as soon as the tag exists.

## apt repository

Publishing a release is enough: the repository at https://github.com/SandSoftwareSolutions/apt rebuilds
every six hours and picks up the `.deb` files of the newest releases (run its *Update repository*
workflow to update it right away). Users then get the new version with `sudo apt upgrade`.

## Verifying a download

```console
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify assay_X.Y.Z_linux_amd64.tar.gz --repo SandSoftwareSolutions/assay
```

## Branch protection (recommended)

Require pull requests into `main` and the status check `ci-ok`. Enable *Dependabot alerts* and
*Code scanning*; the CodeQL workflow reports into the Security tab.

## Package managers

The release carries a Homebrew formula (`assay.rb`) and a Scoop manifest (`assay.json`) with the
right URLs and checksums. To offer them, copy them into a tap repository
(`homebrew-tap`, then `brew install SandSoftwareSolutions/tap/assay`) and a Scoop bucket. Neither
repository exists yet.
