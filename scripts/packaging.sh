#!/usr/bin/env bash
# Renders package-manager manifests (Homebrew formula, Scoop manifest) for a release, using the
# checksums that scripts/dist.sh wrote. The results go to dist/packaging/ and are meant to be copied
# into a Homebrew tap and a Scoop bucket after the release is published.
#
#   scripts/packaging.sh 1.2.3
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:?usage: packaging.sh <version>}"; VERSION="${VERSION#v}"
NAME="assay"
CLASS="Assay"
REPO="SandSoftwareSolutions/assay"
DESC="See whether files were changed"
LICENSE_ID="AGPL-3.0-or-later"
SUMS="$ROOT/dist/SHA256SUMS"
OUT="$ROOT/dist/packaging"
[ -f "$SUMS" ] || { echo "dist/SHA256SUMS not found; run scripts/dist.sh first" >&2; exit 1; }
mkdir -p "$OUT"

sum() { # os arch ext
  local file="${NAME}_${VERSION}_$1_$2.$3" hash
  hash="$(awk -v f="$file" '$2 == f {print $1}' "$SUMS")"
  [ -n "$hash" ] || { echo "no checksum for $file" >&2; exit 1; }
  printf '%s' "$hash"
}
url() { printf 'https://github.com/%s/releases/download/v%s/%s_%s_%s_%s.%s' "$REPO" "$VERSION" "$NAME" "$VERSION" "$1" "$2" "$3"; }

cat > "$OUT/$NAME.rb" <<RUBY
class $CLASS < Formula
  desc "$DESC"
  homepage "https://github.com/$REPO"
  version "$VERSION"
  license "$LICENSE_ID"

  on_macos do
    if Hardware::CPU.arm?
      url "$(url darwin arm64 tar.gz)"
      sha256 "$(sum darwin arm64 tar.gz)"
    else
      url "$(url darwin amd64 tar.gz)"
      sha256 "$(sum darwin amd64 tar.gz)"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$(url linux arm64 tar.gz)"
      sha256 "$(sum linux arm64 tar.gz)"
    else
      url "$(url linux amd64 tar.gz)"
      sha256 "$(sum linux amd64 tar.gz)"
    end
  end

  def install
    bin.install "$NAME"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/$NAME version")
  end
end
RUBY

cat > "$OUT/$NAME.json" <<JSON
{
  "version": "$VERSION",
  "description": "$DESC",
  "homepage": "https://github.com/$REPO",
  "license": "$LICENSE_ID",
  "architecture": {
    "64bit": {
      "url": "$(url windows amd64 zip)",
      "hash": "$(sum windows amd64 zip)",
      "extract_dir": "${NAME}_${VERSION}_windows_amd64"
    },
    "arm64": {
      "url": "$(url windows arm64 zip)",
      "hash": "$(sum windows arm64 zip)",
      "extract_dir": "${NAME}_${VERSION}_windows_arm64"
    }
  },
  "bin": "$NAME.exe",
  "checkver": "github",
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "https://github.com/$REPO/releases/download/v\$version/${NAME}_\$version_windows_amd64.zip",
        "extract_dir": "${NAME}_\$version_windows_amd64"
      },
      "arm64": {
        "url": "https://github.com/$REPO/releases/download/v\$version/${NAME}_\$version_windows_arm64.zip",
        "extract_dir": "${NAME}_\$version_windows_arm64"
      }
    },
    "hash": {
      "url": "https://github.com/$REPO/releases/download/v\$version/SHA256SUMS",
      "regex": "\$sha256\\\\s+\$basename"
    }
  }
}
JSON
echo "Wrote $OUT/$NAME.rb and $OUT/$NAME.json"
