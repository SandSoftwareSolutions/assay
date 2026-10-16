#!/bin/sh
# Installs the latest assay release for Linux or macOS, after checking its SHA-256 checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/SandSoftwareSolutions/assay/main/install.sh | sh
#   sh install.sh --version 1.2.3 --dir ~/.local/bin
#
# Read the script before you pipe it into a shell; it is short on purpose. It downloads only from
# github.com, installs one file and never uses sudo.
set -eu

NAME="assay"
REPO="SandSoftwareSolutions/assay"
VERSION=""
DIR="${HOME}/.local/bin"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --dir) DIR="${2:?--dir needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "this installer needs '$1'" >&2; exit 1; }; }
need curl; need tar; need uname
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"; else echo "this installer needs sha256sum or shasum" >&2; exit 1; fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported system: $(uname -s). Windows users: download the .zip from the releases page." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported processor: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ] && [ -z "${RELEASE_BASE_URL:-}" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$VERSION" ] || { echo "could not find the latest release" >&2; exit 1; }
fi
[ -n "$VERSION" ] || { echo "with RELEASE_BASE_URL you must also give --version" >&2; exit 1; }
VERSION="${VERSION#v}"

archive="${NAME}_${VERSION}_${os}_${arch}.tar.gz"
# RELEASE_BASE_URL lets you install from a mirror or from a local directory served over http (used by tests).
base="${RELEASE_BASE_URL:-https://github.com/$REPO/releases/download/v$VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $archive ..."
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

expected="$(awk -v f="$archive" '$2 == f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || { echo "no checksum listed for $archive" >&2; exit 1; }
actual="$(cd "$tmp" && $SHA "$archive" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch for $archive; refusing to install" >&2
  exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$DIR"
install -m 0755 "$tmp/${NAME}_${VERSION}_${os}_${arch}/$NAME" "$DIR/$NAME"
echo "Installed $NAME $VERSION to $DIR/$NAME"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "Add $DIR to your PATH, for example:  export PATH=\"$DIR:\$PATH\"" ;;
esac
