#!/usr/bin/env bash
# Builds release archives for the common platforms into dist/ and writes SHA256SUMS.
# Nothing in the source tree is modified; the version is injected with -ldflags.
#
#   scripts/dist.sh                  # version from git (git describe)
#   VERSION=1.2.3 scripts/dist.sh
#
# Output per platform: hallmark_<version>_<os>_<arch>.tar.gz (.zip for Windows), containing the binary,
# LICENSE and README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODULE="github.com/SandSoftwareSolutions/hallmark"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X $MODULE/internal/cli.Version=$VERSION -X $MODULE/internal/cli.Commit=$COMMIT -X $MODULE/internal/cli.Date=$DATE"
OUT="$ROOT/dist"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)

for target in "${TARGETS[@]}"; do
  os="${target%/*}"; arch="${target#*/}"
  name="hallmark_${VERSION}_${os}_${arch}"
  dir="$WORK/$name"
  mkdir -p "$dir"
  bin="hallmark"; [ "$os" = windows ] && bin="hallmark.exe"
  echo "[build] $os/$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$dir/$bin" .
  cp LICENSE README.md "$dir/"
  if [ "$os" = windows ]; then
    (cd "$WORK" && zip -qr "$OUT/$name.zip" "$name")
  else
    tar -C "$WORK" -czf "$OUT/$name.tar.gz" "$name"
  fi
done

(cd "$OUT" && : > SHA256SUMS && for f in *.tar.gz *.zip; do [ -e "$f" ] && sha256sum "$f" >> SHA256SUMS; done; true)
echo "Done. Artifacts and SHA256SUMS are in $OUT"
