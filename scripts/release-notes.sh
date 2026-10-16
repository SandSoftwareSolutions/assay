#!/usr/bin/env bash
# Prints the release notes for a version from CHANGELOG.md.
#   scripts/release-notes.sh 1.2.3     # the "## [1.2.3]" section, or "## [Unreleased]" if it is missing
# Exits with status 1 and prints nothing when neither section exists.
set -euo pipefail
version="${1:?usage: release-notes.sh <version>}"
version="${version#v}"
file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md"

extract() {
  awk -v want="$1" '
    /^## \[/ { if (inside) exit; inside = (index($0, "## [" want "]") == 1); next }
    inside { print }
  ' "$file"
}

notes="$(extract "$version")"
[ -n "$notes" ] || notes="$(extract "Unreleased")"
[ -n "$notes" ] || exit 1
printf '%s\n' "$notes" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
