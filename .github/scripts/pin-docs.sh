#!/usr/bin/env bash
# Keeps the version pins a reader copies on the current release (#91).
#
#   pin-docs.sh 0.13.1   rewrites every pin below to that version
#   pin-docs.sh --check  fails if a pin is not the newest release in CHANGELOG.md
#
# The release workflow runs the first form in the changelog pull request, so the
# changelog and the pins change in one commit. Lint runs the second, so main
# always passes, and a pin changed by hand without a release fails at once.
#
# Each pin is a file and the text before the version. Both forms fail if a pin
# matches nothing, so a reworded doc cannot drop out of the list unnoticed.
# Benchmark results and RELEASING.md examples are not pins: they name the
# version that was measured or illustrated.
set -euo pipefail

cd "$(dirname "$0")/../.."

PINS=(
  "README.md|OPENBLOX_VERSION=v"
  "docs/production.md|OPENBLOX_VERSION=v"
  "docs/production.md|must print v"
  "docs/production.md|gh release download v"
  "docs/production.md|^VERSION=v"
  "docs/security.md|^VERSION=v"
  "docs/image.md|openblox-sandbox:"
)
SEMVER='[0-9]+\.[0-9]+\.[0-9]+'

case "${1:-}" in
  --check)
    want="$(grep -m1 -oE "^## \[$SEMVER\] - " CHANGELOG.md | grep -oE "$SEMVER")" || {
      echo "FAIL: CHANGELOG.md has no released '## [X.Y.Z] - ' heading" >&2
      exit 1
    }
    mode="check"
    ;;
  "")
    echo "usage: pin-docs.sh VERSION | --check" >&2
    exit 2
    ;;
  *)
    want="$1"
    if [[ ! "$want" =~ ^${SEMVER}$ ]]; then
      echo "FAIL: '$want' is not a release version (like 0.13.1, no 'v')" >&2
      exit 2
    fi
    mode="write"
    ;;
esac

status=0
for pin in "${PINS[@]}"; do
  file="${pin%%|*}"
  prefix="${pin#*|}"
  found="$(grep -oE "${prefix}${SEMVER}" "$file" | grep -oE "${SEMVER}$" | sort -u)" || {
    echo "FAIL: $file has no pin matching '${prefix}X.Y.Z': update PINS in $0" >&2
    status=1
    continue
  }
  if [ "$mode" = write ]; then
    sed -E -i "s/(${prefix})${SEMVER}/\1${want}/g" "$file"
  elif [ "$found" != "$want" ]; then
    echo "FAIL: $file pins $(echo "$found" | paste -sd, -) at '${prefix}', but the newest release in CHANGELOG.md is $want." >&2
    echo "      Run .github/scripts/pin-docs.sh $want" >&2
    status=1
  fi
done

[ "$status" = 0 ] && echo "OK: every pin is $want"
exit "$status"
