#!/usr/bin/env bash
# Generates shields.io endpoint badges from the repository as it actually is.
#
# The numbers in a README rot the moment someone adds a test and forgets the
# prose. These are measured on every deploy instead: the badge and the code
# cannot disagree, because one is derived from the other.
#
# Output is the shields.io endpoint schema, published to the docs site and read
# back by img.shields.io. Usage: badges.sh <output-dir>
set -euo pipefail

OUT=${1:?usage: badges.sh <output-dir>}
mkdir -p "$OUT"

# Private scratch, cleaned up on exit. Fixed /tmp paths would let a reused
# runner hand us a stale — or planted — coverage profile from an earlier job.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

badge() { # name label message color
  printf '{"schemaVersion":1,"label":"%s","message":"%s","color":"%s","cacheSeconds":3600}\n' \
    "$2" "$3" "$4" > "$OUT/$1.json"
  echo "$1: $3"
}

# Test counts, split by build tag. Integration tests need Docker and runsc, so
# they are counted but not run here — claiming them as "passing" would be a lie.
integration_files=$(grep -rl 'go:build integration' --include='*_test.go' pkg || true)
unit_files=$(grep -rL 'go:build integration' --include='*_test.go' -r pkg || true)

count_tests() { # files...
  [ -z "$1" ] && { echo 0; return; }
  # grep exits 1 when a file holds only helpers and no Test function. Under
  # pipefail that would kill the script, so absence is normalised to zero here.
  # shellcheck disable=SC2086
  { grep -ho '^func Test[A-Za-z0-9_]*' $1 || true; } | wc -l | tr -d ' '
}

unit=$(count_tests "$unit_files")
integration=$(count_tests "$integration_files")

# One run, both badges. Running the suite twice would let the tests badge and
# the coverage badge observe different outcomes and disagree with each other.
if go test -coverprofile="$WORK/cover.out" ./... > "$WORK/test.log" 2>&1; then
  badge tests tests "$unit passing" brightgreen
else
  badge tests tests failing red
  echo "--- go test output ---"
  cat "$WORK/test.log"
fi

badge integration "integration tests" "$integration" blue

# Coverage over the unit suite only. Labelled as such: most of pkg/docker is
# exercised by the integration suite, which does not run in CI (issue #3), so an
# unqualified "coverage" number here would overstate what CI verifies.
#
# A failing suite may leave no profile at all, so its absence reports zero
# rather than aborting the whole badge run.
pct=0
if [ -s "$WORK/cover.out" ]; then
  pct=$(go tool cover -func="$WORK/cover.out" | awk '/^total:/ {print $3}' | tr -d '%')
fi
pct=${pct:-0}
# Colour thresholds are deliberately modest — this measures the unit suite alone.
if   awk "BEGIN{exit !($pct >= 70)}"; then colour=brightgreen
elif awk "BEGIN{exit !($pct >= 50)}"; then colour=green
elif awk "BEGIN{exit !($pct >= 30)}"; then colour=yellow
else                                       colour=orange
fi
badge coverage "coverage (unit)" "${pct}%" "$colour"

# Size, so "small enough to read in an afternoon" is a number and not a boast.
loc=$(find pkg -name '*.go' ! -name '*_test.go' -print0 | xargs -0 cat | wc -l | tr -d ' ')
badge loc "lines of go" "$loc" informational
