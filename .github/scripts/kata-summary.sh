#!/usr/bin/env bash
# Usage: render.sh <go test -json file>  — prints a markdown table; exits 1 if
# the run produced no property results at all.
set -euo pipefail
rows=$(jq -r '
  select(.Test != null
         and (.Test | test("^TestConformanceKata/[^/]+/[^/]+$"))
         and (.Action == "pass" or .Action == "fail" or .Action == "skip"))
  | (.Test | split("/")) as $p
  | "| \($p[1]) | `\($p[2])` | \(.Action | ascii_upcase) |"' "$1")
if [ -z "$rows" ]; then
  echo "**No property results.** The run did not reach the suite (build error, panic, timeout or preflight failure); see the job log."
  exit 1
fi
echo "| Tier | Property | Result |"
echo "|---|---|---|"
echo "$rows"
echo
printf '**%s passed, %s failed, %s skipped** of %s.\n' \
  "$(grep -c '| PASS |$' <<<"$rows" || true)" \
  "$(grep -c '| FAIL |$' <<<"$rows" || true)" \
  "$(grep -c '| SKIP |$' <<<"$rows" || true)" \
  "$(wc -l <<<"$rows")"
