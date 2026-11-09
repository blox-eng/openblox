#!/usr/bin/env bash
# Reports test coverage per package, from the unit run and from unit and
# integration together, with the change against a baseline (#10).
#
#   coverage-report.sh UNIT_PROFILE [INTEGRATION_PROFILE] [BASELINE_JSON] JSON_OUT
#
# Writes a Markdown table to stdout and the same numbers to JSON_OUT, which a
# later run reads back as its baseline. Pass "" for an absent profile or
# baseline: the table then says the number is missing rather than inventing it.
#
# One repository-wide number would average the well-covered pure logic with
# pkg/docker and hide the gap that matters, so every package gets its own row.
# Two columns, because each answers a different question: "unit" is what the
# daemon-free suite covers, "with integration" is what CI verifies against a
# real runtime.
#
# Profiles must come from `go test -covermode=atomic -coverpkg=./...`. With
# -coverpkg every test binary reports every package, so one block can appear
# many times; a block counts as covered if any run covered it.
set -euo pipefail

unit=${1:?usage: coverage-report.sh UNIT_PROFILE [INTEGRATION_PROFILE] [BASELINE_JSON] JSON_OUT}
integration=${2:-}
baseline=${3:-}
out=${4:?usage: coverage-report.sh UNIT_PROFILE [INTEGRATION_PROFILE] [BASELINE_JSON] JSON_OUT}
module=$(go list -m)

# Prints "package<TAB>percent" per package, then "total<TAB>percent".
per_package() { # profiles...
  awk -v module="$module/" '
    FNR == 1 && /^mode:/ { next }
    {
      # file.go:12.3,15.4 statements count
      split($1, loc, ":")
      key = $1
      stmts[key] = $2
      if ($3 > 0) covered[key] = 1
      pkg = loc[1]; sub(/\/[^\/]*$/, "", pkg); sub("^" module, "", pkg)
      pkgof[key] = pkg
    }
    END {
      for (k in stmts) {
        p = pkgof[k]
        total[p] += stmts[k]; all += stmts[k]
        if (k in covered) { hit[p] += stmts[k]; allhit += stmts[k] }
      }
      for (p in total) printf "%s\t%.1f\n", p, 100 * hit[p] / total[p]
      if (all > 0) printf "total\t%.1f\n", 100 * allhit / all
    }' "$@" | sort
}

[ -s "$unit" ] || { echo "FAIL: unit profile '$unit' is missing or empty" >&2; exit 1; }
unit_rows=$(per_package "$unit")
combined_rows=""
if [ -n "$integration" ] && [ -s "$integration" ]; then
  combined_rows=$(per_package "$unit" "$integration")
fi

# {"pkg/docker": {"unit": 49.3, "combined": 81.2}, ..., "total": {...}}
jq -n --arg unit "$unit_rows" --arg combined "$combined_rows" '
  def rows($s): $s | split("\n") | map(select(. != "") | split("\t") | {key: .[0], value: (.[1] | tonumber)}) | from_entries;
  rows($unit) as $u | rows($combined) as $c
  | reduce ($u | keys[]) as $p ({}; .[$p] = {unit: $u[$p], combined: $c[$p]})' > "$out"

base='{}'
if [ -n "$baseline" ] && [ -s "$baseline" ]; then
  base=$(cat "$baseline")
fi

# A missing number prints as "n/a", never as 0%; a missing baseline leaves the
# change blank rather than showing every package as new.
jq -r --argjson base "$base" --arg have_base "$([ "$base" != '{}' ] && echo yes)" '
  def pct: if . == null then "n/a" else "\(.)%" end;
  def delta($now; $was):
    if $have_base != "yes" or $now == null or $was == null then ""
    elif ($now - $was) > 0.05 then " (+\(($now - $was) * 10 | round / 10))"
    elif ($now - $was) < -0.05 then " (\(($now - $was) * 10 | round / 10))"
    else "" end;
  def row($p): .[$p] as $r | $base[$p] as $b
    | "| \($p) | \($r.unit | pct)\(delta($r.unit; $b.unit)) | \($r.combined | pct)\(delta($r.combined; $b.combined)) |";
  "| Package | Unit | With integration |",
  "|---|---|---|",
  (keys - ["total"] | .[] as $p | $root | row($p)),
  ($root | row("total") | sub("^\\| total"; "| **total**"))
' --argjson root "$(cat "$out")" "$out"

if [ -z "$combined_rows" ]; then
  echo
  echo "_With integration: n/a. This run has no integration profile, because the integration job failed or was skipped._"
fi
if [ "$base" = '{}' ]; then
  echo
  echo "_No change shown: no baseline from main was found._"
fi
