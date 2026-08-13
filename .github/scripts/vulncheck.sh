#!/usr/bin/env bash
# Fails if govulncheck reports a reachable vulnerability that is not in the
# allowlist.
#
# govulncheck exits non-zero on ANY finding, which makes it useless as a gate
# when a dependency has a reachable vulnerability with no fix published: the
# check goes permanently red and people learn to ignore it. This narrows the
# gate to what is actionable — a NEW reachable vulnerability — while keeping
# the known-unfixable ones written down in .github/vuln-allowlist.txt rather
# than silently suppressed.
#
# Run it the same way locally: .github/scripts/vulncheck.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
ALLOWLIST=".github/vuln-allowlist.txt"

echo "running govulncheck..."
# Do not let a non-zero exit kill the script; the findings are the output we want.
json="$(govulncheck -format json ./... 2>/dev/null || true)"

reachable="$(printf '%s' "$json" | python3 -c '
import sys, json
# govulncheck emits a stream of pretty-printed JSON objects, not one per line,
# so decode incrementally rather than parsing line by line.
text = sys.stdin.read()
dec = json.JSONDecoder()
idx, ids = 0, set()
n = len(text)
while idx < n:
    while idx < n and text[idx] in " \t\r\n":
        idx += 1
    if idx >= n:
        break
    try:
        obj, end = dec.raw_decode(text, idx)
    except json.JSONDecodeError:
        break
    idx = end
    if not isinstance(obj, dict):
        continue
    finding = obj.get("finding")
    if not isinstance(finding, dict):
        continue
    # A trace whose first frame names a function is one govulncheck traced into
    # our code. Findings without it are only present in the module graph, which
    # is not what we gate on.
    trace = finding.get("trace") or []
    if trace and isinstance(trace[0], dict) and trace[0].get("function") and finding.get("osv"):
        ids.add(finding["osv"])
for i in sorted(ids):
    print(i)
')"

allowed="$(grep -vE '^\s*(#|$)' "$ALLOWLIST" 2>/dev/null | tr -d ' \t' || true)"

unexpected=""
for id in $reachable; do
  if ! printf '%s\n' "$allowed" | grep -qx "$id"; then
    unexpected="$unexpected $id"
  fi
done

if [ -n "$reachable" ]; then
  echo
  echo "reachable vulnerabilities:"
  for id in $reachable; do
    if printf '%s\n' "$allowed" | grep -qx "$id"; then
      echo "  $id  (allowlisted)"
    else
      echo "  $id  <-- NOT ALLOWLISTED"
    fi
  done
fi

# An allowlist entry that no longer appears is stale — the vulnerability was
# fixed, or the code path went away. Say so, so the file does not accumulate
# exceptions nobody revisits.
for id in $allowed; do
  if ! printf '%s\n' "$reachable" | grep -qx "$id"; then
    echo "note: $id is allowlisted but no longer reachable — remove it from $ALLOWLIST"
  fi
done

if [ -n "$unexpected" ]; then
  echo
  echo "FAIL: new reachable vulnerabilities:$unexpected"
  echo "Fix them, or add to $ALLOWLIST with a reason and a route out."
  exit 1
fi

echo
echo "OK: no reachable vulnerabilities outside the allowlist"
