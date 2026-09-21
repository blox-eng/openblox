#!/usr/bin/env bash
# Generate the third-party licence bundle for the openbloxd binaries.
#
# The binaries are statically linked, so every dependency's compiled object code
# is *inside* the file a user downloads. Apache-2.0 §4(a), MIT and BSD alike
# permit that copy only on the condition that the licence text travels with it,
# so the bundle ships on the release next to the binaries it describes.
#
# The module list comes from `go list -deps ./cmd/openbloxd`, not from go.mod:
# go.mod also names test-only and other-platform modules (gotest.tools,
# Microsoft/go-winio, moby/term) that never reach the binary. Attribution should
# describe what is actually distributed, and over-attributing is its own kind of
# wrong answer.
#
# Both published architectures are unioned into one bundle. The set happens to be
# identical today, but build constraints can make it diverge, and a single file
# covering both binaries cannot drift against whichever arch a user downloaded.
#
# Licence text is read from the module cache, so it is the text shipped by the
# exact version go.sum pins rather than whatever a scanner's database believes
# that module is under.
#
# A module with no licence file is a hard failure. A bundle that quietly skips
# one still claims to be complete, which is worse than having no bundle at all.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

out="${1:-THIRD_PARTY_LICENSES.txt}"

go mod download

# `grep -v` finds nothing to drop only if the dependency graph is empty, which is
# a failure worth seeing rather than an empty bundle; `|| true` would hide it.
modules="$(
  {
    GOOS=linux GOARCH=amd64 go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/openbloxd
    GOOS=linux GOARCH=arm64 go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/openbloxd
  } | sort -u | grep -v -e '^$' -e '^github.com/blox-eng/openblox$'
)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

cat >"$tmp" <<'HEADER'
Third-party licences bundled into the openbloxd binaries
========================================================

openbloxd is MIT licensed; see LICENSE for its own terms. The binaries are
statically linked, so they also contain the modules listed below. Each module's
licence text is reproduced in full, along with the NOTICE file for the modules
that ship one.

This file is generated on every release from the modules `go list -deps` reports
for ./cmd/openbloxd, so it describes what is linked in rather than what go.mod
happens to require.

HEADER

missing=()
while read -r module; do
  dir="$(go list -m -f '{{.Dir}}' "$module")"
  version="$(go list -m -f '{{.Version}}' "$module")"

  # LICENSE.docs (opencontainers/go-digest) covers that module's documentation
  # under different terms from its code. It costs three lines to carry and
  # guessing which files are "the real one" is how a bundle goes subtly wrong.
  mapfile -t files < <(cd "$dir" && ls -1 | grep -iE '^(LICEN[CS]E|COPYING|NOTICE)' | sort)

  if [ "${#files[@]}" -eq 0 ]; then
    missing+=("$module")
    continue
  fi

  for file in "${files[@]}"; do
    {
      printf '%s\n' "--------------------------------------------------------------------------------"
      printf '%s %s — %s\n' "$module" "$version" "$file"
      printf '%s\n\n' "--------------------------------------------------------------------------------"
      cat "$dir/$file"
      printf '\n'
    } >>"$tmp"
  done
done <<<"$modules"

if [ "${#missing[@]}" -ne 0 ]; then
  printf 'no licence file found for these modules:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  printf 'add them by hand or drop the dependency — do not ship an incomplete bundle\n' >&2
  exit 1
fi

# mktemp creates 0600; this is a file people read.
chmod 644 "$tmp"
mv "$tmp" "$out"
trap - EXIT

printf 'wrote %s (%s modules)\n' "$out" "$(printf '%s\n' "$modules" | wc -l)"
