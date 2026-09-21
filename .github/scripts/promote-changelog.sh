#!/usr/bin/env bash
# Promotes CHANGELOG.md's "## [Unreleased]" section to a released version.
#
# Usage: promote-changelog.sh <version> <date>
#   version - released version without a leading "v" (e.g. "0.8.1")
#   date    - release date as YYYY-MM-DD
#
# Releases are cut automatically from Conventional Commits, but the changelog is
# written by hand and the prose is the point — it says why a change was made,
# which no commit subject carries. So this promotes the section that is already
# written rather than generating one: the entries do not move, only the heading
# above them and the link definitions below.
#
# That is exactly the mechanical half that kept being left undone. Four releases
# once shipped with their entries still under [Unreleased]; changelog-guard.sh
# catches that now, but catching it means every release blocks the next pull
# request until a human does this by hand.
#
# Both halves matter, because the guard checks both: the dated heading and the
# link definition. The previous version is read out of the [Unreleased] compare
# link rather than passed in — the file already knows what it was, and deriving
# it here means one less argument to get wrong.
#
# Idempotent: promoting a version the file already records is a no-op, so a
# re-run after a partial failure cannot produce two headings for one release.
#
# Run from a repo checkout; rewrites CHANGELOG.md in place.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <version> <date>" >&2
  exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

version="$1"
date="$2"
file="CHANGELOG.md"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "promote-changelog: '$version' is not a semver version" >&2
  exit 1
fi
if [[ ! "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "promote-changelog: '$date' is not YYYY-MM-DD" >&2
  exit 1
fi
if [ ! -f "$file" ]; then
  echo "promote-changelog: $file not found" >&2
  exit 1
fi

if grep -qF "## [$version] - " "$file"; then
  echo "promote-changelog: $file already records $version — nothing to do"
  exit 0
fi

if ! grep -qxF "## [Unreleased]" "$file"; then
  echo "promote-changelog: no '## [Unreleased]' heading in $file — refusing to guess" >&2
  exit 1
fi

# The compare link's base is the previous release, which is what the new
# version's own compare link has to start from.
previous="$(sed -n 's|^\[Unreleased\]: .*/compare/v\(.*\)\.\.\.HEAD$|\1|p' "$file")"
if [ -z "$previous" ]; then
  echo "promote-changelog: no '[Unreleased]: .../compare/vX.Y.Z...HEAD' link in $file" >&2
  exit 1
fi

repo_url="https://github.com/blox-eng/openblox"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

awk -v version="$version" -v date="$date" -v previous="$previous" -v url="$repo_url" '
  # The heading goes below [Unreleased], which stays and is left empty for the
  # next cycle.
  done_heading == 0 && $0 == "## [Unreleased]" {
    print
    print ""
    print "## [" version "] - " date
    done_heading = 1
    next
  }
  # The new link definition goes directly under the [Unreleased] one, keeping
  # the list in descending order like the rest of the file.
  done_link == 0 && $0 ~ /^\[Unreleased\]: .*\.\.\.HEAD$/ {
    print "[Unreleased]: " url "/compare/v" version "...HEAD"
    print "[" version "]: " url "/compare/v" previous "...v" version
    done_link = 1
    next
  }
  { print }
  END {
    if (done_heading == 0 || done_link == 0) {
      exit 1
    }
  }
' "$file" > "$tmp"

mv "$tmp" "$file"
trap - EXIT

echo "promote-changelog: recorded $version ($date), previous $previous"
