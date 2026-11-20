#!/usr/bin/env bash
# Fails when the docs tell an operator to weaken their host.
#
# Rootless Docker on Ubuntu 24.04+ meets the AppArmor user-namespace restriction,
# and the common shortcut is to turn it off for every program on the host, by
# sysctl or through /proc, so any mention of the setting counts. gVisor
# also has --TESTONLY-* flags that make runsc start where it otherwise would not.
# Both trade the host's safety for a working sandbox, which inverts the point of
# openblox. Either may appear only inside a warning, on a line that starts with
# "> **Warning".
#
# Usage: host-weakening-guard.sh [file...]   (default: docs/, SECURITY.md, THREAT_MODEL.md)
set -euo pipefail

cd "$(dirname "$0")/../.."
if [ "$#" -eq 0 ]; then
  set -- docs SECURITY.md THREAT_MODEL.md
fi

hits=$(grep -rnHE --include='*.md' 'apparmor_restrict_unprivileged_userns|TESTONLY' "$@" \
  | grep -vE '^[^:]+:[0-9]+:> \*\*Warning' || true)

if [ -n "$hits" ]; then
  echo "FAIL: these lines tell an operator to weaken the host. Move each into a '> **Warning' line, or remove it:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "OK: no host-weakening step in $*"
