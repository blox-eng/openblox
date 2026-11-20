#!/usr/bin/env bash
# Tests host-weakening-guard.sh against fixtures: a weakening line fails with
# its file and line, the same text inside a Warning passes, the real docs pass.
set -euo pipefail

cd "$(dirname "$0")/../.."
guard=.github/scripts/host-weakening-guard.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

expect_fail() { # name file pattern
  if out=$("$guard" "$2" 2>&1); then
    echo "FAIL: $1: the guard passed"; fail=1
  elif ! grep -qF "$3" <<<"$out"; then
    echo "FAIL: $1: output does not name $3:"; echo "$out"; fail=1
  else
    echo "ok: $1"
  fi
}
expect_pass() { # name file...
  name=$1; shift
  if out=$("$guard" "$@" 2>&1); then echo "ok: $name"; else echo "FAIL: $name:"; echo "$out"; fail=1; fi
}

printf '# Setup\n\nRun this first:\n\n    sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0\n' > "$tmp/sysctl.md"
expect_fail "sysctl in a setup step" "$tmp/sysctl.md" "sysctl.md:5"

printf 'Allow rootlesskit:\n\n    echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns\n' > "$tmp/proc.md"
expect_fail "/proc form in a setup step" "$tmp/proc.md" "proc.md:3"

printf 'Register runsc:\n\n    "runtimeArgs": ["--TESTONLY-unsafe-nonroot"]\n' > "$tmp/testonly.md"
expect_fail "TESTONLY flag in a setup step" "$tmp/testonly.md" "testonly.md:3"

printf '> **Warning:** never set kernel.apparmor_restrict_unprivileged_userns=0 or pass --TESTONLY-unsafe-nonroot.\n' > "$tmp/warning.md"
expect_pass "the same text inside a Warning" "$tmp/warning.md"

expect_pass "the real docs"

exit "$fail"
