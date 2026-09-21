#!/bin/sh
# openbloxd installer — https://openblox.sh
#
# Downloads the openbloxd binary for this machine from the GitHub release,
# verifies it against the checksum published beside it, and installs it.
#
# You are reading this because the landing page asked you to before piping it
# into a shell, which is the right instinct. What it does, in order:
#
#   1. refuses anything but Linux on amd64 or arm64, because that is all
#      openblox runs on — it needs Docker with gVisor registered as runsc
#   2. resolves the release (latest, or $OPENBLOX_VERSION)
#   3. downloads openbloxd-linux-<arch> and its .sha256
#   4. VERIFIES THE CHECKSUM, and installs nothing if it does not match
#   5. verifies the Sigstore build provenance too, when `gh` is available —
#      the checksum comes from the same release as the binary, so on its own
#      it proves transfer integrity, not that the release is the one CI built
#   6. installs to /usr/local/bin, or ~/.local/bin when that is not writable
#
# It writes one file and touches nothing else. No daemon is started, no
# service is enabled, no configuration is written.
#
# Environment:
#   OPENBLOX_VERSION   tag to install (default: the latest release)
#   OPENBLOX_BIN_DIR   directory to install into (default: as described above)
#
# The whole script is one function, invoked on the last line. A truncated
# download therefore does nothing at all, rather than executing half of it.

set -eu

REPO="blox-eng/openblox"

main() {
  say() { printf '%s\n' "$*"; }
  die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

  need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }
  need uname
  need curl
  need mktemp

  # 1. This is not a portability oversight. openblox runs sandboxes under
  #    gVisor, which is Linux-only, so there is no macOS or Windows build to
  #    offer and pretending otherwise would waste your time later, not now.
  os=$(uname -s)
  [ "$os" = "Linux" ] || die "openblox requires Linux (this is $os). It runs sandboxes under gVisor, which is Linux-only."

  case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m); openbloxd is published for amd64 and arm64" ;;
  esac

  if command -v sha256sum >/dev/null 2>&1; then
    checksum() { sha256sum "$1" | cut -d' ' -f1; }
  elif command -v shasum >/dev/null 2>&1; then
    checksum() { shasum -a 256 "$1" | cut -d' ' -f1; }
  else
    die "no sha256sum or shasum; refusing to install a binary it cannot verify"
  fi

  # 2. Resolve the version.
  version=${OPENBLOX_VERSION:-}
  if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
      sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
    [ -n "$version" ] || die "could not resolve the latest release; set OPENBLOX_VERSION=vX.Y.Z"
  fi

  asset="openbloxd-linux-$arch"
  base="https://github.com/$REPO/releases/download/$version"

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT INT TERM

  say "openbloxd $version ($arch)"

  # 3. Download the binary and the checksum published beside it.
  curl -fsSL -o "$work/$asset" "$base/$asset" ||
    die "could not download $asset from $version — check that the release exists"
  curl -fsSL -o "$work/$asset.sha256" "$base/$asset.sha256" ||
    die "could not download the checksum for $asset; refusing to install unverified"

  # 4. Verify, and stop here if it does not match.
  want=$(cut -d' ' -f1 < "$work/$asset.sha256")
  got=$(checksum "$work/$asset")
  [ -n "$want" ] || die "the published checksum is empty; refusing to install"
  if [ "$want" != "$got" ]; then
    die "checksum mismatch for $asset
  published $want
  download  $got
Nothing was installed. Do not use the downloaded file."
  fi
  say "  checksum  ok"

  # 5. The checksum ships in the same release as the binary, so it establishes
  #    that the bytes arrived intact — not that the release is the one CI built
  #    from a verified commit. The provenance attestation does establish that,
  #    and `gh` is the only thing that can check it, so this is opportunistic
  #    rather than required: strictly better when present, never a hard
  #    dependency for installing a binary whose checksum already matched.
  if command -v gh >/dev/null 2>&1; then
    if gh attestation verify "$work/$asset" --repo "$REPO" >/dev/null 2>&1; then
      say "  provenance ok (built by CI in $REPO)"
    else
      die "provenance verification FAILED for $asset.
The checksum matched, but the build attestation did not verify against $REPO.
Nothing was installed. Please report this: https://github.com/$REPO/security"
    fi
  else
    say "  provenance not checked (install the 'gh' CLI to verify the build attestation)"
  fi

  # 6. Install. /usr/local/bin when we can write it, the user's own bin if not.
  if [ -n "${OPENBLOX_BIN_DIR:-}" ]; then
    bindir=$OPENBLOX_BIN_DIR
  elif [ -w /usr/local/bin ] 2>/dev/null; then
    bindir=/usr/local/bin
  else
    bindir="$HOME/.local/bin"
  fi
  mkdir -p "$bindir" || die "could not create $bindir"

  install -m 0755 "$work/$asset" "$bindir/openbloxd" 2>/dev/null ||
    { cp "$work/$asset" "$bindir/openbloxd" && chmod 0755 "$bindir/openbloxd"; } ||
    die "could not write to $bindir — set OPENBLOX_BIN_DIR, or re-run with sudo"

  say "  installed $bindir/openbloxd"

  case ":$PATH:" in
    *":$bindir:"*) ;;
    *) say ""; say "  $bindir is not on your PATH. Add it:"; say "    export PATH=\"$bindir:\$PATH\"" ;;
  esac

  say ""
  say "openbloxd is installed but not running, and it is not configured yet."
  say "It needs Docker with gVisor registered as the runsc runtime, and a"
  say "config file defining the profiles callers may name."
  say ""
  say "  Next: https://docs.openblox.sh/production/"
}

main "$@"
