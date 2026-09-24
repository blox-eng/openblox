#!/bin/sh
# openblox host setup — https://openblox.sh/setup.sh
#
# Turns a freshly installed Debian 13 or Ubuntu 24.04 machine into a dedicated
# openbloxd host: Docker, gVisor, the daemon, its service, an optional mTLS
# listener, a firewall and automatic security updates. Then it proves the host
# works by running a sandbox.
#
# Modelled on k3s's installer: named phases in a fixed order, each checking
# before it changes anything, so running it again is safe — it repairs drift
# and upgrades, and never duplicates. It also writes
# /usr/local/bin/openblox-uninstall.sh, which removes exactly what this added.
#
# Environment (each also a flag when run from a file):
#   OPENBLOX_VERSION        --version        release to install (default: latest)
#   OPENBLOX_LISTEN         --listen         host:port for the mTLS listener (default: none)
#   OPENBLOX_CLIENTS        --client         client certificate names (default: sandbox-caller)
#   OPENBLOX_ALLOW_FROM     --allow-from     CIDR allowed to reach the listener (default: any)
#   OPENBLOX_MEMORY_MB      --memory-mb      per-sandbox memory (default: 2048)
#   OPENBLOX_MAX_SANDBOXES  --max-sandboxes  concurrent cap (default: sized from RAM)
#
# The whole script is one function, invoked on the last line. A truncated
# download therefore does nothing at all, rather than executing half of it.

set -eu

BASE_URL=${OPENBLOX_BASE_URL:-https://openblox.sh}
ID_BIN=${ID_BIN:-id}
SUDO_BIN=${SUDO_BIN:-sudo}
PHASE=preflight

info()  { printf '[openblox] %s\n' "$*"; }
warn()  { printf '[openblox] warning: %s\n' "$*" >&2; }
fatal() { printf '[openblox] %s failed: %s\n' "$PHASE" "$*" >&2; exit 1; }

parse_args() {
  VERSION=${OPENBLOX_VERSION:-}
  LISTEN=${OPENBLOX_LISTEN:-}
  CLIENTS=${OPENBLOX_CLIENTS:-}
  ALLOW_FROM=${OPENBLOX_ALLOW_FROM:-}
  MEMORY_MB=${OPENBLOX_MEMORY_MB:-2048}
  MAX_SANDBOXES=${OPENBLOX_MAX_SANDBOXES:-}
  flag_clients=""
  while [ $# -gt 0 ]; do
    case $1 in
      --version) VERSION=$2; shift 2 ;;
      --listen) LISTEN=$2; shift 2 ;;
      --client) flag_clients="${flag_clients:+$flag_clients }$2"; shift 2 ;;
      --allow-from) ALLOW_FROM=$2; shift 2 ;;
      --memory-mb) MEMORY_MB=$2; shift 2 ;;
      --max-sandboxes) MAX_SANDBOXES=$2; shift 2 ;;
      *) fatal "unknown option $1 (see the header of this script)" ;;
    esac
  done
  [ -n "$flag_clients" ] && CLIENTS=$flag_clients
  if [ -n "$LISTEN" ] && [ -z "$CLIENTS" ]; then CLIENTS=sandbox-caller; fi
  case $MEMORY_MB in ''|*[!0-9]*) fatal "memory_mb must be a whole number of MiB, got '$MEMORY_MB'" ;; esac
}

detect_os() {
  # shellcheck disable=SC1090
  id=$(. "$1"; echo "${ID:-}")
  # shellcheck disable=SC1090
  ver=$(. "$1"; echo "${VERSION_ID:-}")
  case "$id:$ver" in
    debian:13) echo debian13 ;;
    ubuntu:24.04) echo ubuntu2404 ;;
    *) fatal "this is $id $ver. setup.sh supports Debian 13 and Ubuntu 24.04. On anything else, install Docker and gVisor yourself and use install.sh: https://docs.openblox.sh/getting-started/" ;;
  esac
}

detect_arch() {
  case $(uname -m) in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) fatal "unsupported architecture $(uname -m); openblox runs on amd64 and arm64" ;;
  esac
}

# floor((total - 1024 reserve) / (1.4 * per-sandbox)), at least 1. The 1.4 is
# the observed overshoot of memory_mb before the kill lands (issue #30).
compute_max_sandboxes() {
  n=$(( ($1 - 1024) * 10 / ($2 * 14) ))
  [ "$n" -ge 1 ] || n=1
  echo "$n"
}

# sudo drops the caller's environment, so everything already parsed is handed
# over explicitly — otherwise OPENBLOX_LISTEN=… curl … | sh would silently
# lose its settings on the way to root.
need_root() {
  [ "$($ID_BIN -u)" = 0 ] && return 0
  command -v "$SUDO_BIN" >/dev/null 2>&1 ||
    fatal "run as root, or install sudo: this configures system services, packages and the firewall"
  info "re-running as root through sudo"
  set -- env "OPENBLOX_VERSION=$VERSION" "OPENBLOX_LISTEN=$LISTEN" "OPENBLOX_CLIENTS=$CLIENTS" \
    "OPENBLOX_ALLOW_FROM=$ALLOW_FROM" "OPENBLOX_MEMORY_MB=$MEMORY_MB" \
    "OPENBLOX_MAX_SANDBOXES=$MAX_SANDBOXES" "OPENBLOX_BASE_URL=$BASE_URL"
  self=${SETUP_SELF:-$0}
  if [ -f "$self" ] && [ "${self##*/}" = setup.sh ]; then
    "$SUDO_BIN" "$@" sh "$self"
  else
    # Piped from curl there is no file to re-run: fetch the same script again.
    curl -fsSL "$BASE_URL/setup.sh" | "$SUDO_BIN" "$@" sh -s
  fi
  exit $?
}

verify_system() {
  PHASE=verify_system
  [ "$(uname -s)" = Linux ] || fatal "openblox needs Linux; gVisor is Linux-only"
  OS=$(detect_os /etc/os-release)
  ARCH=$(detect_arch)
  [ -f /sys/fs/cgroup/cgroup.controllers ] || fatal "cgroup v2 is not mounted; both supported systems use it by default, so this host was changed"
  for c in curl openssl; do command -v "$c" >/dev/null 2>&1 || apt-get install -y -qq "$c" >/dev/null; done
  total_mb=$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo)
  fits=$(compute_max_sandboxes "$total_mb" "$MEMORY_MB")
  if [ -z "$MAX_SANDBOXES" ]; then MAX_SANDBOXES=$fits
  elif [ "$MAX_SANDBOXES" -gt "$fits" ]; then
    warn "max_sandboxes=$MAX_SANDBOXES exceeds what ${total_mb} MiB holds at ${MEMORY_MB} MiB each ($fits); the host can run out of memory"
  fi
  [ $(( fits * MEMORY_MB * 14 / 10 + 1024 )) -le "$total_mb" ] ||
    warn "${total_mb} MiB is too little for even one ${MEMORY_MB} MiB sandbox at the observed ~1.4x; lower --memory-mb"
  info "$OS $ARCH, ${total_mb} MiB RAM: max_sandboxes=$MAX_SANDBOXES at ${MEMORY_MB} MiB each (≈1.4x resident, 1 GiB kept for the host)"
}

main() {
  parse_args "$@"
  need_root
  verify_system
}

[ "${OPENBLOX_SETUP_LIB:-}" = 1 ] || main "$@"
