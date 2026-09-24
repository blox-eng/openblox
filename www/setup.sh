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

REPO="blox-eng/openblox"
BASE_URL=${OPENBLOX_BASE_URL:-https://openblox.sh}
ETC=${OPENBLOX_ETC:-/etc/openbloxd}
STATE=${OPENBLOX_STATE:-/var/lib/openblox}
SOCKET=/run/openbloxd/openbloxd.sock
BIN_DIR=/usr/local/bin
ID_BIN=${ID_BIN:-id}
SUDO_BIN=${SUDO_BIN:-sudo}
PHASE=preflight

info()  { printf '[openblox] %s\n' "$*"; }
warn()  { printf '[openblox] warning: %s\n' "$*" >&2; }
fatal() { printf '[openblox] %s failed: %s\n' "$PHASE" "$*" >&2; exit 1; }

# Everything this script creates is written here as it is created, and the
# uninstaller removes exactly this list. Something that existed before setup
# first ran is never on it, so uninstalling cannot take away what you had.
record() {
  mkdir -p "$STATE"
  if [ "$1" = pkg ] && grep -qxF "$2" "$STATE/preexisting" 2>/dev/null; then return 0; fi
  grep -qxF "$1 $2" "$STATE/installed" 2>/dev/null || printf '%s %s\n' "$1" "$2" >> "$STATE/installed"
}
recorded() { grep -qxF "$1 $2" "$STATE/installed" 2>/dev/null; }

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

render_config() {
  cat <<EOF
# Written by openblox setup.sh. Edit freely: setup never overwrites this file.
socket: $SOCKET
socket_group: openbloxd
reap_interval: 1m
EOF
  if [ -n "$LISTEN" ]; then
    # shellcheck disable=SC2086 # split the space-separated list
    cns=$(printf '%s\n' $CLIENTS | sed 's/.*/"&"/' | paste -sd, - | sed 's/,/, /g')
    cat <<EOF
listen:
  address: "$LISTEN"
  tls:
    cert_file: $ETC/tls/server.crt
    key_file: $ETC/tls/server.key
    # Signs callers and nothing else. Revoke a caller by removing its name
    # below and restarting: there is no CRL.
    client_ca_file: $ETC/tls/clients-ca.crt
    allowed_client_cns: [$cns]
EOF
  fi
  cat <<EOF
profiles:
  code-exec:
    image: $1
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: $MEMORY_MB
    disk_mb: $((MEMORY_MB / 2))
    max_processes: 256
    max_sandboxes: $MAX_SANDBOXES
    idle_timeout: 30m
    max_age: 4h
    default_timeout: 60s
    max_timeout: 10m
EOF
}

write_config() {
  PHASE=write_config
  mkdir -p "$ETC"
  if [ -f "$ETC/config.yaml" ]; then
    render_config "$1" > "$ETC/config.yaml.new"
    if ! cmp -s "$ETC/config.yaml" "$ETC/config.yaml.new"; then
      warn "$ETC/config.yaml exists and was left as it is. What setup would write now is in config.yaml.new:"
      diff -u "$ETC/config.yaml" "$ETC/config.yaml.new" >&2 || true
    else rm -f "$ETC/config.yaml.new"; fi
    return 0
  fi
  record dir "$ETC"
  render_config "$1" > "$ETC/config.yaml"
  chmod 0640 "$ETC/config.yaml"
  chgrp openbloxd "$ETC/config.yaml" 2>/dev/null || true
  record file "$ETC/config.yaml"
  info "wrote $ETC/config.yaml"
}

# Two CAs. The client CA signs callers and nothing else; the daemon treats it
# as its whole access list, so a server certificate from it would be a
# credential. The server CA signs only the daemon's own certificate.
new_ca() { # name
  [ -f "$ETC/tls/$1.crt" ] && return 0
  openssl ecparam -name prime256v1 -genkey -noout -out "$ETC/tls/$1.key" 2>/dev/null
  chmod 0600 "$ETC/tls/$1.key"
  openssl req -x509 -new -key "$ETC/tls/$1.key" -sha256 -days 3650 \
    -subj "/CN=openblox $1 $(hostname)" -out "$ETC/tls/$1.crt"
  record file "$ETC/tls/$1.key"; record file "$ETC/tls/$1.crt"
}

sign() { # ca, key_out, crt_out, cn, extfile
  openssl ecparam -name prime256v1 -genkey -noout -out "$2" 2>/dev/null
  chmod 0600 "$2"
  openssl req -new -key "$2" -subj "/CN=$4" -out "$2.csr"
  openssl x509 -req -in "$2.csr" -CA "$ETC/tls/$1.crt" -CAkey "$ETC/tls/$1.key" \
    -CAcreateserial -days 825 -sha256 -extfile "$5" -out "$3" 2>/dev/null
  rm -f "$2.csr"
}

issue_certs() {
  PHASE=issue_certs
  [ -n "$LISTEN" ] || return 0
  mkdir -p "$ETC/tls" "$ETC/clients"; chmod 0750 "$ETC/tls"; chgrp openbloxd "$ETC/tls" 2>/dev/null || true
  record dir "$ETC/tls"; record dir "$ETC/clients"
  new_ca server-ca; new_ca clients-ca
  host=${LISTEN%:*}
  if [ ! -f "$ETC/tls/server.crt" ]; then
    case $host in *[!0-9.]*) san="DNS:$host" ;; *) san="IP:$host" ;; esac
    printf 'subjectAltName=%s,DNS:%s\nextendedKeyUsage=serverAuth\n' "$san" "$(hostname)" > "$ETC/tls/server.ext"
    sign server-ca "$ETC/tls/server.key" "$ETC/tls/server.crt" "$(hostname)" "$ETC/tls/server.ext"
    rm -f "$ETC/tls/server.ext"
    chgrp openbloxd "$ETC/tls/server.key" 2>/dev/null && chmod 0640 "$ETC/tls/server.key"
    record file "$ETC/tls/server.key"; record file "$ETC/tls/server.crt"
  fi
  printf 'extendedKeyUsage=clientAuth\n' > "$ETC/tls/client.ext"
  for cn in $CLIENTS; do
    d="$ETC/clients/$cn"
    [ -f "$d/client.crt" ] && continue
    mkdir -p "$d"; chmod 0700 "$d"
    sign clients-ca "$d/client.key" "$d/client.crt" "$cn" "$ETC/tls/client.ext"
    cp "$ETC/tls/server-ca.crt" "$d/ca.crt"
    record dir "$d"
    info "issued client '$cn': copy $d/ to that caller (client.crt, client.key, ca.crt → brokerclient.TLSFiles)"
  done
  rm -f "$ETC/tls/client.ext"
}

render_uninstall() {
  printf '#!/bin/sh\n# Written by openblox setup.sh. Removes what setup installed, and nothing it did not.\nset -u\nSTATE=%s\n' "$STATE"
  cat <<'EOF'
[ "$(id -u)" = 0 ] || exec sudo sh "$0" "$@"
M="$STATE/installed"
[ -f "$M" ] || { echo "nothing recorded in $M; nothing to remove"; exit 0; }
has() { grep -qx "$1" "$M"; }
say() { printf '[openblox-uninstall] %s\n' "$*"; }

if command -v docker >/dev/null 2>&1; then
  ids=$(docker ps -aq --filter label=sh.openblox.managed)
  # shellcheck disable=SC2086 # one argument per container id
  [ -z "$ids" ] || { say "removing sandboxes"; docker rm -f $ids >/dev/null; }
fi
if has "unit openbloxd.service"; then
  systemctl disable --now openbloxd >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/openbloxd.service; systemctl daemon-reload
fi
if has "nft-table inet openblox"; then nft delete table inet openblox 2>/dev/null || true; rm -f /etc/nftables.d/openblox.nft; fi
grep '^image ' "$M" | while read -r _ img; do docker rmi "$img" >/dev/null 2>&1 || true; done
grep '^file ' "$M" | while read -r _ f; do rm -f "$f"; done
grep '^dir ' "$M" | sort -r | while read -r _ d; do rm -rf "$d"; done
has "user openbloxd" && { userdel openbloxd 2>/dev/null || true; groupdel openbloxd 2>/dev/null || true; }
# Unregister gVisor before removing it, or Docker is left pointing at a
# runtime binary that no longer exists.
if has "pkg runsc" && command -v runsc >/dev/null 2>&1; then
  runsc uninstall >/dev/null 2>&1 || true
  systemctl restart docker 2>/dev/null || true
fi
pkgs=$(grep '^pkg ' "$M" | cut -d' ' -f2 | tr '\n' ' ')
if [ -n "$pkgs" ]; then
  say "removing packages setup installed: $pkgs"
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $pkgs >/dev/null
fi
grep '^apt-source ' "$M" | while read -r _ f; do rm -f "$f"; done
if grep -qx "pkg docker-ce" "$M"; then
  say "Docker was removed; its data in /var/lib/docker was kept. Delete it yourself if you no longer need it."
fi
rm -f "$M" "$STATE/preexisting"; rmdir "$STATE" 2>/dev/null || true
say "done"
rm -f "$0"
EOF
}

create_uninstall() {
  PHASE=create_uninstall
  render_uninstall > "$BIN_DIR/openblox-uninstall.sh"
  chmod 0755 "$BIN_DIR/openblox-uninstall.sh"
  info "uninstall with: openblox-uninstall.sh"
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

setup_env() {
  PHASE=setup_env
  mkdir -p "$STATE"
  [ -f "$STATE/preexisting" ] || for p in docker-ce runsc nftables unattended-upgrades; do
    pkg_present "$p" && echo "$p"; done > "$STATE/preexisting"
  export DEBIAN_FRONTEND=noninteractive
}

retry() { n=1; until "$@"; do [ $n -ge 3 ] && return 1; sleep $((n * 5)); n=$((n + 1)); done; }
apt_install() { DEBIAN_FRONTEND=noninteractive retry apt-get install -y -qq "$@" >/dev/null; }
pkg_present() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

install_docker() {
  PHASE=install_docker
  if command -v docker >/dev/null 2>&1; then info "docker present ($(docker --version)); leaving it as it is"; return 0; fi
  distro=${OS%%[0-9]*}   # debian | ubuntu
  install -m 0755 -d /etc/apt/keyrings
  retry curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck source=/dev/null
  codename=$(. /etc/os-release; echo "$VERSION_CODENAME")
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $codename stable" > /etc/apt/sources.list.d/docker.list
  record file /etc/apt/keyrings/docker.asc; record apt-source /etc/apt/sources.list.d/docker.list
  retry apt-get update -qq
  apt_install docker-ce docker-ce-cli containerd.io
  for p in docker-ce docker-ce-cli containerd.io; do record pkg "$p"; done
  systemctl enable --now docker >/dev/null
  info "installed Docker Engine"
}

install_gvisor() {
  PHASE=install_gvisor
  if ! pkg_present runsc && ! command -v runsc >/dev/null 2>&1; then
    # Kept armored, like Docker's: Debian 13's apt verifies with sqv and ships no gpg to dearmor with.
    install -m 0755 -d /etc/apt/keyrings
    retry curl -fsSL https://gvisor.dev/archive.key -o /etc/apt/keyrings/gvisor.asc
    chmod a+r /etc/apt/keyrings/gvisor.asc
    echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/gvisor.asc] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
    record file /etc/apt/keyrings/gvisor.asc; record apt-source /etc/apt/sources.list.d/gvisor.list
    retry apt-get update -qq
    apt_install runsc; record pkg runsc
    info "installed gVisor $(runsc --version | head -n1)"
  fi
  # Registered explicitly: the package's postinst does not on every host.
  if ! docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' | tr ' ' '\n' | grep -qx runsc; then
    runsc install >/dev/null && systemctl restart docker
    info "registered runsc with Docker"
  fi
}

resolve_version() {
  [ -n "$VERSION" ] && return 0
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || fatal "could not resolve the latest release; set OPENBLOX_VERSION=vX.Y.Z"
}

install_openbloxd() {
  PHASE=install_openbloxd
  resolve_version
  if ! id openbloxd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin openbloxd; record user openbloxd
  fi
  have=$("$BIN_DIR/openbloxd" -version 2>/dev/null || true)
  case $have in *"$VERSION"*) info "openbloxd $VERSION already installed" ;;
    *) curl -fsSL "$BASE_URL/install.sh" | OPENBLOX_VERSION=$VERSION OPENBLOX_BIN_DIR=$BIN_DIR sh
       record file "$BIN_DIR/openbloxd" ;;
  esac
}

pin_image() {
  PHASE=pin_image
  tag="ghcr.io/blox-eng/openblox-sandbox:${VERSION#v}"
  retry docker pull -q "$tag" >/dev/null || fatal "could not pull $tag"
  digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$tag" | sed 's/.*@//')
  IMAGE="$tag@$digest"
  if command -v gh >/dev/null 2>&1; then
    gh attestation verify "oci://$IMAGE" --repo "$REPO" >/dev/null 2>&1 ||
      fatal "the build attestation for $IMAGE did not verify against $REPO; not using it"
    info "image provenance ok"
  fi
  record image "$IMAGE"
  info "sandbox image $IMAGE"
}

render_nft() {
  port=${LISTEN##*:}
  # Create-then-delete makes the load idempotent on every nft version: the
  # table always exists to delete, and the definition below replaces it.
  printf 'add table inet openblox\ndelete table inet openblox\n'
  cat <<EOF
table inet openblox {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    meta l4proto { icmp, ipv6-icmp } accept
    tcp dport 22 accept
EOF
  if [ -n "$LISTEN" ]; then
    if [ -n "$ALLOW_FROM" ]; then echo "    ip saddr $ALLOW_FROM tcp dport $port accept"
    else echo "    tcp dport $port accept"; fi
  fi
  printf '  }\n}\n'
}

harden() {
  PHASE=harden
  pkg_present nftables || { apt_install nftables; record pkg nftables; }
  pkg_present unattended-upgrades || { apt_install unattended-upgrades; record pkg unattended-upgrades; }
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
  mkdir -p /etc/nftables.d
  render_nft > /etc/nftables.d/openblox.nft
  # One atomic load: the SSH accept and the drop policy arrive together, so
  # there is no instant where the drop applies without the accept.
  nft -f /etc/nftables.d/openblox.nft || fatal "firewall rules did not load; nothing was changed"
  grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
  systemctl enable nftables >/dev/null 2>&1 || true
  record file /etc/nftables.d/openblox.nft; record nft-table "inet openblox"
  info "firewall: inbound SSH${LISTEN:+ and ${LISTEN##*:}${ALLOW_FROM:+ from $ALLOW_FROM}} only; automatic security updates on"
}

create_systemd_service() {
  PHASE=create_systemd_service
  retry curl -fsSL "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/openbloxd.service" -o /etc/systemd/system/openbloxd.service
  systemctl daemon-reload
  record unit openbloxd.service
}

service_enable_and_start() {
  PHASE=service_enable_and_start
  systemctl enable openbloxd >/dev/null 2>&1
  systemctl restart openbloxd
  i=0; until [ -S "$SOCKET" ]; do i=$((i + 1)); [ $i -gt 20 ] && fatal "openbloxd did not start; see: journalctl -u openbloxd"; sleep 0.5; done
}

api() { curl -fsS --unix-socket "$SOCKET" -H 'Content-Type: application/json' "$@"; }

exec_in() { # name, argv-json → stdout (decoded) ; sets EXIT
  out=$(api -X POST "http://openbloxd/sandboxes/$1/exec" -d "{\"argv\":$2,\"timeout\":\"20s\"}") ||
    fatal "exec in the smoke-test sandbox failed; see: journalctl -u openbloxd"
  EXIT=$(printf '%s' "$out" | sed -n 's/.*"exit_code":\([0-9]*\).*/\1/p')
  printf '%s' "$out" | sed -n 's/.*"stdout":"\([^"]*\)".*/\1/p' | base64 -d 2>/dev/null
}

smoke_test() {
  PHASE=smoke_test
  n="openblox-setup-smoke-$$"
  api -X POST http://openbloxd/sandboxes -d "{\"name\":\"$n\",\"profile\":\"code-exec\"}" >/dev/null ||
    fatal "could not create a sandbox; see: journalctl -u openbloxd"
  kernel=$(exec_in "$n" '["uname","-r"]')
  case $kernel in *gvisor*) ;; *) api -X DELETE "http://openbloxd/sandboxes/$n" >/dev/null; fatal "sandbox kernel is '$kernel', not gVisor" ;; esac
  exec_in "$n" '["python3","-c","import socket; socket.create_connection((\"1.1.1.1\",53),3)"]' >/dev/null
  [ "${EXIT:-0}" != 0 ] || { api -X DELETE "http://openbloxd/sandboxes/$n" >/dev/null; fatal "the sandbox reached the network; egress must be none"; }
  api -X DELETE "http://openbloxd/sandboxes/$n" >/dev/null
  info "smoke test ok: a sandbox ran under gVisor with no network, and was removed"
}

summary() {
  info "done. openbloxd $VERSION, image $IMAGE, max_sandboxes=$MAX_SANDBOXES"
  [ -z "$LISTEN" ] || info "listening on $LISTEN (mTLS). Client bundles: $ETC/clients/<name>/"
  info "config: $ETC/config.yaml · logs: journalctl -u openbloxd · uninstall: openblox-uninstall.sh"
}

main() {
  parse_args "$@"
  need_root
  verify_system
  setup_env
  install_docker
  install_gvisor
  install_openbloxd
  pin_image
  write_config "$IMAGE"
  issue_certs
  harden
  create_uninstall
  create_systemd_service
  service_enable_and_start
  smoke_test
  summary
}

[ "${OPENBLOX_SETUP_LIB:-}" = 1 ] || main "$@"
