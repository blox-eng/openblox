#!/bin/sh
# Unit tests for www/setup.sh. Sources it as a library; needs no root.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
OPENBLOX_SETUP_LIB=1
# shellcheck source=www/setup.sh
. "$here/www/setup.sh"

fails=0
check() { # name, got, want
  if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"
  else printf 'FAIL %s\n  got:  %s\n  want: %s\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi
}
# Runs "$@" in a subshell so a fatal() cannot end the suite; echoes its exit code.
status() { ( "$@" ) >/dev/null 2>&1 && echo 0 || echo $?; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# --- detect_os ---
printf 'ID=debian\nVERSION_ID="13"\n' > "$tmp/debian13"
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$tmp/ubuntu2404"
printf 'ID=ubuntu\nVERSION_ID="22.04"\n' > "$tmp/ubuntu2204"
printf 'ID=fedora\nVERSION_ID="41"\n' > "$tmp/fedora"
check "debian 13 accepted"   "$(detect_os "$tmp/debian13")"   debian13
check "ubuntu 24.04 accepted" "$(detect_os "$tmp/ubuntu2404")" ubuntu2404
check "ubuntu 22.04 refused"  "$(status detect_os "$tmp/ubuntu2204")" 1
check "fedora refused"        "$(status detect_os "$tmp/fedora")" 1

# --- compute_max_sandboxes: floor((mem-1024)/(1.4*memory_mb)), min 1 ---
check "16 GiB at 2048"  "$(compute_max_sandboxes 16000 2048)" 5
check "32 GiB at 2048"  "$(compute_max_sandboxes 32000 2048)" 10
check "8 GiB at 1024"   "$(compute_max_sandboxes 8000 1024)" 4
check "2 GiB never 0"   "$(compute_max_sandboxes 2000 2048)" 1

# --- parse_args: flags win over env, --client repeats ---
OPENBLOX_CLIENTS="from-env"; OPENBLOX_MEMORY_MB=""
parse_args --listen 10.0.0.5:9443 --client a --client b --memory-mb 1024
check "listen flag"   "$LISTEN" 10.0.0.5:9443
check "clients flag"  "$CLIENTS" "a b"
check "memory flag"   "$MEMORY_MB" 1024
OPENBLOX_CLIENTS=""; OPENBLOX_LISTEN="1.2.3.4:9443"; parse_args
check "listen default client" "$CLIENTS" sandbox-caller
check "unknown flag refused" "$(status parse_args --nope)" 1

# --- need_root: re-exec via sudo when not root, refuse without sudo ---
# sudo drops the environment, so the parsed values must travel explicitly.
fake_id() { echo 1000; }
fake_sudo() { echo "sudo:$*"; }
ID_BIN=fake_id SUDO_BIN=fake_sudo SETUP_SELF="$here/www/setup.sh"
parse_args --listen 10.0.0.5:9443 --client a --client b
got=$(need_root 2>/dev/null)
check "re-exec runs this file through sudo" "$(printf '%s' "$got" | grep -c "sh $here/www/setup.sh")" 1
check "listen survives sudo"  "$(printf '%s' "$got" | grep -c 'OPENBLOX_LISTEN=10.0.0.5:9443')" 1
check "clients survive sudo"  "$(printf '%s' "$got" | grep -c 'OPENBLOX_CLIENTS=a b')" 1
check "no sudo refused" "$(ID_BIN=fake_id SUDO_BIN=/nonexistent status need_root)" 1
ID_BIN=id

# --- manifest ---
STATE="$tmp/state"
record file /etc/openbloxd/config.yaml
record file /etc/openbloxd/config.yaml
record pkg runsc
check "record dedupes" "$(grep -c 'file /etc/openbloxd/config.yaml' "$STATE/installed")" 1
check "recorded yes" "$(status recorded pkg runsc)" 0
check "recorded no"  "$(status recorded pkg docker-ce)" 1

# --- config ---
ETC="$tmp/etc"; LISTEN=""; CLIENTS=""; MEMORY_MB=2048; MAX_SANDBOXES=5
img="ghcr.io/blox-eng/openblox-sandbox:0.9.0@sha256:abc"
render_config "$img" > "$tmp/c1"
check "image pinned"  "$(grep -c "image: $img" "$tmp/c1")" 1
check "no listen block without --listen" "$(grep -c '^listen:' "$tmp/c1")" 0
check "cap written"   "$(grep -c 'max_sandboxes: 5' "$tmp/c1")" 1
check "egress none"   "$(grep -c 'egress: none' "$tmp/c1")" 1
LISTEN="10.0.0.5:9443"; CLIENTS="mcpblox-staging mcpblox-prod"
render_config "$img" > "$tmp/c2"
check "listen address" "$(grep -c 'address: "10.0.0.5:9443"' "$tmp/c2")" 1
check "cns allowlisted" "$(grep -c 'allowed_client_cns: \["mcpblox-staging", "mcpblox-prod"\]' "$tmp/c2")" 1
write_config "$img" >/dev/null 2>&1
echo "# operator edit" >> "$ETC/config.yaml"
write_config "$img" >/dev/null 2>&1
check "existing config untouched" "$(tail -n1 "$ETC/config.yaml")" "# operator edit"

# --- certificates ---
ETC="$tmp/pki"; LISTEN="127.0.0.1:9443"; CLIENTS="staging prod"
issue_certs >/dev/null
check "server cert chains to server CA" "$(status openssl verify -CAfile "$ETC/tls/server-ca.crt" "$ETC/tls/server.crt")" 0
check "client chains to CLIENT CA"      "$(status openssl verify -CAfile "$ETC/tls/clients-ca.crt" "$ETC/clients/staging/client.crt")" 0
check "client does NOT chain to server CA" "$(openssl verify -CAfile "$ETC/tls/server-ca.crt" "$ETC/clients/staging/client.crt" >/dev/null 2>&1 && echo accepted || echo refused)" refused
check "client CN" "$(openssl x509 -in "$ETC/clients/prod/client.crt" -noout -subject | sed 's/.*CN *= *//')" prod
check "server SAN has listen IP" "$(openssl x509 -in "$ETC/tls/server.crt" -noout -ext subjectAltName | grep -c 'IP Address:127.0.0.1')" 1
check "bundle carries server CA" "$(cmp -s "$ETC/clients/prod/ca.crt" "$ETC/tls/server-ca.crt" && echo same)" same
check "CA key private" "$(stat -c %a "$ETC/tls/clients-ca.key")" 600
before=$(openssl x509 -in "$ETC/tls/clients-ca.crt" -noout -fingerprint)
CLIENTS="staging prod dev"; issue_certs >/dev/null
check "CA reused on re-run" "$(openssl x509 -in "$ETC/tls/clients-ca.crt" -noout -fingerprint)" "$before"
check "new client issued"   "$(status test -f "$ETC/clients/dev/client.crt")" 0

# --- uninstaller ---
render_uninstall > "$tmp/un.sh"
check "uninstaller parses" "$(status sh -n "$tmp/un.sh")" 0
if command -v shellcheck >/dev/null; then check "uninstaller lint" "$(status shellcheck -s sh "$tmp/un.sh")" 0; fi
check "keeps /var/lib/docker" "$(grep -c 'rm -rf /var/lib/docker' "$tmp/un.sh")" 0
# Docker purged only when setup installed it: the script decides from the manifest at run time.
check "docker purge is manifest-gated" "$(grep -c 'grep -qx "pkg docker-ce"' "$tmp/un.sh")" 1
check "runsc unregistered before purge" "$(grep -c 'runsc uninstall' "$tmp/un.sh")" 1

[ "$fails" -eq 0 ] || { printf '%d failed\n' "$fails"; exit 1; }
echo "all passed"
