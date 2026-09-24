#!/bin/sh
# Unit tests for www/setup.sh. Sources it as a library; needs no root.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
OPENBLOX_SETUP_LIB=1
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# shellcheck source=www/setup.sh
. "$here/www/setup.sh"
STATE="$tmp/state0"   # never read a real host's saved settings
SSHD_BIN=/nonexistent # nor its sshd

fails=0
check() { # name, got, want
  if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"
  else printf 'FAIL %s\n  got:  %s\n  want: %s\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi
}
# Runs "$@" in a subshell so a fatal() cannot end the suite; echoes its exit code.
status() { ( "$@" ) >/dev/null 2>&1 && echo 0 || echo $?; }


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

# --- firewall ---
LISTEN="10.0.0.5:9443"; ALLOW_FROM="10.0.0.0/24"
render_nft > "$tmp/fw"
check "own table" "$(grep -c '^table inet openblox {' "$tmp/fw")" 1
check "ssh allowed" "$(grep -c 'tcp dport { 22 } accept' "$tmp/fw")" 1
check "listener limited to source" "$(grep -c 'ip saddr { 10.0.0.0/24 } tcp dport 9443 accept' "$tmp/fw")" 1
check "delete before define (re-run safe)" "$(head -n2 "$tmp/fw" | grep -c 'delete table inet openblox')" 1
LISTEN=""; render_nft > "$tmp/fw2"
check "no listener port without --listen" "$(grep -c 'dport 9443' "$tmp/fw2")" 0

# --- pre-existing packages are never recorded, so never removed ---
printf 'docker-ce\n' > "$STATE/preexisting"; record pkg docker-ce
check "preexisting docker never recorded" "$(status recorded pkg docker-ce)" 1

# --- settings persist, so a re-run without them keeps the listener (review C1) ---
STATE="$tmp/st-settings"; mkdir -p "$STATE"
OPENBLOX_LISTEN=""; OPENBLOX_CLIENTS=""; OPENBLOX_ALLOW_FROM=""; OPENBLOX_MEMORY_MB=""; OPENBLOX_MAX_SANDBOXES=""
parse_args --listen 10.0.0.5:9443 --client staging --client prod --allow-from 10.0.0.0/24 --memory-mb 1024
save_settings
parse_args
check "listen kept on a bare re-run"     "$LISTEN" 10.0.0.5:9443
check "allow-from kept on a bare re-run" "$ALLOW_FROM" 10.0.0.0/24
check "clients kept on a bare re-run"    "$CLIENTS" "staging prod"
check "memory kept on a bare re-run"     "$MEMORY_MB" 1024
check "computed cap not frozen"          "$MAX_SANDBOXES" ""
parse_args --client dev
check "a new client adds to the saved ones" "$CLIENTS" "staging prod dev"
check "settings file is root-only" "$(stat -c %a "$STATE/settings")" 600

# --- ssh ports come from sshd, so a non-22 port is not locked out (review C2) ---
fake_sshd() { printf 'port 2222\nport 22\naddressfamily any\n'; }
check "ssh ports detected" "$(SSHD_BIN=fake_sshd ssh_ports)" "22, 2222"
check "ssh falls back to 22" "$(SSHD_BIN=/nonexistent ssh_ports)" 22
LISTEN="10.0.0.5:9443"; ALLOW_FROM=""
check "detected ports in the ruleset" "$(SSHD_BIN=fake_sshd render_nft | grep -c 'tcp dport { 22, 2222 } accept')" 1

# --- settings are validated before they reach YAML, paths, openssl or nft (review I5) ---
STATE="$tmp/st-validate"
check "client with a slash refused"   "$(status parse_args --client a/b)" 1
check "client with .. refused"        "$(status parse_args --client ..)" 1
check "client with a quote refused"   "$(status parse_args --client 'a"b')" 1
check "ordinary client accepted"      "$(status parse_args --client app-staging.v2_x)" 0
check "max-sandboxes 0 refused"       "$(status parse_args --max-sandboxes 0)" 1
check "max-sandboxes abc refused"     "$(status parse_args --max-sandboxes abc)" 1
check "memory-mb 0 refused"           "$(status parse_args --memory-mb 0)" 1
check "listen without port refused"   "$(status parse_args --listen 10.0.0.5)" 1
check "listen port range"             "$(status parse_args --listen 10.0.0.5:99999)" 1
check "listen ipv6 literal refused"   "$(status parse_args --listen '[::1]:9443')" 1
check "listen by name accepted"       "$(status parse_args --listen box.lan:9443)" 0
check "allow-from junk refused"       "$(status parse_args --listen box.lan:9443 --allow-from '1.2.3.4;drop')" 1
parse_args --listen box.lan:9443 --allow-from '10.0.0.0/24,fd00::/64 192.168.1.0/24'
render_nft > "$tmp/fw3"
check "v4 sources as one set" "$(grep -c 'ip saddr { 10.0.0.0/24, 192.168.1.0/24 } tcp dport 9443 accept' "$tmp/fw3")" 1
check "v6 sources as ip6"     "$(grep -c 'ip6 saddr { fd00::/64 } tcp dport 9443 accept' "$tmp/fw3")" 1

# --- need_root: a failed re-fetch is a failure, and a renamed file is re-run, not re-fetched (review I4) ---
# shellcheck disable=SC2329 # shadows curl inside need_root
curl() { return 22; }
check "failed re-fetch refused" "$(ID_BIN=fake_id SUDO_BIN=fake_sudo SETUP_SELF=sh status need_root)" 1
unset -f curl
cp "$here/www/setup.sh" "$tmp/openblox-setup.sh"
check "renamed file re-run as is" "$(ID_BIN=fake_id SUDO_BIN=fake_sudo SETUP_SELF="$tmp/openblox-setup.sh" need_root 2>/dev/null | grep -c "sh $tmp/openblox-setup.sh")" 1

# --- every failure names its phase, once (review I3) ---
check "silent failure named" "$( (PHASE=pin_image; trap on_exit EXIT; false) 2>&1 | grep -c '^\[openblox\] pin_image failed')" 1
check "fatal not reported twice" "$( (PHASE=harden; trap on_exit EXIT; fatal boom) 2>&1 | wc -l | tr -d ' ')" 1

# --- an issued client missing from the live allowlist is called out (review I2) ---
ETC="$tmp/pki2"; mkdir -p "$ETC"; LISTEN="127.0.0.1:9443"; CLIENTS="staging"
printf 'listen:\n  tls:\n    allowed_client_cns: ["staging"]\n' > "$ETC/config.yaml"
issue_certs >/dev/null 2>&1
CLIENTS="staging dev"
check "new client not yet allowed is named" "$(issue_certs 2>&1 >/dev/null | grep -c "'dev' is not in allowed_client_cns")" 1
check "allowed client not warned" "$(issue_certs 2>&1 >/dev/null | grep -c "'staging' is not")" 0

# --- docker is reloaded, never restarted: a restart stops other containers (review I1) ---
check "setup never restarts docker" "$(grep -c 'restart docker' "$here/www/setup.sh")" 0

[ "$fails" -eq 0 ] || { printf '%d failed\n' "$fails"; exit 1; }
echo "all passed"
