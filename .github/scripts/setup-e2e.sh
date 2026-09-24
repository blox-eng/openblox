#!/bin/sh
# Runs on a fresh GitHub-hosted Ubuntu 24.04 VM. Proves setup, re-run, a new
# client, the mTLS listener both ways, uninstall, and install-after-uninstall.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
export OPENBLOX_BASE_URL="file://$here/www"   # this branch's setup.sh and install.sh
setup() { sudo -E sh "$here/www/setup.sh" "$@"; }
say() { printf '\n== %s\n' "$*"; }

say "1. fresh install with a listener and two clients"
setup --listen 127.0.0.1:9443 --client staging --client prod
cfg_before=$(sudo sha256sum /etc/openbloxd/config.yaml)
ca_before=$(sudo sha256sum /etc/openbloxd/tls/clients-ca.crt)

say "2. mTLS: a known client is served, an unknown CA is refused"
c=/etc/openbloxd/clients/staging
sudo curl -fsS --cacert $c/ca.crt --cert $c/client.crt --key $c/client.key https://127.0.0.1:9443/profiles | grep -q code-exec
tmp=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=staging -keyout "$tmp/k" -out "$tmp/c" -days 1 2>/dev/null
if sudo curl -fsS --cacert $c/ca.crt --cert "$tmp/c" --key "$tmp/k" https://127.0.0.1:9443/profiles >/dev/null 2>&1; then
  echo "FAIL: a certificate from an unknown CA was accepted"; exit 1; fi

say "3. re-run changes nothing"
setup --listen 127.0.0.1:9443 --client staging --client prod
[ "$(sudo sha256sum /etc/openbloxd/config.yaml)" = "$cfg_before" ] || { echo "FAIL: config rewritten"; exit 1; }
[ "$(sudo sha256sum /etc/openbloxd/tls/clients-ca.crt)" = "$ca_before" ] || { echo "FAIL: CA regenerated"; exit 1; }
[ "$(sudo grep -c 'tcp dport 22 accept' /etc/nftables.d/openblox.nft)" = 1 ] || { echo "FAIL: firewall duplicated"; exit 1; }

say "4. adding a client issues only that client"
staging_before=$(sudo sha256sum $c/client.crt)
setup --listen 127.0.0.1:9443 --client staging --client prod --client dev
sudo test -f /etc/openbloxd/clients/dev/client.crt
[ "$(sudo sha256sum $c/client.crt)" = "$staging_before" ] || { echo "FAIL: existing client re-issued"; exit 1; }

say "5. uninstall removes what setup added, and setup works again after"
# Explicit ifs: under set -e, a bare `! cmd` never aborts the script, so it
# would make these checks unable to fail.
fail() { echo "FAIL: $*"; exit 1; }
sudo openblox-uninstall.sh
if systemctl is-active --quiet openbloxd; then fail "openbloxd still running"; fi
if sudo test -e /etc/openbloxd; then fail "/etc/openbloxd left behind"; fi
if sudo nft list table inet openblox >/dev/null 2>&1; then fail "firewall table left behind"; fi
[ -z "$(sudo docker ps -aq --filter label=sh.openblox.managed)" ] || fail "sandboxes left behind"
command -v docker >/dev/null || fail "Docker pre-existed and was removed"
if sudo docker info --format '{{json .Runtimes}}' | grep -q runsc; then fail "runsc still registered with Docker"; fi
setup
echo; echo "e2e: all passed"
