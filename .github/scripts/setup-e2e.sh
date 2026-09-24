#!/bin/sh
# Runs on a fresh GitHub-hosted Ubuntu 24.04 VM. Proves setup, re-run, a new
# client, the mTLS listener both ways, uninstall, and install-after-uninstall.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
export OPENBLOX_BASE_URL="file://$here/www"   # this branch's setup.sh and install.sh
setup() { sudo -E sh "$here/www/setup.sh" "$@"; }
say() { printf '\n== %s\n' "$*"; }

fail() { echo "FAIL: $*"; exit 1; }

# A container that was here before openblox. Setup and uninstall reload
# Docker rather than restart it, so this must still be running at the end.
sudo docker run -d --name bystander busybox sleep 3600 >/dev/null

say "1. fresh install with a listener and two clients"
setup --listen 127.0.0.1:9443 --client staging --client prod
ca_before=$(sudo sha256sum /etc/openbloxd/tls/clients-ca.crt)

say "2. mTLS: a known client is served, an unknown CA is refused"
c=/etc/openbloxd/clients/staging
sudo curl -fsS --cacert $c/ca.crt --cert $c/client.crt --key $c/client.key https://127.0.0.1:9443/profiles | grep -q code-exec
tmp=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=staging -keyout "$tmp/k" -out "$tmp/c" -days 1 2>/dev/null
if sudo curl -fsS --cacert $c/ca.crt --cert "$tmp/c" --key "$tmp/k" https://127.0.0.1:9443/profiles >/dev/null 2>&1; then
  echo "FAIL: a certificate from an unknown CA was accepted"; exit 1; fi

say "3. re-run on an operator-edited config changes nothing"
echo "# operator edit" | sudo tee -a /etc/openbloxd/config.yaml >/dev/null
cfg_before=$(sudo sha256sum /etc/openbloxd/config.yaml)
setup --listen 127.0.0.1:9443 --client staging --client prod
[ "$(sudo sha256sum /etc/openbloxd/config.yaml)" = "$cfg_before" ] || fail "config rewritten"
[ "$(sudo sha256sum /etc/openbloxd/tls/clients-ca.crt)" = "$ca_before" ] || fail "CA regenerated"
[ "$(sudo nft list tables | grep -c 'inet openblox')" = 1 ] || fail "firewall table duplicated"
[ "$(grep -c 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf)" = 1 ] || fail "nftables.conf include duplicated"

say "3b. a re-run with no settings (an upgrade) keeps the listener and its firewall rule"
setup
sudo curl -fsS --cacert $c/ca.crt --cert $c/client.crt --key $c/client.key https://127.0.0.1:9443/profiles | grep -q code-exec ||
  fail "listener unreachable after a bare re-run"
sudo grep -q 'tcp dport 9443 accept' /etc/nftables.d/openblox.nft || fail "listener port dropped from the firewall"

say "4. adding a client issues only that client"
staging_before=$(sudo sha256sum $c/client.crt)
out=$(setup --client dev 2>&1)
printf '%s\n' "$out"
sudo test -f /etc/openbloxd/clients/dev/client.crt || fail "new client not issued"
[ "$(sudo sha256sum $c/client.crt)" = "$staging_before" ] || fail "existing client re-issued"
printf '%s' "$out" | grep -q "'dev' is not in allowed_client_cns" || fail "no warning that dev is not allowed yet"

say "5. uninstall removes what setup added, and setup works again after"
# Explicit ifs: under set -e, a bare `! cmd` never aborts the script, so it
# would make these checks unable to fail.
sudo openblox-uninstall.sh
if systemctl is-active --quiet openbloxd; then fail "openbloxd still running"; fi
if sudo test -e /etc/openbloxd; then fail "/etc/openbloxd left behind"; fi
if sudo nft list table inet openblox >/dev/null 2>&1; then fail "firewall table left behind"; fi
[ -z "$(sudo docker ps -aq --filter label=sh.openblox.managed)" ] || fail "sandboxes left behind"
command -v docker >/dev/null || fail "Docker pre-existed and was removed"
if sudo docker info --format '{{json .Runtimes}}' | grep -q runsc; then fail "runsc still registered with Docker"; fi
[ "$(sudo docker inspect -f '{{.State.Running}}' bystander)" = true ] || fail "a container that predates openblox was stopped"
setup
echo; echo "e2e: all passed"
