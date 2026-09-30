# setup.sh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `curl -fsSL https://openblox.sh/setup.sh | sh` turns a fresh Debian 13 / Ubuntu 24.04 machine into a hardened openbloxd host, and a generated `openblox-uninstall.sh` removes exactly what it added.

**Architecture:** one POSIX `sh` script, `www/setup.sh`, modelled on k3s's `install.sh`. It runs named phases in a fixed order, and every phase checks before it changes anything. Pure logic (argument parsing, OS detection, sizing, config rendering, certificates, the manifest, the uninstaller) is unit-tested without root by sourcing the script with `OPENBLOX_SETUP_LIB=1`. The system phases are proven end to end on a fresh GitHub-hosted Ubuntu 24.04 VM.

**Tech Stack:** POSIX sh, apt, Docker Engine, gVisor (`runsc`), openssl, nftables, systemd, shellcheck, GitHub Actions.

**Spec:** `specs/2026-09-24-setup-sh-design.md`

## Global Constraints

- Supported systems: Debian 13 (`ID=debian`, `VERSION_ID=13`) and Ubuntu 24.04 (`ID=ubuntu`, `VERSION_ID=24.04`), on amd64 or arm64. Everything else is refused.
- POSIX `sh` only, with no bashisms. It must pass `shellcheck -s sh`.
- The script is one `main "$@"` call on its last line, so a truncated download runs nothing.
- Environment variables are the interface: `OPENBLOX_VERSION`, `OPENBLOX_LISTEN`, `OPENBLOX_CLIENTS` (space-separated), `OPENBLOX_ALLOW_FROM`, `OPENBLOX_MEMORY_MB` (default `2048`), `OPENBLOX_MAX_SANDBOXES`. Each has a flag equivalent: `--version`, `--listen`, `--client` (repeatable), `--allow-from`, `--memory-mb`, `--max-sandboxes`.
- Sizing: `max_sandboxes = floor((MemTotal_MB − 1024) / (1.4 × memory_mb))`, minimum 1.
- Paths:
  - binary: `/usr/local/bin/openbloxd`
  - config: `/etc/openbloxd/config.yaml` (0640, `root:openbloxd`)
  - TLS: `/etc/openbloxd/tls/` and `/etc/openbloxd/clients/<cn>/{client.crt,client.key,ca.crt}`
  - manifest: `/var/lib/openblox/installed`
  - uninstaller: `/usr/local/bin/openblox-uninstall.sh`
  - socket: `/run/openbloxd/openbloxd.sock`
- An existing config, CA or client certificate is never overwritten.
- Image: `ghcr.io/blox-eng/openblox-sandbox:<version>@sha256:<digest>`, in lockstep with the daemon version.
- Container labels: `sh.openblox.managed` marks every sandbox (`pkg/docker/backend.go:29`).
- Output: `info` / `warn` / `fatal` helpers and no colour codes. `fatal` names the phase and the next action.
- No new runtime dependencies beyond what the phases install. The tests need only `sh`, `openssl` and `shellcheck`.

## Review Focus

1. **A re-run on a configured host.** The operator edited `config.yaml` and re-runs to upgrade. The config must be untouched, a diff printed, and the CAs reused. Pinned by Task 3 and Task 4 tests, and by e2e step 3.
2. **`curl … | sh` as a non-root user with sudo.** It must re-exec through sudo and work; with no sudo, it must refuse clearly. Pinned by a Task 1 unit test (`need_root` with a stubbed `id` / `sudo`).
3. **Memory too small for even one sandbox**, e.g. a 2 GiB machine at `memory_mb=2048`. The cap must be 1, with a warning that the host is undersized, never 0 or negative. Pinned by a Task 1 test.
4. **SSH lockout from the firewall.** The rules must be loaded atomically with SSH allowed, and a re-run must not duplicate them. Pinned by the Task 6 test on the rendered ruleset and by e2e (the job keeps running after `harden`).
5. **Uninstall on a host where Docker pre-existed.** It must leave Docker installed and its other containers running. Pinned by a Task 5 test (manifest without `pkg docker-ce` → the rendered uninstaller contains no Docker purge).

---

## File Structure

- `www/setup.sh` (create): the script. Served at `openblox.sh/setup.sh`.
- `.github/scripts/setup-unit.sh` (create): unit tests. Sources the script as a library and needs no root.
- `.github/scripts/setup-e2e.sh` (create): the end-to-end checks run in CI after `setup.sh`.
- `.github/workflows/host-setup.yml` (create): the *Host setup (Ubuntu 24.04)* job.
- `.github/workflows/ci.yml` (modify): the Lint job gains shellcheck and the setup unit tests.
- `Makefile` (modify): `lint-sh` and `test-setup` targets.
- `www/_headers` (modify): `/setup.sh` served as text/plain, 5-minute cache.
- `www/index.html`, `www/app.js` (modify): a fourth tab, **Host**.
- `docs/self-hosting.md` (create), `mkdocs.yml` (nav), `docs/production.md`, `README.md`, `CHANGELOG.md` (modify).

---

### Task 1: Skeleton, helpers, options, preflight, sizing

**Files:**
- Create: `www/setup.sh`
- Create: `.github/scripts/setup-unit.sh`
- Modify: `Makefile`, `.github/workflows/ci.yml` (Lint job)

**Interfaces:**
- Produces:
  - `info MSG`, `warn MSG`, `fatal MSG` (exits 1)
  - `parse_args "$@"`, which sets `VERSION LISTEN CLIENTS ALLOW_FROM MEMORY_MB MAX_SANDBOXES`
  - `detect_os OS_RELEASE_PATH`, which echoes `debian13` or `ubuntu2404`, or calls `fatal`
  - `detect_arch`, which echoes `amd64` or `arm64`
  - `compute_max_sandboxes MEMTOTAL_MB MEMORY_MB`, which echoes an integer ≥ 1
  - `need_root`, which re-execs via sudo, passing the parsed values explicitly, or calls `fatal`
  - `$SUDO_BIN` and `$ID_BIN`, overridable in tests
  - `OPENBLOX_SETUP_LIB=1` makes the script define its functions without running `main`

- [ ] **Step 1: Write the failing unit tests**

`.github/scripts/setup-unit.sh`:
```sh
#!/bin/sh
# Unit tests for www/setup.sh. Sources it as a library; needs no root.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
OPENBLOX_SETUP_LIB=1
# shellcheck source=../../www/setup.sh
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

[ "$fails" -eq 0 ] || { printf '%d failed\n' "$fails"; exit 1; }
echo "all passed"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `sh .github/scripts/setup-unit.sh`
Expected: fails with `www/setup.sh: No such file or directory`.

- [ ] **Step 3: Write the skeleton**

`www/setup.sh`:
```sh
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
BIN_DIR=/usr/local/bin
SOCKET=/run/openbloxd/openbloxd.sock
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
  id=$(. "$1"; echo "${ID:-}"); ver=$(. "$1"; echo "${VERSION_ID:-}")
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
```

Note: the last line breaks the "last line is `main`" rule only for the library guard. A truncated download still runs nothing, because the guard *is* the last line.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `sh .github/scripts/setup-unit.sh`
Expected: every line `ok`, then `all passed`. (Worked check: 16000 MiB at 2048 → (16000−1024)·10/(2048·14) = 149760/28672 = 5.)

- [ ] **Step 5: Add the lint and test targets and wire CI**

`Makefile`, next to the existing targets:
```make
lint-sh: ## shellcheck every shell script we ship or run in CI
	shellcheck -s sh www/install.sh www/setup.sh .github/scripts/setup-unit.sh .github/scripts/setup-e2e.sh

test-setup: ## unit tests for www/setup.sh (no root needed)
	sh .github/scripts/setup-unit.sh
```
`.github/workflows/ci.yml`, Lint job, after `golangci-lint`:
```yaml
      # actionlint does not lint shell without shellcheck, and nothing else
      # did either: install.sh shipped with only human review.
      - name: shellcheck
        run: sudo apt-get install -y -qq shellcheck && make lint-sh
      - name: setup.sh unit tests
        run: make test-setup
```
Install locally: `sudo apt-get install -y shellcheck`. Then run `make lint-sh test-setup`. Expected: no findings, `all passed`. (Create an empty `.github/scripts/setup-e2e.sh` with a shebang now so `lint-sh` resolves; Task 7 fills it in.) Fix any shellcheck finding in `install.sh` in this task too.

- [ ] **Step 6: Commit**
```bash
git add www/setup.sh .github/scripts/setup-unit.sh .github/scripts/setup-e2e.sh Makefile .github/workflows/ci.yml www/install.sh
git commit -m "feat(setup): setup.sh skeleton — options, preflight, sizing, sudo re-exec"
```

---

### Task 2: Manifest

**Files:** Modify `www/setup.sh`, `.github/scripts/setup-unit.sh`

**Interfaces:**
- Produces:
  - `record KIND VALUE`: appends `KIND VALUE` to `$STATE/installed` once. Kinds: `pkg`, `file`, `dir`, `user`, `apt-source`, `nft-table`, `image`, `unit`.
  - `recorded KIND VALUE`: exit status 0 if that entry is recorded.
  - `preexisting_pkg PKG`: exit status 0 if the package was installed before setup first ran; the answer is kept in `$STATE/preexisting`.

- [ ] **Step 1: Failing tests** (append to `setup-unit.sh` before the summary):
```sh
# --- manifest ---
STATE="$tmp/state"
record file /etc/openbloxd/config.yaml
record file /etc/openbloxd/config.yaml
record pkg runsc
check "record dedupes" "$(grep -c 'file /etc/openbloxd/config.yaml' "$STATE/installed")" 1
check "recorded yes" "$(status recorded pkg runsc)" 0
check "recorded no"  "$(status recorded pkg docker-ce)" 1
```
- [ ] **Step 2:** Run `sh .github/scripts/setup-unit.sh`. Expected: FAIL (`record: not found`).
- [ ] **Step 3: Implement** in `www/setup.sh`, after the helpers:
```sh
# Everything this script creates is written here as it is created, and the
# uninstaller removes exactly this list. Something that existed before setup
# first ran is never on it, so uninstalling cannot take away what you had.
record() {
  mkdir -p "$STATE"
  grep -qxF "$1 $2" "$STATE/installed" 2>/dev/null || printf '%s %s\n' "$1" "$2" >> "$STATE/installed"
}
recorded() { grep -qxF "$1 $2" "$STATE/installed" 2>/dev/null; }
```
- [ ] **Step 4:** Run the tests. Expected: `all passed`.
- [ ] **Step 5:** Commit: `feat(setup): record what setup creates, so uninstall removes only that`

---

### Task 3: Configuration rendering, never clobbered

**Files:** Modify `www/setup.sh`, `.github/scripts/setup-unit.sh`

**Interfaces:**
- Consumes: `record`, and `LISTEN CLIENTS MEMORY_MB MAX_SANDBOXES`.
- Produces:
  - `render_config IMAGE`: echoes the full YAML.
  - `write_config IMAGE`: writes `$ETC/config.yaml` if absent. Otherwise it leaves the file alone and prints a diff with a `warn`.

- [ ] **Step 1: Failing tests:**
```sh
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
```
- [ ] **Step 2:** Run the tests. Expected: FAIL (`render_config: not found`).
- [ ] **Step 3: Implement.** Values come from `deploy/openbloxd.example.yaml`:
```sh
render_config() {
  cat <<EOF
# Written by openblox setup.sh. Edit freely: setup never overwrites this file.
socket: $SOCKET
socket_group: openbloxd
reap_interval: 1m
EOF
  if [ -n "$LISTEN" ]; then
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
  render_config "$1" > "$ETC/config.yaml"
  chmod 0640 "$ETC/config.yaml"
  chgrp openbloxd "$ETC/config.yaml" 2>/dev/null || true
  record file "$ETC/config.yaml"
  info "wrote $ETC/config.yaml"
}
```
`printf '%s\n' $CLIENTS` is deliberately unquoted: it splits the space-separated list. Add `# shellcheck disable=SC2086` on that line.
- [ ] **Step 4:** Run the tests. Expected: `all passed`.
- [ ] **Step 5:** Commit: `feat(setup): write the daemon config once, and diff instead of clobbering`

---

### Task 4: Certificates — two CAs, reuse, per-client bundles

**Files:** Modify `www/setup.sh`, `.github/scripts/setup-unit.sh`

**Interfaces:**
- Consumes: `record`, `LISTEN`, `CLIENTS`, `ETC`.
- Produces: `issue_certs`. It is a no-op without `LISTEN`. Otherwise it creates:
  - `$ETC/tls/{server-ca.crt,server-ca.key,server.crt,server.key,clients-ca.crt,clients-ca.key}`
  - `$ETC/clients/<cn>/{client.crt,client.key,ca.crt}`

- [ ] **Step 1: Failing tests:**
```sh
# --- certificates ---
ETC="$tmp/pki"; LISTEN="127.0.0.1:9443"; CLIENTS="staging prod"
issue_certs >/dev/null
check "server cert chains to server CA" "$(status openssl verify -CAfile "$ETC/tls/server-ca.crt" "$ETC/tls/server.crt")" 0
check "client chains to CLIENT CA"      "$(status openssl verify -CAfile "$ETC/tls/clients-ca.crt" "$ETC/clients/staging/client.crt")" 0
check "client does NOT chain to server CA" "$(status openssl verify -CAfile "$ETC/tls/server-ca.crt" "$ETC/clients/staging/client.crt")" 1
check "client CN" "$(openssl x509 -in "$ETC/clients/prod/client.crt" -noout -subject | sed 's/.*CN *= *//')" prod
check "server SAN has listen IP" "$(openssl x509 -in "$ETC/tls/server.crt" -noout -ext subjectAltName | grep -c 'IP Address:127.0.0.1')" 1
check "bundle carries server CA" "$(cmp -s "$ETC/clients/prod/ca.crt" "$ETC/tls/server-ca.crt" && echo same)" same
check "CA key private" "$(stat -c %a "$ETC/tls/clients-ca.key")" 600
before=$(openssl x509 -in "$ETC/tls/clients-ca.crt" -noout -fingerprint)
CLIENTS="staging prod dev"; issue_certs >/dev/null
check "CA reused on re-run" "$(openssl x509 -in "$ETC/tls/clients-ca.crt" -noout -fingerprint)" "$before"
check "new client issued"   "$(status test -f "$ETC/clients/dev/client.crt")" 0
```
- [ ] **Step 2:** Run the tests. Expected: FAIL (`issue_certs: not found`).
- [ ] **Step 3: Implement:**
```sh
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
  mkdir -p "$ETC/tls" "$ETC/clients"; chmod 0750 "$ETC/tls"
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
```
`for cn in $CLIENTS` splits deliberately; add `# shellcheck disable=SC2086` if shellcheck flags it. `server.key` is group-readable by `openbloxd` because the daemon reads it. The CA keys stay root-only.
- [ ] **Step 4:** Run the tests. Expected: `all passed`.
- [ ] **Step 5:** Commit: `feat(setup): mTLS — separate client and server CAs, reused on re-run, one bundle per caller`

---

### Task 5: The generated uninstaller

**Files:** Modify `www/setup.sh`, `.github/scripts/setup-unit.sh`

**Interfaces:**
- Consumes: the manifest format from Task 2.
- Produces: `render_uninstall`, which echoes a POSIX sh script that reads `$STATE/installed` at run time. `create_uninstall` writes it to `$BIN_DIR/openblox-uninstall.sh`, mode 0755.

- [ ] **Step 1: Failing tests:**
```sh
# --- uninstaller ---
render_uninstall > "$tmp/un.sh"
check "uninstaller parses" "$(status sh -n "$tmp/un.sh")" 0
if command -v shellcheck >/dev/null; then check "uninstaller lint" "$(status shellcheck -s sh "$tmp/un.sh")" 0; fi
check "keeps /var/lib/docker" "$(grep -c 'rm -rf /var/lib/docker' "$tmp/un.sh")" 0
# Docker purged only when setup installed it: the script decides from the manifest at run time.
check "docker purge is manifest-gated" "$(grep -c 'grep -qx "pkg docker-ce"' "$tmp/un.sh")" 1
check "runsc unregistered before purge" "$(grep -c 'runsc uninstall' "$tmp/un.sh")" 1
```
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3: Implement.** The body is written with a quoted heredoc, so nothing expands at setup time. Only `STATE` is substituted.
```sh
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
```
- [ ] **Step 4:** Run `make test-setup lint-sh`. Expected: `all passed`, no shellcheck findings.
- [ ] **Step 5:** Commit: `feat(setup): generate openblox-uninstall.sh from the install manifest, as k3s does`

---

### Task 6: System phases — Docker, gVisor, daemon, image, firewall, service, smoke test

**Files:** Modify `www/setup.sh`, `.github/scripts/setup-unit.sh` (firewall rendering only)

**Interfaces:**
- Consumes: everything above.
- Produces: `install_docker`, `install_gvisor`, `install_openbloxd`, `pin_image` (sets `IMAGE`), `render_nft`, `harden`, `create_systemd_service`, `service_enable_and_start`, `smoke_test`, and the final `main` order.

These phases need root and a real host, so their proof is the CI job in Task 7. `render_nft` is pure and gets unit tests.

- [ ] **Step 1: Failing firewall tests:**
```sh
# --- firewall ---
LISTEN="10.0.0.5:9443"; ALLOW_FROM="10.0.0.0/24"
render_nft > "$tmp/fw"
check "own table" "$(grep -c 'table inet openblox' "$tmp/fw")" 1
check "ssh allowed" "$(grep -c 'tcp dport 22 accept' "$tmp/fw")" 1
check "listener limited to source" "$(grep -c 'ip saddr 10.0.0.0/24 tcp dport 9443 accept' "$tmp/fw")" 1
check "delete before define (re-run safe)" "$(head -n2 "$tmp/fw" | grep -c 'delete table inet openblox')" 1
LISTEN=""; render_nft > "$tmp/fw2"
check "no listener port without --listen" "$(grep -c 'dport 9443' "$tmp/fw2")" 0
```
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3: Implement the phases:**
```sh
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
    retry curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
    record file /usr/share/keyrings/gvisor-archive-keyring.gpg; record apt-source /etc/apt/sources.list.d/gvisor.list
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
  out=$(api -X POST "http://openbloxd/sandboxes/$1/exec" -d "{\"argv\":$2,\"timeout\":\"20s\"}")
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
```
Final `main`:
```sh
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
```
Also add `setup_env`. It snapshots which relevant packages existed before the *first* run, so the uninstaller never removes them:
```sh
setup_env() {
  PHASE=setup_env
  mkdir -p "$STATE"
  [ -f "$STATE/preexisting" ] || for p in docker-ce runsc nftables unattended-upgrades; do
    pkg_present "$p" && echo "$p"; done > "$STATE/preexisting"
  export DEBIAN_FRONTEND=noninteractive
}
```
Then, in `record`, skip `pkg` entries listed in `$STATE/preexisting`:
```sh
record() {
  mkdir -p "$STATE"
  if [ "$1" = pkg ] && grep -qxF "$2" "$STATE/preexisting" 2>/dev/null; then return 0; fi
  grep -qxF "$1 $2" "$STATE/installed" 2>/dev/null || printf '%s %s\n' "$1" "$2" >> "$STATE/installed"
}
```
Add a unit test for that (Review Focus 5):
```sh
printf 'docker-ce\n' > "$STATE/preexisting"; record pkg docker-ce
check "preexisting docker never recorded" "$(status recorded pkg docker-ce)" 1
```
- [ ] **Step 4:** Run `make test-setup lint-sh`. Expected: `all passed`, no findings.
- [ ] **Step 5:** Commit: `feat(setup): the system phases — Docker, gVisor, daemon, pinned image, firewall, service, smoke test`

---

### Task 7: End to end on a fresh Ubuntu 24.04 VM

**Files:**
- Modify: `.github/scripts/setup-e2e.sh`
- Create: `.github/workflows/host-setup.yml`

- [ ] **Step 1: Write the e2e checks** in `.github/scripts/setup-e2e.sh`:
```sh
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
```
Note: steps 2 and 3 are the known-risk checks from Review Focus 1 and 4.

- [ ] **Step 2: Add the workflow**, `.github/workflows/host-setup.yml`:
```yaml
name: Host setup

on:
  pull_request:
    paths: ['www/setup.sh', 'www/install.sh', '.github/scripts/setup-*.sh', '.github/workflows/host-setup.yml']
  push:
    branches: [main]
    paths: ['www/setup.sh', 'www/install.sh', '.github/scripts/setup-*.sh', '.github/workflows/host-setup.yml']
  workflow_dispatch:

permissions:
  contents: read

jobs:
  ubuntu:
    name: Host setup (Ubuntu 24.04)
    # A hosted runner is a real VM with root and its own kernel — the only CI
    # place setup.sh can install Docker, gVisor and a firewall for real.
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: setup, re-run, add a client, uninstall, reinstall
        run: sh .github/scripts/setup-e2e.sh
```
The runner image ships Docker already. So this run exercises the "Docker pre-exists" branch: setup must leave Docker installed, and the uninstaller must not purge it. That is Review Focus 5, proven for real.

- [ ] **Step 3:** Push the branch and open a draft PR. Watch the job: `gh run watch`. Expected: the job ends with `e2e: all passed`. On failure, read the log, fix the phase, and push again. Do not weaken a check to get green.
- [ ] **Step 4:** Commit: `ci(setup): prove setup.sh end to end on a fresh Ubuntu 24.04 VM`

---

### Task 8: Docs, README, CHANGELOG

**Files:**
- Create: `docs/self-hosting.md`
- Modify: `mkdocs.yml` (nav: `- Self-hosting: self-hosting.md` after Production), `docs/production.md` (a link in "Deploying `openbloxd`"), `README.md` (a "Dedicated host" subsection under Install, and a link in "In production"), `CHANGELOG.md` (an `### Added` entry under `[Unreleased]`)

- [ ] **Step 1:** Write `docs/self-hosting.md` with these sections, in this order:
  1. **What you get:** one paragraph, and the one command.
  2. **Hardware:** amd64 or arm64, at least 4 cores, an SSD. A RAM table from the sizing formula at `memory_mb=2048`: 8 GiB → 2, 16 GiB → 5, 32 GiB → 11, 64 GiB → 22 (nominal sizes; the real MemTotal is a little lower, so the script may compute one less), each computed with `compute_max_sandboxes`.
  3. **Choosing an OS:** Debian 13 minimal (recommended: small, no snap, long support) or Ubuntu 24.04 LTS. Install with SSH only, no desktop.
  4. **Run it:** the command. The options table from the spec. What each phase does, one line each.
  5. **Remote callers:** the `OPENBLOX_LISTEN=… OPENBLOX_CLIENTS="a b"` example. Where the bundles land. How to copy them to a caller. The Go snippet using `brokerclient.NewRemote(addr, brokerclient.TLSFiles{CertFile, KeyFile, CAFile})`. Bind to a private address; reaching it (VPN, tailnet) is yours to arrange.
  6. **Upgrading:** re-run with `OPENBLOX_VERSION=vX.Y.Z`. The config is not rewritten, so bump the image line by hand from the printed diff.
  7. **Uninstalling:** `openblox-uninstall.sh`, what it removes, and that it keeps `/var/lib/docker`.
  8. **Known limits:** client CNs are not bound to profiles; Kata is not provisioned (link to getting-started).
- [ ] **Step 2:** Build the docs: `python -m venv /tmp/mk && /tmp/mk/bin/pip install -q -r requirements-docs.txt && /tmp/mk/bin/mkdocs build --strict`. Expected: no warnings.
- [ ] **Step 3:** README and CHANGELOG edits, then commit: `docs: self-hosting guide, and setup.sh in the README`

---

### Task 9: Landing page — the Host tab

**Files:** Modify `www/index.html`, `www/app.js`, `www/_headers`

- [ ] **Step 1:** In `www/index.html`, add a fourth tab after `t-lib`:
```html
<button role="tab" id="t-host" aria-selected="false" aria-controls="cmdline">Host</button>
```
- [ ] **Step 2:** In `www/app.js`, add to `COMMANDS`, and make `readit` follow the tab:
```js
    't-host': {
      cmd: 'curl -fsSL https://openblox.sh/setup.sh | sh',
      note: 'Debian 13 or Ubuntu 24.04 · a machine of its own · Docker, gVisor, daemon, firewall',
      read: '/setup.sh'
    }
```
Change the Daemon entry to `read: '/install.sh'`. In `select`, replace `readit.hidden = !c.read;` with:
```js
    readit.hidden = !c.read;
    if (c.read) readit.href = c.read;
```
- [ ] **Step 3:** In `www/_headers`, add after the `/install.sh` block:
```
/setup.sh
  Content-Type: text/plain; charset=utf-8
  Cache-Control: public, max-age=300
```
- [ ] **Step 4:** Verify: `.github/scripts/check-links.sh www` passes. Then serve locally with `python3 -m http.server -d www 8000` and check with the browser (Playwright):
  - All four tabs switch, and arrow keys cycle through all four.
  - Host shows the setup command, and its read link opens `/setup.sh`.
  - Copy copies the Host command.
  - There are no console errors.
  - The layout holds at 375px width.
- [ ] **Step 5:** Commit: `feat(www): a Host tab for setup.sh`

---

### Task 10: The first real machine (Debian 13)

- [ ] **Step 1:** On a fresh Debian 13 install, run `curl -fsSL https://raw.githubusercontent.com/blox-eng/openblox/feat/setup-sh/www/setup.sh | OPENBLOX_BASE_URL=https://raw.githubusercontent.com/blox-eng/openblox/feat/setup-sh/www sh`, with the user's `--listen`, clients and `--allow-from`.
- [ ] **Step 2:** Record in the PR:
  - the output
  - `openbloxd -version`
  - the smoke test line
  - a re-run showing no changes
  - `openblox-uninstall.sh` followed by a reinstall
- [ ] **Step 3:** Fix anything Debian-specific. Each fix gets a unit test where the logic allows one.
