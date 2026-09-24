# `setup.sh`: a dedicated sandbox host from a fresh OS install

**Status:** approved 2026-09-24. The script is modelled on k3s's installer, uninstaller included.

## Goal

One command takes a freshly installed Debian 13 or Ubuntu 24.04 machine to a
working, hardened `openbloxd` host:

```bash
curl -fsSL https://openblox.sh/setup.sh | sh
```

…and one command undoes it: `openblox-uninstall.sh`, which `setup.sh` writes.

`install.sh` stays what it is: it installs the binary and touches nothing else.
`setup.sh` is for someone who has a machine to give to sandboxes and wants the
whole host done: runtime, daemon, service, network listener, firewall. It
calls `install.sh` for the binary, so the checksum and provenance checks live
in one place.

The first user is a real one: a spare machine on an isolated office network,
serving two remote callers (a staging and a production app). The design
must not depend on that setup.

## Non-goals

- Tunnels or VPNs (Tailscale, WireGuard). The guide tells you to bind the
  listener to a private address. How callers reach that address is up to you.
- Operating systems other than Debian 13 and Ubuntu 24.04. They are refused
  with a clear message. Supporting two well beats supporting ten badly.
- Kata. `setup.sh` provisions gVisor, the default runtime. Kata stays a
  documented manual path (`docs/getting-started.md#using-kata-instead`).
- Configuration management (Ansible, cloud-init) or prebuilt OS images.

## Behaviour

**Modelled on k3s's `install.sh`.** That installer is the reference for
getting this kind of script right: named phases run in a fixed order,
`info`/`warn`/`fatal` helpers, environment variables as the interface, and an
uninstaller generated at install time.

- **Root.** If not run as root, the script re-executes the privileged steps
  through `sudo`, so `curl … | sh` works on its own. With neither root nor
  `sudo`, it refuses with a message.
- **Idempotent.** Every phase checks before it changes anything. A re-run
  fixes drift and upgrades the version, and never duplicates anything.
- **Truncation-safe.** Like `install.sh`, the script is one `main` function
  invoked on the last line, so a truncated download runs nothing.
- **Phases:** `verify_system` → `setup_env` → `install_docker` →
  `install_gvisor` → `install_openbloxd` → `pin_image` → `write_config` →
  `issue_certs` → `harden` → `create_uninstall` →
  `create_systemd_service` → `service_enable_and_start` → `smoke_test`.
  The numbered steps below describe what each phase does.

### Options

Environment variables, since `curl … | sudo sh` cannot pass flags without
`sh -s --`. Each is also accepted as a flag when the script is run from a
file.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `OPENBLOX_VERSION` | `--version` | latest release | daemon and image version, in lockstep |
| `OPENBLOX_LISTEN` | `--listen` | unset (Unix socket only) | `host:port` for the mTLS listener |
| `OPENBLOX_CLIENTS` | `--client` (repeatable) | `sandbox-caller` when listening | client certificate Common Names to issue and allowlist |
| `OPENBLOX_ALLOW_FROM` | `--allow-from` | unset (any source) | CIDR allowed to reach the listener |
| `OPENBLOX_MEMORY_MB` | `--memory-mb` | `2048` | `memory_mb` of the generated `code-exec` profile |
| `OPENBLOX_MAX_SANDBOXES` | `--max-sandboxes` | computed, see step 1 | `max_sandboxes` of that profile |

### Steps

1. **Preflight.**
   - Checks: root; Linux on amd64 or arm64; `/etc/os-release` is Debian 13 or Ubuntu 24.04; cgroup v2 mounted.
   - Computes `max_sandboxes` as `floor((MemTotal − 1 GiB reserve) / (1.4 × memory_mb))`, minimum 1, and prints the arithmetic. The 1.4 factor comes from the observed overshoot of `memory_mb` (issue #30).
   - An explicit `OPENBLOX_MAX_SANDBOXES` that exceeds the computed value is accepted, with a warning.
2. **Docker Engine** from Docker's apt repository. The signing key is fetched to `/etc/apt/keyrings/docker.asc`, and the repository is limited to that key with `signed-by`. It is skipped if `docker` is already installed from any source; the script then only checks the version.
3. **gVisor.**
   - Installs `runsc` from gVisor's apt repository, using the same `signed-by` pattern.
   - Registers the runtime with `runsc install`, which *merges* into `/etc/docker/daemon.json` rather than replacing it.
   - Reloads Docker only if the runtime is not already listed in `docker info`.
4. **openbloxd.**
   - Installs the binary by running `install.sh` with `OPENBLOX_VERSION` and `OPENBLOX_BIN_DIR=/usr/local/bin`. It is fetched from the same origin as `setup.sh`.
   - Creates the `openbloxd` system user and group (no login shell, no home).
   - Installs the unit from `deploy/openbloxd.service`, fetched at the resolved tag rather than `main`.
5. **Sandbox image.**
   - Pulls `ghcr.io/blox-eng/openblox-sandbox:<version>`. Version tags are immutable by the publish pipeline.
   - Reads its digest and writes it into the config as `…:<version>@sha256:<digest>`.
   - When `gh` is present, it also verifies the image's build attestation, following `install.sh`'s rule: opportunistic, fatal only if it runs and fails.
6. **Configuration.** Writes `/etc/openbloxd/config.yaml` (mode 0640, `root:openbloxd`) with one profile, `code-exec`. It has the values of `deploy/openbloxd.example.yaml`, plus the pinned image and the computed cap.
   - **An existing config is never overwritten.** A re-run leaves it alone and prints a diff against what it would have written. Operators edit this file, and a setup script that clobbers edits cannot be run twice.
7. **Remote callers.** Only when `OPENBLOX_LISTEN` is set.
   - Creates a CA under `/etc/openbloxd/tls/`: an ECDSA P-256 key, mode 0600, owned by root.
   - That CA is used for **client certificates only**, as the example config requires. The server certificate comes from a second CA.
   - Issues the server certificate. Its SANs are the listen host plus the machine's hostname.
   - Issues one client certificate per Common Name, into `/etc/openbloxd/clients/<cn>/` as `client.crt`, `client.key` and `ca.crt` (the server CA, which the caller verifies the daemon against).
   - Existing CAs and certificates are reused, never regenerated. A re-run with a new `--client` issues only that client.
   - Prints the path of each client bundle and the `brokerclient.TLSFiles` it maps to.
   - Uses `openssl` only.
8. **Hardening.**
   - Installs and enables `unattended-upgrades`, security origin only.
   - Configures an nftables firewall: inbound default drop; allow established, loopback and SSH; plus the listener port, limited to `OPENBLOX_ALLOW_FROM` when set.
   - nftables and not ufw, because both OSes ship nftables and Docker already writes nftables/iptables rules. The script's rules live in their own table and never touch Docker's chains.
   - Existing SSH access is preserved: SSH is allowed before the default drop takes effect.
9. **Uninstaller.** Writes `/usr/local/bin/openblox-uninstall.sh`, as k3s
   does for `k3s-uninstall.sh`.
   - Each phase appends what it actually created to a manifest,
     `/var/lib/openblox/installed`. The uninstaller removes exactly that
     list and nothing more. Docker or gVisor that existed before setup ran
     is recorded as pre-existing and left alone.
   - What it removes:
     - every sandbox the daemon created, found by the openblox labels
     - the service, the binary and the `openbloxd` user
     - `/etc/openbloxd`: config, CAs and client bundles
     - the nftables table
     - the apt sources and keys that setup added
     - Docker and gVisor packages, if setup installed them
     - the pinned image
     - itself
   - It leaves `/var/lib/docker` in place and says so. Deleting a container
     store is not something to do implicitly.
   - Re-running setup rewrites the uninstaller, so it always matches the
     current install.
10. **Start and prove it.**
   - Enables and restarts `openbloxd`.
   - Runs a smoke test through the daemon's own socket: create a sandbox under `code-exec`, exec `uname -r`, and require `gvisor` in the output. Then exec a network lookup and require that it fails, then destroy the sandbox.
   - The smoke test uses the daemon's API with `curl --unix-socket`, so it needs no extra tooling.
   - Prints a summary: version, image digest, cap, listener, client bundles, next steps. On any failure, it names the step and exits non-zero.

### Output

The output follows `install.sh`'s voice. It uses plain `say`/`die`, prints one line per step, and has no colour codes that pollute logs. Every refusal tells you what to do next.

## Documentation

- **`docs/self-hosting.md`** (new; in the nav between "Production" and "Security model"). It covers:
  - Hardware: amd64 or arm64, at least 4 cores, an SSD, and RAM sized with the formula from step 1 in a worked table.
  - Which OS and why: Debian 13 minimal first, Ubuntu 24.04 also supported.
  - The command, and what each step does, linking the script.
  - Connecting remote callers: bundle paths → `brokerclient.NewRemote`.
  - Upgrading (re-run with a new version) and uninstalling (`openblox-uninstall.sh`, and what it keeps).
  - One known limit: CN allowlisting does not bind a client to a profile.
- **README:** a short "Dedicated host" subsection under Install, and a link from "In production".
- **`docs/production.md`:** links to self-hosting from "Deploying `openbloxd`".
- **Landing page:** a fourth install tab, **Host**, shows `curl -fsSL https://openblox.sh/setup.sh | sudo sh`, with the note "Debian 13 or Ubuntu 24.04 · a machine of its own". "Read the script first" points at `/setup.sh`.
  - `www/setup.sh` gets the same `_headers` block as `install.sh`: `text/plain`, 5-minute cache.
  - `check-links.sh` must pass.
- **CHANGELOG:** an `Added` entry under Unreleased.

## Testing

- **shellcheck** on `www/setup.sh` and `www/install.sh`, added to CI's Lint job (it isn't there today, and actionlint skips shell without it).
- **End to end in CI**, in a new job *Host setup (Ubuntu 24.04)* on a GitHub-hosted `ubuntu-24.04` VM, where there is root and a real kernel:
  1. Run `setup.sh` with `OPENBLOX_LISTEN=127.0.0.1:9443` and two clients. It must finish with the smoke test green.
  2. Call the listener over mTLS with a client bundle, and require the call to succeed. Present a certificate from an unknown CA, and require it to be refused.
  3. **Run `setup.sh` again.** It must change nothing (config untouched, CAs reused) and pass the smoke test again.
  4. Add a third client on a re-run, and require only that one to be issued.
  5. Run `openblox-uninstall.sh`. Require every manifest entry to be gone,
     no openblox containers left, and the firewall table removed. Then run
     `setup.sh` once more on the cleaned machine, and require it to succeed:
     an uninstall has to leave the host able to install again.

  The job runs against the latest *published* release, so it is not required on PRs. It runs on PRs that touch `www/setup.sh`, and on main.
- **Debian 13** is tested by hand on the first real machine. The PR records the result.

## Security notes

- The CA private keys never leave the host. Client keys are generated on the host and copied to callers by the operator. This is documented as the one secret-handling step.
- `setup.sh` never disables anything already hardened on the host, never opens a port other than SSH and the listener, and gives sandboxes no network (`egress: none`, as in the example).
- Two CAs, one for clients and one for the server, so that the client CA "signs NOTHING else", as the daemon's config documentation requires.
