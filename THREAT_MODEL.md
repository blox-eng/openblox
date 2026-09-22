# Threat model

This document states what openblox defends against, how, where the defence is
tested, and what it does not defend against. It describes the code in this
repository at the commit you are reading. Where a statement is backed by a test,
the test is named; a claim with no test next to it is a design statement, not a
verified one.

openblox reduces the attack surface available to untrusted code. It does not make
running untrusted code risk-free, and nothing here should be read as a guarantee
that a sandbox cannot be escaped.

## 1. System and deployment modes

```
 untrusted code ──runs in──► sandbox (container, runtime: runsc)
                                  ▲
                                  │ Docker Engine API
                     ┌────────────┴────────────┐
   Mode A (direct):  your process + pkg/docker     ← holds the Docker socket
   Mode B (broker):  openbloxd + pkg/docker        ← holds the Docker socket
                        ▲ Unix socket (group-gated)
                     your process + pkg/brokerclient  ← holds no Docker access
```

- **Mode A — direct library.** Your process imports `pkg/docker` and talks to the
  Docker daemon. It therefore holds the Docker socket, which is equivalent to root
  on the host. Anything that can make your process issue arbitrary Docker API calls
  — a bug, a dependency, a prompt injection that reaches a code path you did not
  intend — owns the host. openblox cannot prevent this; it is a property of the
  Docker API.
- **Mode B — `openbloxd` broker (recommended for production).** The daemon owns the
  Docker socket and exposes only openblox's operations over a Unix socket. Isolation
  policy (image, runtime, egress, user, resources, lifetime) is fixed per profile in
  the daemon's configuration and cannot be set by a request. A compromised caller can
  create, use and destroy sandboxes within the configured profiles; it cannot ask
  for a weaker sandbox and cannot reach the Docker API.

## 2. Trust

| Trusted (a failure here is outside openblox's control) | Untrusted (openblox is designed to contain it) |
|---|---|
| Host hardware, firmware and kernel | Code running inside a sandbox, including native code |
| Docker Engine and containerd | AI-generated code and code supplied by users |
| gVisor (`runsc`) and its configuration | Files, archives and data placed into a sandbox |
| `openbloxd`, its binary and its config file | Everything a sandbox returns: stdout, stderr, files, exit codes, preview HTTP responses |
| The sandbox image (its userland) | Holders of preview URLs (authenticated by token, not trusted) |
| The process that imports openblox (Mode A) | |
| Members of `openbloxd`'s `socket_group` (Mode B) | |

The **image** is trusted because it is the guest's entire userland: a malicious image
controls what every command in the sandbox does. openblox does not scan or verify
images. Pin them by digest.

## 3. Assets

1. **The host** — its kernel, filesystem, processes, credentials.
2. **The Docker socket** — root-equivalent on the host.
3. **Other sandboxes** — their files, environment, processes and output.
4. **Caller secrets** — registry credentials, the preview signing key, the caller's
   own environment.
5. **The network** — the host's and the LAN's services, cloud metadata endpoints,
   the internet (as an exfiltration route).
6. **Availability** — of the host, of `openbloxd`, and of other sandboxes.

## 4. Attacker

The primary attacker controls code running inside a sandbox, as the unprivileged
sandbox user, with every syscall gVisor implements. They choose what the code
prints, which files it writes, which ports it listens on inside the sandbox, how
long it runs, and how it behaves when signalled. They may know the openblox source
and the host's gVisor version.

Secondary attackers considered: a holder of a preview URL (with or without a valid
token), and a caller that has been compromised (Mode B: it can speak to
`openbloxd`; Mode A: see §1 — it already owns the host).

Not considered attackers: host root, Docker administrators, the image publisher,
and anyone who can edit `openbloxd`'s configuration. Each of those already controls
more than a sandbox.

## 5. Trust boundaries and what happens when each fails

| Boundary | Enforced by | If it fails |
|---|---|---|
| **B1** guest ↔ gVisor Sentry | gVisor's user-space kernel: guest syscalls are handled by the Sentry, not the host kernel | The attacker runs code in the Sentry's context on the host: an unprivileged, seccomp-filtered process. Combined with **B2** failing, host compromise. |
| **B2** Sentry ↔ host kernel | gVisor's seccomp filter on the Sentry and gofer, running in their own namespaces | Host kernel attack surface is exposed to an attacker already past B1. Host compromise is plausible. |
| **B3** sandbox ↔ network | `NetworkMode: none`: the only interface is loopback | The sandbox can reach whatever the host can: other hosts, internal services, metadata endpoints, the internet. Only relevant if a profile or caller opts into `unrestricted` egress, or Docker ignores the setting. |
| **B4** caller ↔ `openbloxd` (Mode B) | Unix socket permissions (`0660`, `socket_group`) and a fixed API with strict decoding | A process outside the group gains full control of every sandbox the daemon manages — create, exec, read, destroy — within the configured profiles. It does not gain the Docker socket. |
| **B5** `openbloxd` ↔ Docker | `openbloxd` is the only holder of the socket in Mode B | Compromise of `openbloxd` is compromise of the Docker socket, i.e. host root. |
| **B6** preview client ↔ sandbox port | HMAC-SHA256 token bound to sandbox name, port and expiry; key ≥ 32 bytes; TTL ≤ 24 h | A token holder reaches that port on that sandbox. A key compromise lets the holder mint tokens for any sandbox port. |

## 6. Attacks

"Tested" names the test that exercises the attack on a live gVisor host
(`go test -tags integration`). "Unit" tests need no Docker.

Where the defence is one of the properties `pkg/conformance`
asserts against `sandbox.Backend`, "Tested" names the property as registered in
`pkg/conformance/conformance.go`'s `core` slice (run here via `pkg/docker`'s
`TestConformance`: `go test -tags integration -run TestConformance ./pkg/docker/`)
or its `hostLocal` slice, marked **(host-local)** below — real coverage, opt-in,
and never a Core result, because an implementation that cannot run it has not
conformed any less. Everything else is an ordinary Go test name.

### Escape and privilege

| Attack | Defence | Tested | Residual |
|---|---|---|---|
| Container escape via the host kernel | gVisor: guest syscalls never reach the host kernel directly (B1, B2). The configured runtime must be registered or `Create` fails (`ErrRuntimeUnavailable`); there is never a silent fallback to `runc`. This model assumes the default, `runsc`; under a microVM runtime the guest reaches a separate kernel instead and B1/B2 do not apply. | `TestSandboxRunsUnderGvisorKernel`, `TestCreateRejectsUnavailableRuntime` | A gVisor vulnerability. Keep `runsc` patched. |
| gVisor vulnerability | Out of openblox's control. Defence in depth: non-root, no capabilities, read-only root, no network. | — | Real. gVisor has had and will have CVEs. |
| Running as root | `Spec.Validate` refuses a user that is not an explicit, numeric, non-zero `uid:gid`. User names are refused because they resolve inside the untrusted image, and a bare uid because Docker then takes its primary and supplementary groups from that image — possibly group 0. `openbloxd` refuses such a profile at load. | `TestSpecValidateRefusesRootAndNamedUsers` (unit), `create-refuses-root`, `TestBrokerRefusesARootProfile`, `TestLoadRejectsRootUser` (unit) | — |
| Linux capabilities | `CapDrop: ALL`. | `no-capabilities` (all five sets are zero) | — |
| setuid / setgid binaries | `no-new-privileges`; every writable mount is `nosuid,noexec`; the root filesystem is read-only, so no new setuid binary can be placed. | `writable-mounts-are-noexec-nosuid` | A setuid binary already in the image is inert under `no-new-privileges`; use images without them anyway. |
| Namespace abuse, `mount`, device nodes | No capabilities, so no `mount`, `mknod`, `unshare` of privileged namespaces. No block devices are present. `/dev/fuse` is present in gVisor's `/dev` but mounting FUSE requires `CAP_SYS_ADMIN`. | `no-block-devices` | — |
| `/proc` and `/sys` abuse | Both are gVisor's synthetic views, not the host's. | `cannot-write-kernel-knobs` | Information about the guest itself is readable, as in any Linux process. |
| Docker socket access | No host path is ever mounted into a sandbox (no `Binds`, no `Mounts`, not privileged). | `TestBuildConfigAppliesContainment` (unit), `no-control-plane-socket` | A deployment that adds a mount by other means defeats this. |

### Network

| Attack | Defence | Tested | Residual |
|---|---|---|---|
| Outbound HTTP/HTTPS, IPv4 and IPv6 | `NetworkMode: none` (default; `EgressNone`). | `TestSandboxHasNoEgressAndNoResolver`, `no-host-private-or-metadata-addresses` | — |
| DNS exfiltration | No interface, so no resolver path, even to a resolver named explicitly. | same | `/etc/resolv.conf` inside the sandbox is written by Docker from the host's and reveals the host's nameservers and search domains. Informational only; it is unusable without a network. |
| Host loopback services | The sandbox's `127.0.0.1` is its own network namespace. | `loopback-is-not-the-hosts` | — |
| Private networks, Docker bridge, cloud metadata (`169.254.169.254`) | No route: only `lo` exists. | `no-host-private-or-metadata-addresses`, `only-a-loopback-interface` | — |
| Egress with `EgressUnrestricted` / `egress: unrestricted` | **None.** The sandbox gets ordinary Docker bridge networking and can reach the internet, the LAN, the host's bridge address and cloud metadata. | — | Do not use it for untrusted code unless an external firewall you control constrains it. |
| Previews as an inbound path | Previews reach a sandbox port over the Docker exec channel, not the network, and only with a valid token. Each (sandbox, port) has its own upstream connection pool, bounded in size and idle time, and the dialler refuses an address that does not match the authorised route. | `TestProxyNeverReusesAConnectionAcrossRoutes` (unit), `TestPreviewServesAnExposedPort` | Revocation is per process (see §7). |

### Filesystem and data

| Attack | Defence | Tested | Residual |
|---|---|---|---|
| Reading host files | The guest filesystem is the image plus private tmpfs mounts; nothing from the host is mounted. | `host-files-are-invisible-to-the-guest` (host-local) | — |
| Path traversal and symlinks through `ReadFile` / `WriteFile` | Both run *inside* the sandbox as the sandbox user, so `..` and symlinks resolve within the guest's own filesystem, with that user's permissions. | `no-traversal-out-of-the-guest` | Traversal *within* the guest is permitted by design. |
| Malicious file names (shell metacharacters, newlines, leading `-`) | Paths are passed as `argv`, never interpolated into a shell. Paths must be absolute, so none begins with `-`. | `no-traversal-out-of-the-guest`, `TestExecRunsWithoutAShell`, `argv-is-never-a-shell-builtin` | — |
| Writing outside scratch space | Read-only root filesystem. | `TestWritesOutsideScratchAreRejected` | — |
| Data left behind for the next sandbox | Every sandbox has its own tmpfs mounts; `Destroy` removes the container. Re-creating a name produces a fresh sandbox. | `sandboxes-share-no-state` | `Create` on a stopped name replaces the container with a fresh one under the options of that call, rather than reviving the policy it was created under (`stopped-sandbox-is-replaced-by-create`). |
| Environment and credential leakage | The caller's own environment is not passed to the sandbox. Registry credentials and the preview key never enter a sandbox; the preview `Authorization` header is stripped before forwarding. | `sandboxes-share-no-state`, `TestProxyStripsTheCredentialBeforeForwarding` (unit) | Anything you pass with `WithEnv`, `Command.Env` or a file **is** visible to the untrusted code. Labels are visible to anyone with Docker access. |
| Malicious archives | openblox does not unpack archives. Unpacking inside the sandbox is contained like any other guest code. | — | Unpacking sandbox output *on the host* is outside openblox; treat it as untrusted input. |
| Hostile output | Output is returned as raw bytes, not interpreted. | — | Rendering it in a browser, feeding it to an LLM, or parsing it without limits is the caller's risk. See §7 on previews and origins. |

### Processes and time

| Attack | Defence | Tested | Residual |
|---|---|---|---|
| Fork bomb, PID exhaustion | `PidsLimit` (default 256). | `TestForkBombIsBoundedByTheProcessCap` | — |
| Command exceeding its timeout | Timeouts are clamped to a per-sandbox ceiling. On timeout or cancellation the command's process group is killed (SIGKILL) from inside the sandbox, and `Exec` returns `ErrTimeout` (or the context's error). | `TestExecHonoursTimeout`, `TestExecClampsTimeoutToCeiling`, `timed-out-command-kills-its-children`, `cancelled-command-is-not-reported-as-timeout`, `timeout-kill-is-scoped-to-its-own-command`, `kill-group-waits-for-a-late-group-record` (approximates the original race via a tight `Exec` timeout rather than forcing it; see the property's doc comment) | **Best effort against hostile code:** a process that calls `setsid`, or a guest that fills `/tmp` so the group record cannot be written, survives the kill (`known-escape-setsid-survives-the-timeout-kill`). It stays bounded by the CPU and PID caps, and is ended by the lifetime bounds or `Destroy`. |
| Client disconnect (Mode B) | The daemon's request context is cancelled, which kills the command as above. | `TestBrokerClientDisconnectKillsTheCommand` | Same as above. |
| Detached, orphaned and zombie processes | They live in the sandbox's own PID namespace, count against `PidsLimit`, and end with the sandbox. | `timeout-kill-is-scoped-to-its-own-command` | They survive individual commands by design (`StartProcess` relies on this). |
| Living forever | Idle timeout and max age, recorded on the container at creation. The activity timestamp is written as root on a root-owned tmpfs with the host's clock, so the guest cannot refresh or forge it. | `TestReapDestroysASandboxPastItsMaxAge`, `TestReapDestroysAnIdleSandbox`, `TestSandboxCannotForgeItsActivityTimestamp` | **Mode A: bounds are enforced only if your process calls `Reap` periodically.** `openbloxd` does this itself. |
| Guest stopping its own sandbox | Under gVisor the guest can kill its own PID 1. This only affects that sandbox; `Exec` then fails promptly and `Create` replaces it. | `crashed-sandbox-recovers-through-create` | Self-inflicted denial of service. |

### Resource exhaustion

| Attack | Defence | Tested | Residual |
|---|---|---|---|
| Memory exhaustion | cgroup memory limit, swap disabled (`MemorySwap = Memory`). | `TestMemoryHogIsKilledAndTheHostSurvives` | The limit is enforced approximately; about 1.4× the configured value has been observed resident before the kill. Size hosts with headroom. |
| CPU exhaustion | `NanoCPUs` quota per sandbox. | — (quota is asserted in `TestContainmentIsAppliedToTheRuntime`) | No fairness across sandboxes: N busy sandboxes use N × their quota. |
| Disk exhaustion | Root filesystem read-only; scratch is size-capped tmpfs drawn from the memory budget; no container-log output. | `TestFillingScratchHitsTheDiskCapNotTheHost` | `/dev/shm` is a separate tmpfs, bounded by the memory limit rather than `DiskBytes`. |
| Stdout/stderr flooding | Each stream is capped at `sandbox.MaxOutputBytes` (16 MiB) in memory; the rest is drained and discarded, `Result.Truncated` is set, and the command still completes. | `TestCappedBuffer*` (unit), `output-flood-is-capped-and-the-command-completes`, `TestBrokerReportsTruncatedOutput` | Concurrent execs each hold up to 32 MiB of output plus JSON encoding in `openbloxd`. `ReadFile` streams without a cap; its size is bounded by the sandbox's disk budget. |
| Too many sandboxes | `openbloxd`: `max_sandboxes` per profile (`429 at_capacity`). | `internal/daemon/capacity_test.go` (unit) | Mode A has no global cap. Neither mode caps the total across profiles; size the host for the sum. |
| Leaks from repeated create/destroy | Destroy removes the container; no host state is kept. | `destroy-removes-the-sandbox`, `host-retains-no-process-goroutine-or-descriptor` (host-local: goroutines, file descriptors, and a host `/proc` scan for processes still serving a destroyed sandbox) | — |

## Under Kata

Measured by `.github/workflows/kata.yml` (Kata 4.2.0, runtime-rs + QEMU,
hosted amd64 runner), first recorded 2026-09-22 in
[run 35783796144](https://github.com/blox-eng/openblox/actions/runs/35783796144).
Not merge-gating: gVisor is the default and the only runtime this project gates
on. Under Kata the guest reaches its own kernel inside a VM, so B1 and B2 above
do not apply; the boundary is the hypervisor. arm64 is not measured.

19 of 21 Core properties pass, and both host-local properties pass. The two
failures are below; all others pass, one host-local property measuring
something other than it does under gVisor.

| Property | Result | Class | What it means |
|---|---|---|---|
| `writable-mounts-are-noexec-nosuid` | FAIL | Real difference | The guest's `/dev/shm` is mounted `rw,relatime`, without `noexec` or `nosuid`, and a binary the guest copied there executed. `/tmp` and `/workspace`, which openblox mounts itself with `nosuid,nodev,noexec`, kept their flags. `/dev/shm` is left to Docker's default mount, whose flags `runsc` honours and Kata's guest does not show. Under Kata the guest can therefore run a binary it wrote, and setuid on that path is left to `no-new-privileges`. A defence-in-depth layer is lost, not the boundary: the guest already runs arbitrary code, as a non-root user with no capabilities (`no-capabilities` passes). Residual; the possible follow-up is for openblox to mount `/dev/shm` itself with the same flags. |
| `crashed-sandbox-recovers-through-create` | FAIL | gVisor-shaped | The property crashes the sandbox with `kill -9 1` from inside the guest, which assumes the guest can kill its own init. gVisor allows that; Linux, which is Kata's guest kernel, does not deliver SIGKILL to a PID namespace's init from inside that namespace, so the sandbox was still running 20 s later and the property failed before reaching its claim. Two consequences: the self-inflicted stop in *Guest stopping its own sandbox* above does not work this way under Kata, and the claim itself — `Exec` on a crashed sandbox fails promptly with `ErrStopped`, `Create` brings it back — is unmeasured under Kata. |

`host-retains-no-process-goroutine-or-descriptor` passes, but its host `/proc`
scan measures something different under Kata. Guest processes never appear in
the host's `/proc`; the process its positive control finds naming the live
sandbox is one of Kata's host-side processes (the shim, QEMU, `virtiofsd`),
whose command lines carry the container ID. Under Kata the property shows that
those are gone after `Destroy`, not that guest processes are — the VM boundary
keeps those off the host in the first place.

Predictions made before the first run
([specs/2026-09-22-kata-evidence.md](specs/2026-09-22-kata-evidence.md)):
host-local reports "cannot measure" — did not hold, for the reason above;
`kill-group-waits-for-a-late-group-record` may pass within its 100 ms timeout —
held; `known-escape-setsid-survives-the-timeout-kill` may differ in kind — did
not: it passes, meaning a `setsid` process survives the timeout kill under Kata
exactly as under gVisor, and the documented limit is the same.

## 7. Explicit non-goals and residual risks

- **Multi-tenancy.** openblox has no tenants, users or authorisation. In Mode B every
  member of `socket_group` can open, exec into, read from and destroy every sandbox,
  by name. Sandbox names are not secrets. If callers must not reach each other's
  sandboxes, that is enforced in front of openblox, not by it.
- **Side channels.** Sandboxes share CPUs, caches and memory bandwidth. Spectre-class
  and timing attacks between co-resident sandboxes are not addressed.
- **Fairness.** One sandbox can use its whole CPU and memory budget and slow its
  neighbours.
- **Preview content is attacker-controlled.** A preview serves whatever the guest's
  server returns, including HTML and JavaScript. Serve previews from an origin that
  shares no cookies or storage with your application (a separate registrable domain,
  not a subdomain of it), or a malicious preview can act as your application in the
  user's browser.
- **Preview revocation** is recorded only in the process that called `Revoke`. With
  several replicas, expiry is the only bound that always holds. Keep TTLs short.
- **Image supply chain.** The image is trusted. openblox warns (`openbloxd`) when a
  profile's image is not digest-pinned but does not refuse it.
- **Host hardening.** openblox does not configure the host, Docker, or gVisor. It
  verifies only that a runtime named `runsc` is registered, not what that runtime is.

## 8. Assumptions that must hold

1. `runsc` is a current gVisor release, registered with Docker under that name.
2. The Docker daemon is not reachable by untrusted parties, and no sandbox is given
   access to it by means outside openblox.
3. In Mode B, only processes that should control sandboxes are in `socket_group`,
   and nothing else runs as the `openbloxd` user.
4. Profiles and `WithEgress` do not enable `unrestricted` egress for untrusted code.
5. Secrets are never placed into a sandbox by environment, file or argument.
6. Output from a sandbox is treated as untrusted input wherever it goes next.

## 9. Verifying these claims yourself

```sh
make test               # unit tests, race detector
make test-integration   # the tests named above; needs Docker with runsc registered
go test -tags integration -run TestConformance ./pkg/docker/ -v   # the conformance suite, both tiers
```

The leak check's iteration count (`hostLeakIterations` in
`pkg/conformance/hostlocal.go`, 15 by default) is a package constant rather
than an environment variable, deliberately: a caller-supplied lever would let
a run be quietly made to measure less than it claims. To run a longer soak,
raise that constant in source and re-run just that property:

```sh
go test -tags integration -run 'TestConformance/host-retains-no-process-goroutine-or-descriptor' ./pkg/docker/ -v
```

Report anything that contradicts this document as a vulnerability — see
[SECURITY.md](SECURITY.md).
