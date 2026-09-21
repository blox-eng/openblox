<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/openblox-mark-dark.svg">
  <img alt="openblox" src=".github/assets/openblox-mark.svg" width="76">
</picture>

# openblox

[![CI](https://github.com/blox-eng/openblox/actions/workflows/ci.yml/badge.svg)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/endpoint?url=https://docs.openblox.sh/badges/tests.json)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Integration tests](https://img.shields.io/endpoint?url=https://docs.openblox.sh/badges/integration.json)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://docs.openblox.sh/badges/coverage.json)](https://github.com/blox-eng/openblox/issues/10)
[![Lines of Go](https://img.shields.io/endpoint?url=https://docs.openblox.sh/badges/loc.json)](ARCHITECTURE.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/blox-eng/openblox.svg)](https://pkg.go.dev/github.com/blox-eng/openblox)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-black.svg)](LICENSE)

Run untrusted, AI-generated code on your own hardware. Under 3,000 lines of Go over
Docker and [gVisor](https://gvisor.dev) — no control plane, no database, no
scheduler. A sandbox is a container, and the container is the state.

[openblox.sh](https://openblox.sh) · [Docs](https://docs.openblox.sh) ·
[Getting started](https://docs.openblox.sh/getting-started/) ·
[Production](https://docs.openblox.sh/production/) · [Architecture](ARCHITECTURE.md) ·
[Threat model](THREAT_MODEL.md) · [Security](SECURITY.md) · [Releasing](RELEASING.md) ·
[Discord](https://discord.gg/ksxTebDjj)

> **Status: pre-release (`0.x`).** The API will change; breaking changes bump the
> minor version and are listed in the [changelog](CHANGELOG.md).

## Quick start

Needs Linux, Docker, and gVisor registered as the `runsc` runtime
([how](https://docs.openblox.sh/getting-started/#prerequisites)).

```bash
go get github.com/blox-eng/openblox
```

```go
backend, err := docker.New()
if err != nil {
    return err
}
defer backend.Close()

// No options: no network, non-root, read-only rootfs, capped CPU/memory/PIDs,
// gVisor runtime, reaped when idle.
sb, err := backend.Create(ctx, "session-1",
    sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"))
if err != nil {
    return err
}

res, err := sb.Exec(ctx, sandbox.Command{
    Argv: []string{"python3", "-c", "print(6 * 7)"},
})
fmt.Println(string(res.Stdout)) // 42
```

That image is the [reference sandbox userland](image/README.md); any image that
meets [the contract](https://docs.openblox.sh/image/) works. `:latest` is fine here —
pin a digest anywhere it matters.

## In production: run `openbloxd`

The quick start imports the library, so **your process holds the Docker socket,
which is root-equivalent on the host.** In production, run the `openbloxd` daemon
on the host instead. It owns the socket, and your application talks to it over a
Unix socket with `pkg/brokerclient` — the same `Backend` interface, no Docker
access:

```
application ──unix socket──► openbloxd ──Docker API──► Docker + gVisor ──► sandbox
(no Docker access)           (policy per profile,
                              not settable by requests)
```

Deployment, verification, compatibility, upgrades and troubleshooting:
**[Running in production](https://docs.openblox.sh/production/)**.

## Where this sits

openblox is the layer *below* a sandbox platform, not a smaller one.

```
  your scheduler, your tenancy, your API    ← yours to build, if you ever need it
  ──────────────────────────────────────
  openblox                                  ← isolation, done correctly
  ──────────────────────────────────────
  Docker + gVisor                           ← the boundary itself
```

One rule decides what belongs here:

> **How a sandbox is isolated is openblox's problem.
> Which sandbox runs where is yours.**

Egress, capabilities, filesystem, resource caps, lifetime, runtime: openblox's.
Placement, queueing, tenancy, metering, snapshots: not openblox's, and not
planned. Build those on top when something actually asks for them. That is what
a lower layer is for, and it is why there is no control plane to adopt first.

The comparison is `libvirt`, not OpenStack.

## Restrictive by default

The zero value of every option is the most restrictive one. A sandbox created
with no options gets:

| | |
|---|---|
| **Isolation** | gVisor (`runsc`) — syscalls handled in user space, not by the host kernel |
| **Network** | no external interface, so no egress *and* no DNS side channel |
| **Filesystem** | read-only root, non-root user (root is refused), `noexec` scratch |
| **Resources** | bounded CPU, memory (no swap), disk, process count, and captured output |
| **Privileges** | all capabilities dropped, `no-new-privileges` |
| **Lifetime** | commands killed at their timeout; sandboxes reaped when idle and at max age |

Relaxing anything is explicit and greppable at the call site. If the host cannot
provide gVisor, `Create` fails with `ErrRuntimeUnavailable`; it never falls back
to a weaker boundary.

These are isolation *measures*, not a guarantee: the boundary is gVisor's, and
[THREAT_MODEL.md](THREAT_MODEL.md) lists what is defended, the test behind each
claim, and what is not defended.

**Two levels of the same guarantee.** In the library, *your* code chooses: the
defaults are safe, and every relaxation is explicit and greppable at the call
site. Through [`openbloxd`](https://docs.openblox.sh/security/#deploying-the-policy-broker-openbloxd)
the choice stops being the caller's at all — profiles live in the daemon's
config file and no request can reach them. A caller names a profile. It cannot
name an image, a runtime, a user, an egress policy, or a resource cap.

That is the difference between weakening being **visible** and weakening being
**unreachable**, and it is the whole reason the daemon exists.

## What you get

| | |
|---|---|
| **Exec** | run a command with a per-call timeout, get stdout, stderr, exit code |
| **Files** | read and write inside the sandbox without a shell round-trip |
| **Processes** | start a detached background command, idempotently |
| **Preview links** | HMAC-signed reverse proxy to a port inside the sandbox |
| **Reaping** | idle timeout and max age, enforced without a scheduler |
| **`openbloxd`** | a policy broker so callers never touch Docker |

## When not to use it

- **You need tenants isolated from each other at the API.** Every caller of one
  `openbloxd` can reach every sandbox; tenancy is yours to enforce in front of it.
- **You need a fleet.** One host, one daemon. No scheduling, no fairness.
- **You need a separate kernel per workload** (hardware virtualisation), or
  protection from side channels between co-resident sandboxes.
- **You need snapshots, fork, pause/resume, or sub-second cold starts.**
- **You cannot run Linux with gVisor**, or cannot keep `runsc` patched.

Most of these are placement rather than isolation, which the rule above puts on
your side of the line; the rest are trades made deliberately. None are gaps
waiting to be filled. They are the boundary that keeps openblox small enough to
be worth reading, and requests to cross it get declined on that basis. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the reasoning.

## Supported

Linux on `amd64` and `arm64`, both tested natively in CI against a real gVisor
runtime. Docker Engine with `runsc` registered. Go 1.25+ for library users. The
[compatibility matrix](https://docs.openblox.sh/production/#compatibility) covers
`openbloxd`, clients, images, Docker and gVisor.

## Status

The badges above are measured from the source on every deploy, not typed here.
Three direct dependencies (`docker/docker`, `containerd/errdefs`, `yaml.v3`).

CI runs lint, race-enabled tests, CodeQL and `govulncheck` (gating on newly
reachable vulnerabilities), plus the integration and adversarial suites against a
real gVisor runtime on amd64 and arm64 — including attacks on the network,
filesystem, privileges, resource caps and timeouts.

Every release is cut by CI from a verified commit. The `openbloxd` binaries are
reproducible and ship with SBOMs; binaries and the sandbox image carry Sigstore-signed
build provenance. [RELEASING.md](RELEASING.md#verifying-a-release) shows how to
verify them.

Written for [Blox](https://bloxng.com), where it is the only sandbox backend and
replaced a hosted platform. Its own production rollout is gated on migrating its
callers off the Docker socket and onto `openbloxd`. No support SLA.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Please do not
open a public issue.

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Commits follow
[Conventional Commits](https://www.conventionalcommits.org/); CI enforces it.
For a question that is not an issue, there is a
[Discord](https://discord.gg/ksxTebDjj).

## License

MIT — see [LICENSE](LICENSE).

The `openbloxd` binaries are statically linked, so they also carry the code of
their dependencies. Every release attaches `THIRD_PARTY_LICENSES.txt` with the
full licence text of each linked module, generated from what is actually in the
binary. Build it yourself with `make licenses`.
