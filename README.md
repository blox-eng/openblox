<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/openblox-mark-dark.svg">
  <img alt="openblox" src=".github/assets/openblox-mark.svg" width="76">
</picture>

# openblox

[![CI](https://github.com/blox-eng/openblox/actions/workflows/ci.yml/badge.svg)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/endpoint?url=https://openblox.sh/badges/tests.json)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Integration tests](https://img.shields.io/endpoint?url=https://openblox.sh/badges/integration.json)](https://github.com/blox-eng/openblox/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://openblox.sh/badges/coverage.json)](https://github.com/blox-eng/openblox/issues/10)
[![Lines of Go](https://img.shields.io/endpoint?url=https://openblox.sh/badges/loc.json)](ARCHITECTURE.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/blox-eng/openblox.svg)](https://pkg.go.dev/github.com/blox-eng/openblox)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-black.svg)](LICENSE)

Run untrusted, AI-generated code on your own hardware. 2,000 lines of Go over
Docker and [gVisor](https://gvisor.dev) — no control plane, no database, no
scheduler. A sandbox is a container, and the container is the state.

[Docs](https://openblox.sh) · [Getting started](https://openblox.sh/getting-started/) ·
[Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Sandbox image](image/README.md)

> **Status: pre-release.** The API is taking shape and will change.

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

That image is the [reference sandbox userland](image/README.md) openblox
publishes. Any image works, as long as it has a shell, a non-root default user,
and `nc` or `python3`.

## Why

Running code an LLM wrote, against files a user uploaded, is a hostile workload
wearing a friendly hat. The usual answers are a hosted sandbox platform — which
means your customers' data crosses someone else's boundary — or a plain
container, which shares a kernel with the host.

openblox takes the third option: a substrate small enough to read in an
afternoon, that you run yourself, with isolation supplied by gVisor rather than
by hope.

## Secure by default

The zero value of every option is the safe one. A sandbox created with no
options gets:

| | |
|---|---|
| **Isolation** | gVisor (`runsc`) — syscalls handled in user space, not by the host kernel |
| **Network** | no external interface, so no egress *and* no DNS side channel |
| **Filesystem** | read-only root, non-root user |
| **Resources** | bounded CPU, memory, disk, and process count |
| **Privileges** | all capabilities dropped, `no-new-privileges` |
| **Lifetime** | reaped when idle, destroyed at max age |

Forgetting an option can only make a sandbox more restrictive, never less.
Relaxing anything is explicit and greppable at the call site.

If the host cannot provide the requested isolation, `Create` fails with
`ErrRuntimeUnavailable`. It never silently falls back to a weaker boundary — a
sandbox that is quietly less isolated than you asked for is worse than no
sandbox, because you keep trusting it.

## What you get

| | |
|---|---|
| **Exec** | run a command with a per-call timeout, get stdout, stderr, exit code |
| **Files** | read and write inside the sandbox without a shell round-trip |
| **Processes** | start a detached background command, idempotently |
| **Preview links** | HMAC-signed reverse proxy to a port inside the sandbox |
| **Reaping** | idle timeout and max age, enforced without a scheduler |

## What it is not

- **Not multi-tenant.** No organizations, auth, billing, or metering. Tenancy is
  the caller's concern.
- **Not a fleet.** One host, one daemon.
- **No snapshot, fork, or pause/resume.** Stop and re-create from a baked image.
- **Not the fastest.** Correctness and containment over cold-start latency.

Those are deliberate. See [ARCHITECTURE.md](ARCHITECTURE.md) for the reasoning.

## Install

```bash
go get github.com/blox-eng/openblox
```

Requires Go 1.25+, Docker Engine, and gVisor (`runsc`) registered as a Docker
runtime. The [getting started guide](https://openblox.sh/getting-started/) covers
installing `runsc` and wiring it up.

## Status

The badges above are measured from the source on every deploy, not typed here —
size, test counts, and coverage cannot drift from the code that produced them.
Two direct dependencies (`docker/docker` and `containerd/errdefs`). Every release
publishes a multi-architecture sandbox image with an SBOM and build provenance.
CI runs lint, tests, and `govulncheck`, gating on newly reachable
vulnerabilities. The integration suite runs there too, against a real gVisor
daemon on a hosted runner — including the adversarial cases that try to break
the resource caps.

Honest about the gaps: importing the library still means giving your service
access to the Docker socket, which is root-equivalent on the host. `openbloxd`
closes that — a daemon that owns the socket and exposes only openblox's own
surface, policy fixed daemon-side and not settable per request — see
[Security](https://openblox.sh/security/#deploying-the-policy-broker-openbloxd).
The [open issues](https://github.com/blox-eng/openblox/issues) are the honest
roadmap for what's left.

Written for [Blox](https://blox.bg), where it is the only sandbox backend and
replaced a hosted platform. Its own production rollout is gated on migrating its
callers off the Docker socket and onto `openbloxd`. The API is unstable
pre-1.0 — expect breaking changes on minor versions. No support SLA.

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Commits follow
[Conventional Commits](https://www.conventionalcommits.org/); CI enforces it.

## License

MIT — see [LICENSE](LICENSE).
