# openblox

Secure sandboxes for running untrusted, AI-generated code.

openblox is a small Go library over Docker and [gVisor](https://gvisor.dev). There is
no control plane, no database, and no scheduler — a sandbox is a container, and
the container is the state.

> **Status: pre-release.** The API is taking shape and will change.

The image above is the [reference sandbox userland](image/README.md) openblox
publishes; any image works, as long as it has a shell, a non-root default user,
and `nc` or `python3`.

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

## Why

Running code an LLM wrote, against files a user uploaded, is a hostile workload
wearing a friendly hat. The usual answers are a hosted sandbox platform — which
means your customers' data crosses someone else's boundary — or a plain
container, which shares a kernel with the host.

openblox takes the third option: a substrate small enough to read in an
afternoon, that you run yourself, with hardware-grade isolation supplied by
gVisor rather than by hope.

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

## What it is not

- **Not multi-tenant.** No organizations, auth, billing, or metering. Tenancy is
  the caller's concern.
- **Not a fleet.** One host, one daemon.
- **No snapshot, fork, or pause/resume.** Stop and re-create from a baked image.
- **Not the fastest.** Correctness and containment over cold-start latency.

Those are deliberate. See [ARCHITECTURE.md](ARCHITECTURE.md) for the reasoning.

## Requirements

- Go 1.25+
- Docker Engine
- gVisor (`runsc`) registered as a Docker runtime

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — design, state model, security model
- [SECURITY.md](SECURITY.md) — threat model and how to report a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and conventions

## License

[MIT](LICENSE)
