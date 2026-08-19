# openblox

Secure sandboxes for running untrusted, AI-generated code.

openblox is a small Go library over Docker and [gVisor](https://gvisor.dev). There is no
control plane, no database, and no scheduler — a sandbox is a container, and the
container is the state.

```go
backend, err := docker.New()
if err != nil {
    return err
}
defer backend.Close()

// No options: no network, non-root, read-only rootfs, capped CPU/memory/PIDs,
// gVisor runtime, reaped when idle.
sb, err := backend.Create(ctx, "session-1")
if err != nil {
    return err
}

res, err := sb.Exec(ctx, sandbox.Command{
    Argv: []string{"python3", "-c", "print(6 * 7)"},
})
fmt.Println(string(res.Stdout)) // 42
```

!!! warning "Status: pre-release"
    The API is taking shape and will change.

## Why

Running code an LLM wrote, against files a user uploaded, is a hostile workload wearing
a friendly hat. The usual answers are a hosted sandbox platform — which means your
customers' data crosses someone else's boundary — or a plain container, which shares a
kernel with the host.

openblox takes the third option: a substrate small enough to read in an afternoon, that
you run yourself, with isolation supplied by gVisor rather than by hope.

## Where this sits

openblox is the layer *below* a sandbox platform, not a smaller one.

```
  your scheduler, your tenancy, your API    ← yours to build, if you ever need it
  ──────────────────────────────────────
  openblox                                  ← isolation, done correctly
  ──────────────────────────────────────
  Docker + gVisor                           ← the boundary itself
```

!!! quote "The rule"
    **How a sandbox is isolated is openblox's problem.
    Which sandbox runs where is yours.**

Egress, capabilities, filesystem, resource caps, lifetime, runtime: openblox's.
Placement, queueing, tenancy, metering, snapshots: not openblox's, and not planned.
Build those on top when something actually asks for them. That is what a lower layer
is for, and it is why there is no control plane to adopt first.

The comparison is `libvirt`, not OpenStack.

## What you get

<div class="grid cards" markdown>

-   **A container, not a platform**

    No API server, no database, no runner service, no key. `docker ps` shows your
    sandboxes; `docker rm` destroys them.

-   **Safe by default**

    The zero value of every option is the safe one. No network, non-root, read-only
    rootfs, bounded CPU, memory and PIDs.

-   **Previews without a network**

    A signed, expiring URL to a port inside a sandbox that has no network interface —
    reached over the exec channel, not the network.

-   **Reaped, not leaked**

    Idle timeout and max age, enforced against a timestamp the sandbox itself cannot
    forge.

</div>

## What it is not

- **Not multi-tenant infrastructure.** There is no scheduler and no multi-node story.
  One host, many sandboxes.
- **Not a snapshot/fork/resume engine.** Stop and re-create from a baked image.
- **Not a substitute for a threat model.** Read the [security model](security.md) and
  decide whether its guarantees match your workload.

The first two are the rule above, applied: they are placement, not isolation. They
are not gaps waiting to be filled.

## Next

- [Quick start](getting-started.md) — install, prerequisites, a working example
- [Security model](security.md) — what is isolated, how, and what is *not* claimed
- [The image contract](image.md) — what an image must provide
