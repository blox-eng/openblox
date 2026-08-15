# Architecture

openblox runs untrusted, machine-generated code in disposable Linux sandboxes.

It is a **Go library first** and a daemon second. There is no control plane, no
database, and no scheduler. A sandbox is a container; the container is the state.

## Non-goals

Stating these up front, because every one of them is a place a sandbox project
grows into a platform:

- **No multi-tenant SaaS.** No organizations, billing, usage metering, or audit log.
- **No scheduler.** One host, one daemon. Not a fleet.
- **No memory snapshot / fork / pause-resume.** Stopping and re-creating from a
  baked image is the supported lifecycle.
- **No sub-second cold starts.** Correctness and containment over latency.
- **No database.** Container labels are the registry.

If you need those, you want a hosted platform. That is a legitimate need and
openblox is the wrong tool for it.

## Shape

```
   consumer (Go)                  consumer (anything)
        │                                 │
        │ imports                         │ HTTP
        ▼                                 ▼
  ┌────────────────────┐          ┌────────────────────┐
  │  pkg/sandbox       │◄─────────│  cmd/openbloxd     │
  │  the library       │          │  the policy broker │
  └─────────┬──────────┘          └────────────────────┘
            │
            │ Backend interface
            ▼
  ┌────────────────────┐
  │  Docker Engine API │
  │  runtime: runsc    │  ← gVisor: the isolation boundary
  └────────────────────┘
```

The library is the product. `openbloxd` holds no *sandbox* behaviour the library
doesn't — if a way to run code can only be reached over HTTP, it's in the wrong
place. It does hold *policy*, and that is the point: the daemon exists so a
caller can create sandboxes without holding the Docker socket, which is only
true if the isolation policy lives on the daemon's side of the socket. Options
such as `WithRuntime` and `WithEgress` are therefore configuration in
`openbloxd` and are unreachable from a request.

## Core interfaces

Two, deliberately small:

- **`Backend`** — provisions and destroys sandboxes. Knows about the host runtime.
- **`Sandbox`** — a live instance: execute, read/write files, run background
  processes, expose a port.

Everything else is options structs and errors. A second backend
(Firecracker, Kata, a remote host) must be implementable without changing either
interface — that constraint is what keeps the abstraction honest, not a promise
that we'll ship one.

## State model

Three states, not twenty-two:

```
  (none) ──create──► RUNNING ──stop──► STOPPED ──destroy──► (none)
                        │                  │
                        └──────destroy─────┘
                        │
                        └──► ERROR
```

Docker already owns process supervision, restart, and health. openblox does not
maintain a parallel state machine over it, and does not reconcile a desired state
against an observed one — there is no controller loop, because there is no fleet
to reconcile. `Create` is synchronous and either returns a usable sandbox or an
error.

The idle reaper is the one background loop: it sweeps containers by label and
enforces two bounds — **idle timeout** (no exec since T) and **max age** (created
before T). Both default conservative. Each sandbox carries its own bounds as
labels, so a reaper reclaims sandboxes it knows nothing about, including ones
created before it started. The reaper is idempotent and safe to run in multiple
processes, because it acts on Docker, which arbitrates.

The two bounds are not redundant. Idle handles the common case — a sandbox nobody
came back to. Max age catches what idle cannot: a sandbox kept permanently warm by
a wedged or deliberately busy background process is never idle, and would
otherwise live forever. Max age is therefore the bound that must hold
unconditionally, and it is enforced purely from the creation label — no exec, no
cooperation from the guest.

### Where the activity timestamp lives

Idle needs a "last used" time, and there is nowhere obvious to put it. Docker
exposes no last-exec timestamp, and container labels are immutable after create.
Tracking it in process would work but would break the property that any process
can manage any sandbox, which is the reason openblox keeps no state of its own.

So the timestamp lives inside the sandbox, in a dedicated tmpfs at
`/run/openblox` mounted `mode=0755` and owned by root while the sandbox itself
runs unprivileged. openblox writes it after each exec, as root, using the *host's*
clock. Two consequences follow, both deliberate:

- Code in the sandbox can read the timestamp but cannot write it, so it cannot
  refresh its own idle deadline and evade reaping. Nor can it shift the deadline
  by moving the guest clock, since the value is the host's.
- This is the only exec openblox runs as root. It is a single write, with all
  capabilities dropped and a read-only root filesystem, and it exists to make the
  idle bound real rather than advisory.

The write is fire-and-forget: idle reaping is resource hygiene, and a failed
bookkeeping write must not fail a caller's command. If the timestamp is missing
for any reason, the idle clock falls back to the creation time — which reaps
sooner, not later.

## Session identity

Sandboxes are addressed by a caller-supplied name, hashed into a container name
and stored in labels. Two calls with the same name reach the same sandbox until it
is reaped. openblox does **not** interpret the name — tenancy is the caller's
concern, and baking a tenant model into a sandbox library is how you end up with a
control plane.

## Security model

The isolation boundary is **gVisor (`runsc`)**, not the container runtime's
namespaces. A shared-kernel container is not a sufficient boundary for
attacker-controlled native code, which is the workload openblox is built for.

Enforced at create, non-optional:

| Control | Why |
|---|---|
| `runsc` runtime | syscalls handled in user space, not passed to the host kernel |
| `NetworkMode: none` | no external interface, so no egress *and* no DNS side channel (loopback stays, see Preview links) |
| CPU / memory / disk caps | a crafted input must not exhaust the host |
| `PidsLimit` | fork-bomb containment |
| non-root user, read-only rootfs | reduce what a successful RCE can reach |
| all capabilities dropped, `no-new-privileges` | no path to escalate inside the guest |

Two invariants that are easy to violate and fatal when violated:

1. **The Docker socket is never mounted into a sandbox.** Socket access is host root.
2. **Egress is off by default.** Any future allow-list is opt-in per sandbox and
   must not be reachable by the sandboxed code itself.

Files move over the Docker control channel, not the network, which is why
`NetworkMode: none` costs nothing functionally.

### What openblox does not protect against

Stated plainly, because a security section that only lists wins is marketing:

- A gVisor escape. We inherit gVisor's threat model and its CVEs.
- A malicious or backdoored sandbox **image**. Image supply chain is the caller's
  responsibility — pin digests.

  openblox pulls an image when it is absent and otherwise uses what is already on
  the host. Pull-if-absent, not always-pull, is the deliberate choice: the image
  is the guest's entire userland, so re-resolving a mutable tag on every create
  would let the code running in a sandbox change without anything in the caller's
  configuration changing. The corollary is that a tag is only as trustworthy as
  the moment it was first pulled, which is why `WithImage` says to pin a digest.
- Side channels between co-resident sandboxes on the same host.
- Anything the caller does with the results. openblox contains execution; it does
  not sanitise output.

## Preview links

A sandboxed process can be reached on a port through a signing proxy. Tokens are
HMAC-signed, carry an expiry, and are individually revocable.

The token travels in a **request header, never a query parameter** — query strings
leak into access logs, browser history, and `Referer`. A proxy that fails to verify
a token is a direct route into the sandbox, so the negative paths (tampered,
expired, revoked, wrong port) are tested before the positive one.

Tokens are self-describing and validated by local HMAC, so serving a preview
consults nothing. That is what lets the proxy be a handler the caller mounts on
their own server rather than a service with a database behind it. The cost is that
**revocation is best-effort** — a revocation lives only in the process that
recorded it — so expiry is the bound that always holds and lifetimes are short.

### Reaching a port with no network

The sandbox has no external interface, so there is no address to connect to. The
proxy instead dials **through the runtime's exec channel**: a relay runs inside the
sandbox, connects to `127.0.0.1:port` there, and its stdin and stdout become the
two directions of a `net.Conn`. `httputil.ReverseProxy` sits on top, so ordinary
HTTP, streaming responses, and protocol upgrades all work unmodified.

The alternative — attaching the sandbox to a Docker network, even an internal one —
was rejected. An interface brings back a DNS resolver to abuse as a covert channel
and makes sandboxes reachable from each other, undoing the containment openblox
exists for. Everything already travels the control channel; this is one more thing
that does.

One consequence is load-bearing and easy to undo by accident: the container is
created with `NetworkMode: "none"` but **not** `Config.NetworkDisabled`. The latter
looks like belt-and-braces and is not — under gVisor it removes the network stack
outright, including loopback, so nothing inside the sandbox can bind a port at all.
`NetworkMode: "none"` is what provides the containment; loopback reaches nothing
but the sandbox itself. A unit test pins this.

The relay needs either `nc` or `python3` in the image, tried in that order.
Neither is universal — busybox images have `nc` and often no Python, slimmed
language images frequently have the reverse — and shipping a forwarder in is not
an option, because every writable mount is `noexec`, deliberately. An image with
neither fails the dial loudly rather than hanging or returning an empty body that
would read as a broken server.

## Repository layout

```
pkg/sandbox/       the library — Backend, Sandbox, options, errors
pkg/preview/       preview-link signing + reverse proxy
pkg/brokerapi/     the wire types openbloxd speaks
pkg/brokerclient/  a Backend that reaches openbloxd instead of Docker
cmd/openbloxd/     the policy broker
internal/daemon/   openbloxd's internals — config, routes, policy
deploy/            systemd unit and reference config
```

`internal/` is load-bearing: everything outside it is API we are promising to keep.
