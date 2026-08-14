# openbloxd: a policy broker for the Docker API

Design for [openblox#2](https://github.com/blox-eng/openblox/issues/2). Written 2026-08-15.

## The problem

openblox is a library, so the process that imports it talks to the Docker daemon
and needs the socket. When that process runs in a container — the common
deployment — mounting `/var/run/docker.sock` grants it root-equivalent access to
the host. Anyone who can make it issue a Docker API call can bind-mount `/` or
start a privileged container and step onto the host. The blast radius exceeds the
sandbox openblox exists to provide.

A filtering socket proxy does not close this. Those proxies allow or deny a
verb, and `POST /containers/create` is the dangerous verb: `Binds`, `Privileged`,
`PidMode` and `Runtime` are fields inside a request the proxy already permitted.

`openbloxd` owns the Docker connection and exposes only openblox's own surface.
Compromising a caller then buys sandboxes, which the caller can create by design,
rather than the host.

## What the field does

Every system that solved this converged on admin-defined profiles that a request
selects by name.

| System | Where policy lives | What the caller sets |
|---|---|---|
| k8s SIG `agent-sandbox` | `SandboxTemplate` — admin-defined podTemplate and networkPolicy | A `SandboxClaim` naming `spec.sandboxTemplateRef` |
| E2B | Template, built out of band; CPU and RAM fixed at build time | Which template |
| Docker Sandboxes | Host policy file; egress through a host proxy | Nothing that loosens it; local deny rules still apply |
| Daytona | Org quotas in the control plane | Runner DTO accepts image ref, registry auth, CPU, memory, CIDR allow-lists |
| Kata/CoCo `genpolicy` | Policy delivered to the trusted in-guest agent | Nothing; policy matches on payload fields |

Two findings shaped this design.

Confidential Containers derives issue #2's argument independently: constraining
the RPC verb alone is inadequate, because a policy must examine payload fields —
the image digest, the command arguments. Its trust-boundary lesson is the one
that matters here. Policy is enforced in the trusted component that receives it
from a secure source, never in the caller.

Daytona is a cautionary tale rather than a model. Its runner owns the Docker
connection but trusts the control plane, so the runner's create DTO re-exports
image references, registry credentials and network allow-lists as request fields.
That is sound when a separate control plane holds the policy. openbloxd has no
separate control plane, so copying that surface would rebuild the hole. Take
Daytona's split, not its runner API.

## Architecture

```
  mcpblox (container, uid 1001)          openbloxd (host)
  ┌──────────────────────────┐           ┌────────────────────────┐
  │ brokerclient             │──socket──►│ policy: profiles only  │
  │   (implements Backend)   │           │ pkg/sandbox + docker   │
  │ preview.Handler          │           └───────────┬────────────┘
  └──────────────────────────┘                       │ docker.sock
        ▲ browser-facing HTTP                        ▼
                                              Docker Engine, runsc
```

The caller keeps the browser-facing surface, the daemon keeps the dangerous one,
and neither holds both. openbloxd has one listener and no route a browser can
reach. The caller has no Docker access.

**openbloxd runs as a host systemd unit, not a container.** Running it as a
container with `docker.sock` mounted would move the root-equivalent mount to a
smaller and better-audited process — a real improvement, but not the clean story.
As a systemd unit under a `docker`-group user, no container on the box holds the
socket, and `/run/openbloxd` is the only thing crossing into the compose stack.
The cost is that openbloxd deploys outside the compose flow, so `release.yml`
does not carry it.

## Transport

A Unix socket, and nothing else, in v1. Authentication is filesystem permissions;
`SO_PEERCRED` records the peer's uid and gid for the audit log.

mTLS would add nothing here at real cost. A Unix socket is a kernel object with
no wire to intercept, and mTLS brings a CA, issuance and rotation — expired
certificates have caused more outages than socket permissions have caused
breaches.

The design's honest weakness is that filesystem permissions are coarse. Anything
in the `openbloxd` group reaches the full surface, with no per-caller
distinction. That matters only when two callers need different privileges, which
is what profile-to-identity binding is reserved for. Recording the peer uid from
day one means the identity exists before it is enforced. Under user-namespace
remapping the peer uid is the remapped one; compose without userns, the current
deployment, makes container uid 1001 host uid 1001.

Two deployment rules follow:

- Mount the socket's **directory**, not the socket file. Bind-mounting the file
  leaves the container holding a stale inode after the daemon restarts and
  recreates it.
- The daemon creates the socket 0660 with explicit ownership and refuses to start
  if it cannot set them. A world-writable socket is the one way this design
  fails, so make it impossible to reach by accident.

If the caller is ever separated from the Docker host, socket-only stops working
loudly rather than degrading quietly. That is the correct failure.

## Configuration

```yaml
socket: /run/openbloxd/openbloxd.sock   # 0660, group openbloxd
profiles:
  code-exec:
    image: ghcr.io/blox-eng/blox-sandbox@sha256:…
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: 2048
    disk_mb: 1024
    max_processes: 256
    idle_timeout: 30m
    max_age: 4h
    default_timeout: 60s
    max_timeout: 10m
    registry_auth:
      username: …
      password: …
  browser:
    image: ghcr.io/blox-eng/blox-browser@sha256:…
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: 4096
    disk_mb: 2048
    max_processes: 256
    idle_timeout: 30m
    max_age: 4h
```

Registry credentials live here, which closes openblox's `ImagePull` gap: today it
sends no auth, so a private image must already be in the local store. The
credentials never leave the daemon and are never a request field.

An image given as a tag rather than a digest is logged as a warning at startup. A
tag can be repointed by whoever controls the registry, and the image is the
sandbox's entire userland.

## The rule that makes or breaks it

`WithRuntime` and `WithEgress` are daemon configuration. Three rules carry that
guarantee.

**A request naming a policy field is rejected with 400, never ignored.** JSON
decoding is strict and unknown fields are errors. Silently ignoring a field is
how a closed hole reopens, because the caller looks like it is being obeyed.

**A profile resolves once, at create, from configuration alone.** No code path
lets a request value reach `Spec.Runtime` or `Spec.Egress`. This is a property to
test, not a convention to remember.

**Create with an existing name but a different profile is a 409.**
`Backend.Create` returns the live sandbox when the name exists, so without this
check a request for `browser` could receive a `code-exec` sandbox. The daemon
labels each sandbox with its profile and refuses the mismatch.

The library keeps both options unchanged. A library caller already holds the
socket and can start a privileged container directly, so removing the option
would take away a legitimate knob without removing any capability. The broker's
guarantee comes from what it declines to expose.

## HTTP surface

```
POST   /sandboxes                       {name, profile, env?, labels?} → Info
GET    /sandboxes                       → []Info
GET    /sandboxes/{name}                → Info
DELETE /sandboxes/{name}
POST   /sandboxes/{name}/stop
POST   /sandboxes/{name}/exec           {argv, env, dir, timeout} → {stdout, stderr, exit}
PUT    /sandboxes/{name}/files/{path}   body = content
GET    /sandboxes/{name}/files/{path}   → content
POST   /sandboxes/{name}/processes      {name, argv, env, dir}
GET    /sandboxes/{name}/dial/{port}    Upgrade → 101, raw stream
GET    /profiles                        → names and lifetime bounds
```

Paths carry no version prefix. The daemon and its client ship from one repo and
speak over a local socket, so no independently versioned consumer needs
protecting. A header can version the surface later without baking a guess into
every path.

`env` and `labels` remain request fields because neither weakens isolation. They
are the caller's bookkeeping.

Per-command `Timeout` remains a request field. The daemon clamps it to the
profile's `max_timeout` through the library's existing `ResolveTimeout`, so a
caller can only narrow it.

`GET /profiles` exists for one reason. mcpblox enforces a reaper-first invariant:
openblox's idle timeout must exceed the manager's `IdleTTL`, or a cached handle
points at a destroyed sandbox. It checks this today by reading its own
`openblox.idle_timeout_minutes`, a key that stops being authoritative once the
daemon owns lifetime. Without this endpoint the check silently becomes a check on
nothing.

## Previews

`preview.Handler` depends on one interface, `Dialer` — `DialPort(ctx, name, port)
(net.Conn, error)`. It needs a byte stream, not Docker access.

So the daemon exposes `DialPort` as a connection upgrade, and the caller runs
`preview.Handler` unchanged over a broker-backed dialer. The daemon keeps exactly
one listener and never faces a browser.

Serving previews from the daemon instead would give the process holding
root-equivalent Docker access a browser-facing HTTP port — a second and much
larger attack surface on precisely the wrong process.

`Expose` and `Revoke` need no daemon endpoint at all. `Expose` touches Docker
nowhere: it signs a name, a port and an expiry, and opens nothing. So the client
implements both locally through `WithPreviews(key, baseURL)`, and the signing key
lives in exactly one process — the one that also verifies it. The daemon holds no
preview configuration and no key.

`DialPort` is therefore the whole of the daemon's involvement in previews, and it
is the only part that genuinely needs Docker.

## Client

`pkg/brokerclient`. Its type satisfies `sandbox.Backend`, its handle satisfies
`sandbox.Sandbox`, and it satisfies `preview.Dialer`, so
`preview.NewHandler(client, signer)` needs no adapter. It takes the same
`WithPreviews(key, baseURL)` option the Docker backend takes, and mints preview
credentials locally. The `Backend` and
`Sandbox` interfaces were built so a second backend could be written without
changing them; this is that second backend.

`Backend.Create` takes `...CreateOption`, and the client cannot honour the
policy-bearing ones. Dropping them silently would repeat the daemon's sin one
layer up, so the client resolves the options into a `Spec`, compares the
policy-bearing fields against the library defaults, and fails:

```
openbloxd: runtime is daemon policy and cannot be set per-request;
configure it in the profile
```

Profile selection gets its own option, `brokerclient.WithProfile("browser")`, so
the one legitimate choice is explicit rather than smuggled through a label.

## Errors

`ErrNotFound` maps to 404, `ErrInvalid` to 400, a profile conflict to 409, and
anything else to 500 with the detail logged rather than returned — the discipline
`proxyError` already sets. The client maps the codes back to the same sentinel
errors, so existing `errors.Is` checks keep working.

## Testing

Run the existing `pkg/docker` integration suite against `brokerclient` instead of
`docker.Backend`. One interface, one suite: "the broker behaves identically"
becomes something CI checks on the hosted gVisor runner that already gates merge
(#3).

Add an adversarial table in the spirit of #5. Request bodies carrying `runtime`,
`privileged`, `binds`, `pid_mode`, `user` and `cpus`, plus unknown profiles and
profile mismatches. Each asserts a 4xx and, more importantly, asserts that no
value reached the resolved `Spec`.

Unit tests cover socket permission refusal, strict decoding, profile resolution
and the client's policy-option rejection.

## What this changes in mcpblox

`OpenbloxConfig` loses `Image`, `Runtime`, `CPUs`, `MemoryBytes`, `DiskBytes`,
`IdleTimeout`, `MaxAge` and `AllowEgress`. Every one becomes profile
configuration. It keeps `PreviewSigningKey` and `PreviewBaseURL`, which are
genuinely its own.

`resolveSandboxImage()` and `defaultSandboxImage` go away, because which image a
sandbox runs stops being mcpblox's business. That retires the pin-drift guard in
blox 1d6bbc4a7, which stays load-bearing until this migration lands and then
becomes moot: the end state removes the class of bug rather than guarding it.

## Rollout

Four steps, each revertible on its own.

1. openblox ships `cmd/openbloxd` and `pkg/brokerclient` with tests. Nothing
   deployed.
2. tekom runs openbloxd alongside the existing setup. mcpblox stays on the
   library path.
3. tekom switches mcpblox to `brokerclient` and removes the `docker.sock` mount
   and `group_add: 989`. Verify `execute_code` and the browser sandbox.
4. Soak, then enable on prod with the socket never mounted. Close blox#2672 with
   the outcome.

The library path stays selectable by configuration for one release, so step 3
reverts without a rebuild.

## A documented rule this design breaks

`ARCHITECTURE.md` says openbloxd "is a transport wrapper over it and must never
hold logic the library doesn't. If a behaviour can only be reached over HTTP,
it's in the wrong place."

This design breaks that deliberately. Policy resolution is logic the library does
not have, and it lives only in the daemon. Amend the rule: the daemon holds no
sandbox behaviour the library lacks, but it does own policy, because policy is
what a broker is for.

## Out of scope

- Binding profiles to caller identity. The seam is the recorded peer uid; build
  it when a second caller with different privileges exists.
- mTLS and TCP transport. Add behind the same handlers when a remote caller
  exists.
- Rootless Docker (#6), a complementary mitigation tracked separately.
- Sandbox-name namespacing across callers. One caller today; the profile label
  already scopes what the daemon will act on.

## Decision record

The counter-argument in the tracking task — prod has never invoked
`execute_code`, so the honest resolution might be to leave prod off permanently —
was settled before this design: code execution on prod is wanted, so build the
broker. Mounting the socket into mcpblox on prod remains rejected. The socket
mount on tekom (tekom#143) is accepted risk for a tailnet-only box with family
tenants, and is not a precedent for prod.
