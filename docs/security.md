# Security model

openblox exists to run code you do not trust. This page states what it isolates, how,
and — as importantly — what it does **not** claim.

## The threat model

**Assumed hostile:** the code running inside a sandbox, and any data it processes. It
will try to reach the network, read other tenants' data, escape to the host, exhaust
resources, and persist beyond its session.

**Assumed trusted:** the host kernel, the Docker daemon, the gVisor runtime, and the
process that calls openblox.

That last one matters and is examined below — it is the weakest link in a default
deployment.

## What isolates it

### A user-space kernel

Sandboxes run under gVisor (`runsc`). Guest syscalls are serviced by a user-space kernel
rather than passed to the host, so the host kernel's syscall surface is not directly
reachable from inside a sandbox.

openblox **will not fall back to `runc`**. If `runsc` is not registered, `Create` fails
with `ErrRuntimeUnavailable`. A fallback would mean untrusted code silently running on
the host kernel while the API reported success.

### No network interface at all

A sandbox is created with `NetworkMode: none`. Not a firewall, not an allow-list — there
is no external interface to send packets through.

This closes a class of covert channel that IP-layer blocking leaves open. A sandbox on a
normal Docker network gets an embedded DNS resolver on loopback, which forwards
recursively to the host's upstreams — enough to exfiltrate data slowly by encoding it in
lookups to a domain you control. With no interface there is no resolver, on any host,
with nothing to configure and nothing to forget.

!!! note "Loopback still exists, deliberately"
    `lo` is present, which is what lets a process bind a port for a preview.
    Setting Docker's `NetworkDisabled` would remove the network stack *including*
    loopback, which is why openblox does not set it. Egress containment comes from
    `NetworkMode: none`, and a test pins that behaviour.

### Least privilege inside

Non-root by default (`1000:1000`), read-only root filesystem, and only `/tmp`,
`/workspace` and openblox's own state directory writable — all mounted `noexec`.

### Bounded resources

CPU, memory, scratch disk and PID count are capped per sandbox. Scratch is tmpfs and is
drawn from the memory budget, so a sandbox cannot fill the host's disk by writing files.

### Bounded lifetime

Every sandbox has an idle timeout and a max age, enforced by a reaper.

The idle timestamp lives on a root-owned tmpfs while the sandbox runs unprivileged, and
is written by the host's clock through a privileged exec. **The guest can read it but
cannot forge it**, so code inside a sandbox cannot extend its own life. Max age needs no
cooperation from the guest at all.

## What is not claimed

- **gVisor is not a hypervisor.** It is a strong boundary and a much smaller one than a
  shared kernel, but it is not the same as hardware virtualisation. Vulnerabilities in
  it have existed and will again.
- **No side-channel resistance.** Sandboxes on one host share physical CPU. Spectre-class
  attacks between sandboxes are not addressed.
- **No multi-tenant scheduling or fairness.** One sandbox can consume its whole budget
  and slow its neighbours. Capacity planning is yours.
- **Preview revocation is best-effort.** Verification is a local HMAC check consulting no
  shared state, so a revocation only holds in the process that recorded it. Expiry is
  the guarantee — keep TTLs short.

## The caller is the weak link

openblox is a library, so the process importing it talks to the Docker daemon and
therefore needs the Docker socket.

**If that process is containerized, mounting `/var/run/docker.sock` into it grants
root-equivalent access to the host.** Anyone who can make it issue a Docker API call can
bind-mount `/` or start a privileged container — a strictly larger blast radius than the
sandbox it was protecting.

A filtering socket proxy does not fix this. Those filter at the verb level, but
`POST /containers/create` **is** the dangerous verb: `Binds`, `Privileged` and `PidMode`
are fields inside a request the proxy has already allowed.

Two mitigations, best used together:

- **Run the Docker daemon rootless**, so a socket compromise yields an unprivileged user
  rather than the host. ([#6](https://github.com/blox-eng/openblox/issues/6))
- **Put a policy broker in front of it** — a daemon that owns the Docker connection and
  exposes only openblox's own surface, with the isolation policy enforced daemon-side
  and not settable per request. ([#2](https://github.com/blox-eng/openblox/issues/2))

Until then, prefer running the calling process directly on the host over handing a
container the socket.

## Reporting a vulnerability

See [SECURITY.md](https://github.com/blox-eng/openblox/blob/main/SECURITY.md). Please do
not open a public issue for a security report.
