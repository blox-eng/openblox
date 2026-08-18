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

Those bound one sandbox. `openbloxd` additionally bounds how many exist at once, per
profile, through `max_sandboxes` — without it a caller looping on create exhausts host
memory while every individual sandbox stays inside its policy. Size a host against
`memory_mb` × `max_sandboxes` **with headroom**: the runtime enforces `memory_mb`
approximately rather than exactly, and roughly 1.4× the configured figure has been
observed resident before the kill lands.

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
  and not settable per request. This is `openbloxd`; see below.

Where the calling process cannot run directly on the host, prefer `openbloxd` over
handing a container the Docker socket.

## Deploying the policy broker (`openbloxd`)

`openbloxd` is the daemon described above: it holds the Docker connection so nothing
else on the box has to. A caller talks to it over a Unix socket instead, using
`pkg/brokerclient`, which implements the same `Backend` interface `pkg/docker` does —
switching to it is a constructor change, not a rewrite.

**Install it on the host, not as a container.** Running `openbloxd` in a container with
`docker.sock` mounted puts the privilege straight back where the daemon exists to take
it from. Each release attaches the binary for `amd64` and `arm64`, alongside the systemd
unit and an example config:

```sh
# Pick your arch; verify before trusting it.
curl -fsSLO https://github.com/blox-eng/openblox/releases/latest/download/openbloxd-linux-amd64
curl -fsSLO https://github.com/blox-eng/openblox/releases/latest/download/openbloxd-linux-amd64.sha256
sha256sum -c openbloxd-linux-amd64.sha256

sudo install -m 0755 openbloxd-linux-amd64 /usr/local/bin/openbloxd
openbloxd --version      # must print the release tag, not "dev"
```

`--version` reporting `dev` means the binary is somebody's local build rather than a
release asset. That distinction matters because the client and daemon have to agree on
the wire format, so "what is actually running on this host" needs an answer you can
trust.

**Profiles are the whole policy surface.** Every setting that could weaken isolation —
image, runtime, egress, resource caps, lifetime — is chosen by profile name in the
daemon's config file (`deploy/openbloxd.example.yaml`), not by the request. `Create`
rejects a request that tries to set any of them; see the transport-wrapper note in
[ARCHITECTURE.md](https://github.com/blox-eng/openblox/blob/main/ARCHITECTURE.md#shape).
A caller that only ever gets to name a profile cannot ask its way into a weaker
sandbox, whatever it was compromised into sending.

**Mount the socket's directory, not the socket file.** A containerized caller needs
`/run/openbloxd` bind-mounted in, not `/run/openbloxd/openbloxd.sock`. Bind-mounting the
file pins the container's mount to the inode that existed at mount time; when the
daemon restarts, `Listen` removes the stale socket and creates a new one at the same
path with a new inode, and the container's bind mount still points at the old one. The
container is left talking to nothing. Mounting the directory means the container
resolves the path fresh on every connection and picks up the new socket.

**The socket group is the entire access-control list.** There is no token and no TLS —
a Unix socket is a kernel object with no wire to intercept, and mTLS would add a CA,
issuance and rotation for no real gain here. That calculus only holds while caller and
daemon share a host; see [Remote transport](#remote-transport) below for the network
case, where a CA is unavoidable and buys something real. Two different groups do two different jobs
here, and they are easy to conflate: `socket_group` in the daemon's own config file
(`deploy/openbloxd.example.yaml`) names the group that may reach the socket — the
daemon itself creates the socket `0660` and chowns it to that group in `Listen`
(`internal/daemon/listener.go`), not the unit file. `SupplementaryGroups=docker` in
`deploy/openbloxd.service` is unrelated: it grants the daemon *itself* membership of the
`docker` group so it can reach `/var/run/docker.sock`. Anything in `socket_group` reaches
the full broker surface, with no per-caller distinction inside it — grant it only to
processes that should be able to create sandboxes.

`socket_group` must be the daemon user's primary group, or `Group=` must be set on the
unit to match it. systemd creates `RuntimeDirectory` (`/run/openbloxd`) owned by the
unit's `User`/`Group`, and with `Group=` unset that's the user's primary group — the
shipped default happens to set `socket_group` to that same group, so it works out of the
box. Picking a different `socket_group` without also setting `Group=` chowns the socket
correctly but leaves it inside a directory that group cannot traverse: connections fail
with `EACCES` and nothing about the socket's own permissions explains why.

`RuntimeDirectoryMode=0750` on the unit is not tidiness — it is load-bearing. `Listen`
creates the socket with `net.Listen`, which the umask governs, and only narrows it to
`0660` with a subsequent `os.Chmod`. Between those two calls the socket briefly carries
whatever mode the umask produced, and the `0750` runtime directory is what limits who
can reach it during that window. Loosen that line and the window is wide open, not
narrowly so.

`SO_PEERCRED` on the accepted connection carries the calling process's uid (and gid).
openbloxd does not act on it today, but the identity is there to key a future per-caller
audit trail or profile-to-identity binding off of. Under user-namespace remapping,
that's the *remapped* uid — the one the kernel sees on the socket, not the uid the
process believes it's running as inside its container.

## Remote transport

openbloxd serves a Unix socket by default, and that remains the recommended
arrangement wherever the caller and the daemon share a host. The optional
`listen` block (`internal/daemon/config.go`) adds a network listener so the
daemon can run on a machine of its own — because gVisor contains escape, not
contention, and sandboxes otherwise compete for CPU, memory bandwidth and disk
IO with whatever runs beside them.

A network listener requires mutual TLS. There is no unauthenticated network
mode and there is no way to configure one: every field of `listen.tls` is
required, and `Load` refuses to start the daemon if any is missing.

### What authenticates a caller

Two gates, both during the TLS handshake in `ListenTLS`
(`internal/daemon/listener_tls.go`):

1. The client certificate must chain to `listen.tls.client_ca_file`.
2. Its Common Name must appear in `listen.tls.allowed_client_cns`.

The second is not redundant. With verification alone **the CA is the entire
access control list** — any certificate it ever signs is accepted. Use a CA
that signs nothing else, and treat the allowlist as the thing that makes a
mis-issuance survivable.

### What this does not protect against

**mTLS authenticates the process holding the key, not its intent.** A caller
that has been compromised is a *valid* caller: it holds the certificate.
Authentication contributes nothing to that case.

That case is the one openbloxd exists for, and the credential is not what
answers it. The guarantee is the same one the rest of this page describes: a
compromised caller gains sandboxes bounded by a profile, never the host, and
that bound is enforced daemon-side and unreachable from a request — see
[Profiles are the whole policy surface](#deploying-the-policy-broker-openbloxd)
above. Nothing about arriving over the network relaxes that. `openbloxd`
serves both listeners from the one handler
(`cmd/openbloxd/main.go`), and `internal/daemon/policy_test.go` asserts every
hostile request body rejected over both transports rather than leaving that
as a convention.

**A private network is a real mitigation and a poor sole control.** Running
the daemon on a VPN or a private subnet meaningfully reduces exposure and is
recommended. It is not a substitute for the credential: it authenticates a
route rather than a peer, and it fails open the moment anything else on that
network is compromised.

**Confidentiality in transit is TLS's alone.** Exec output, file reads and
dialled streams all cross the network now, with no application-layer
encryption beneath.

### Revocation

There is none beyond configuration. Go checks neither CRL nor OCSP by default,
and openbloxd runs neither.

**To revoke a caller: remove its Common Name from `allowed_client_cns` and
restart the daemon.** `RuntimeDirectoryPreserve=yes` in the shipped unit
(`deploy/openbloxd.service`) is what makes that restart transparent to
clients mounting the socket directory, as described above.

This is a limitation, not a design feature. It is workable for a small,
enumerated set of callers and would not be workable at a scale where
certificates are issued automatically — anything issuing certificates
automatically should revoke them automatically too.

### Issuing the certificates

openbloxd is not a certificate authority and does not want to be. A minimal
private CA, sufficient for one daemon and one caller (bash/zsh — `<(...)`
process substitution is not POSIX `sh`):

```bash
# A CA that signs nothing else.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=openbloxd-ca"

# The daemon's certificate. The SAN must match the address callers dial.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=openbloxd"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out server.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth")

# One caller. The CN is what goes in allowed_client_cns.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client.key -out client.csr -subj "/CN=sandbox-caller"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth")
```

Keep `ca.key` off both machines once the certificates are issued.

## Reporting a vulnerability

See [SECURITY.md](https://github.com/blox-eng/openblox/blob/main/SECURITY.md). Please do
not open a public issue for a security report.
