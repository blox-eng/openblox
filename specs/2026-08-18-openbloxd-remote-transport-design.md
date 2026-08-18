# openbloxd: remote transport and caller authentication

Design for [openblox#32](https://github.com/blox-eng/openblox/issues/32). Written 2026-08-18.

Sibling to [the policy broker design](2026-08-15-openbloxd-policy-broker-design.md),
which built the daemon this extends.

## The problem

`openbloxd` listens on a Unix socket and only a Unix socket, so the daemon and
its caller must share a host. That is often the wrong arrangement: gVisor
contains escape, not contention. It is explicitly not a hypervisor, and
sandboxes compete for CPU, memory bandwidth and disk IO with whatever else runs
beside them. When the neighbour has an availability requirement, the sandboxes
belong on their own machine — and today that is simply unsupported, because the
caller can no longer reach the daemon.

The listener is the small half. `Listen(socketPath, group)` chmods the socket to
a group, and **that group membership is the entire access control list** — the
filesystem performs the authentication. The daemon has no notion of a caller:
no authentication, no authorization, no identity of any kind.

Bind the same handler to a port and every one of those properties is gone at
once. What remains is an unauthenticated remote sandbox-creation API, which
inverts the daemon's purpose. openbloxd exists so that a compromised caller
gains sandboxes rather than the host; a network listener without authentication
hands sandboxes to anyone who can route to the port, and a sandbox is a foothold
on the daemon's host.

So the authentication model is the issue, and the transport is a consequence of
it.

## What the field does

The [broker design](2026-08-15-openbloxd-policy-broker-design.md) surveyed where
*policy* lives. The question here is narrower: what does a remote sandbox daemon
verify about its caller?

Daytona is the only system in that survey whose runner is structurally the same
thing as openbloxd — it owns the container runtime while a separate control
plane reaches it over a network — so it is the one worth reading rather than
recalling. At `v0.190.0`, the last release before the repository stopped being
maintained, `apps/runner` authenticates like this:

```go
token := parts[1]
if token != apiToken {
    ctx.Error(common_errors.NewUnauthorizedError(errors.New("invalid token")))
```

A single static bearer token, compared with `!=`. TLS is opt-in
(`EnableTLS`, default false) and server-side only; across its Go services there
is no client-certificate verification and no constant-time comparison at all.
The listener defaults to every interface on port 8080.

Two things follow. First, a pre-shared token is a real, shipped precedent for
this exact job — choosing it would not be negligent. Second, the token is stored
per-runner in the control plane's database, alongside that runner's address:
it identifies **which runner you are dialing**, not **who is dialing it**. From
the runner's side every caller holding the token is the same caller. Daytona
never needed to distinguish callers because its runner has exactly one by
construction.

That is the property that decides this design. openbloxd has already recorded
per-caller quotas as wanted ([#28](https://github.com/blox-eng/openblox/issues/28)),
and a transport that discards who the caller was has to be revisited to add
them. Daytona's model is precisely the thing that would need revisiting.

As before: take the shape, not the surface.

## The decision

**mTLS, with a private CA and an explicit CN allowlist.**

A client certificate authenticates the caller without putting a shared secret at
rest on it — the daemon holds no copy of the client's key, so nothing
extractable from the daemon's host lets anyone impersonate a caller. And a
client certificate *is* a caller identity, which is the prerequisite #28 named.
Acquiring it here costs one design; acquiring it later costs this one again.

The cost is real and is accepted: certificate issuance, distribution and
rotation become an operational requirement for any deployment that turns remote
transport on. That is why the Unix socket stays the default and stays unchanged.

### Two gates, not one

`RequireAndVerifyClientCert` against a configured CA, **plus** a check of the
leaf certificate's Common Name against an explicit allowlist.

The second gate is not belt-and-braces. With certificate verification alone the
**CA is the ACL**: any certificate it ever signs is accepted, so a CA shared with
anything else silently grants sandbox creation to whatever that other thing
issued. That is the common way an mTLS deployment ends up weaker than the token
it replaced. The allowlist makes a CA mis-issuance survivable, and it makes the
set of permitted callers something an operator can read in one place.

Both gates run during the TLS handshake, via `VerifyConnection`, so a
rejected caller never reaches the request router at all. The daemon logs the
rejected CN; the client sees a TLS alert.

`VerifyConnection` is used rather than `VerifyPeerCertificate` deliberately:
Go does not invoke `VerifyPeerCertificate` on a resumed TLS session — the
peer's certificates come back from cached session state and that callback is
skipped — so an allowlist check living there would stop being enforced for a
resumed caller even after its CN was removed from the allowlist.
`VerifyConnection` runs on every connection, fresh or resumed, so the check
applies without exception.

## Configuration

`listen` is a new optional block. Absent, nothing about an existing deployment
changes.

```yaml
socket: /run/openbloxd/openbloxd.sock
socket_group: openbloxd

listen:                                   # optional; absent means no network listener
  address: "127.0.0.1:9443"               # required when listen is present
  tls:                                    # required when listen is present
    cert_file:       /etc/openbloxd/tls/server.crt
    key_file:        /etc/openbloxd/tls/server.key
    client_ca_file:  /etc/openbloxd/tls/clients-ca.crt
    allowed_client_cns: ["sandbox-caller"]
```

Every field is required when `listen` is present, and none has a default. A
daemon that starts listening on a network interface because a key was omitted is
the failure this design exists to avoid — the same reasoning that makes an unset
image a refusal to start rather than a guess.

Two rules deserve stating outright:

- **`socket` becomes optional, but only when `listen` is set.** Neither one set
  is a refusal to start — `the daemon would accept nothing` — mirroring the
  existing refusal on zero profiles. A daemon serving both transports at once is
  a supported and expected arrangement.
- **A wildcard host is warned about, not refused.** `0.0.0.0:9443` is a
  legitimate bind for a containerized daemon whose network namespace is already
  the boundary. What this design forbids is an *implicit* bind, and that stays
  impossible. The warning exists because the difference between deliberate and
  careless is invisible in the config file.

## Authentication and identity

```go
// Caller is who made a request. It is recorded on every request, over every
// transport, whether or not anything consumes it yet.
type Caller struct {
    Transport string // "unix" or "tls"
    Name      string // certificate CN over tls; empty over unix
}

func CallerFrom(ctx context.Context) (Caller, bool)
```

One middleware wraps the one shared handler and branches on whether `r.TLS` is
set. It records the caller on the request context and on the request log.

`Name` is empty for a Unix caller because `SO_PEERCRED` remains unimplemented —
that is the local transport's identity seam and it is unrelated to this work.
`Transport` is carried explicitly rather than inferred from an empty name: an
access log for a security boundary should say whether a request arrived locally
or over a network, not leave it to be deduced.

Nothing consumes `Caller` yet, and it is built anyway. Per-caller quotas are out
of scope here, but a transport that throws away the caller's identity forces
this file to be reopened to add them.

## One handler, two listeners

`Handler()` is unchanged, and there is exactly one of it. Both listeners feed the
same `http.Server`: `Serve` on the Unix listener, and `Serve` on a
`tls.NewListener` wrapping a TCP listener. `Shutdown` closes both.

This is the structural answer to "policy must stay unreachable regardless of
transport". There is no second route table that could drift from the first,
because there is no second route table. The property is asserted by test as
well — see below — but the design is what makes the test cheap to keep true.

`serve` becomes variadic over listeners. `DialPort`'s connection hijack works
unchanged over TLS: `*tls.Conn` implements `CloseWrite`, which is what
`upgradedConn`'s type assertion needs.

## The client half

`New(socketPath, opts...)` keeps its exact signature. A same-host caller is
untouched.

```go
// TLSFiles is the client's half of the mTLS credential.
type TLSFiles struct {
    CertFile, KeyFile, CAFile string
    ServerName string // optional; derived from the dial address when empty
}

func NewRemote(address string, tls TLSFiles, opts ...Option) (*Client, error)
```

The credential is a positional argument rather than an `Option`, so it cannot be
forgotten. It takes file paths rather than a `*tls.Config` for a specific
reason: exposing `*tls.Config` would mean accepting `InsecureSkipVerify: true`
and then refusing it at runtime. Taking file paths makes an unverified client
**inexpressible** rather than rejected, which is the better version of the same
guarantee. It also matches how the daemon side is configured. If in-memory
certificates are ever needed, that is an `Option`, added when something asks for
it.

Internally `Client.socket` becomes a `dial func(context.Context) (net.Conn, error)`.
One seam, used by both the pooled HTTP transport and the raw `DialPort` path, so
the two cannot diverge on which transport they use.

Previews are unaffected. Minting one signs a name, a port and an expiry; it
touches neither Docker nor the daemon, and the daemon holds no key.

## What this does not protect against

Stated here rather than left to be discovered, and repeated in `docs/security.md`.

**mTLS authenticates the process holding the key, not its intent.** A caller that
has been compromised is a *valid* caller: it holds the certificate. Authentication
contributes nothing to that case.

That case is the dominant risk, and it is the one openbloxd was built for. The
guarantee is that a compromised caller gains sandboxes rather than the host, and
it is enforced by the profile being unreachable from a request — not by the
credential. Neither mTLS nor any alternative credential is what makes remote
transport safe. The credential's job is narrower and should be described
narrowly: keep unauthenticated strangers off the port, and record who called.

**A private network is a real mitigation and a poor sole control.** Running the
daemon on a VPN or a private subnet meaningfully reduces exposure and is
recommended. It is not a substitute for the credential, because it fails open
the moment anything else on that network is compromised, and it authenticates a
route rather than a peer.

**Confidentiality of sandbox contents in transit is TLS's, and only TLS's.**
Exec output, file reads and dialled streams all cross the network now. There is
no application-layer encryption beneath.

## Revocation

There is none beyond configuration. Go's `crypto/tls` checks neither CRL nor
OCSP by default, and openbloxd runs neither.

**Revoking a caller is: remove its CN from `allowed_client_cns` and restart the
daemon.** Not a reload signal — `RuntimeDirectoryPreserve=yes` already makes a
restart transparent to clients that mount the socket directory, so a reload
mechanism would be unearned complexity for the one operation it would serve.

This is a limitation, not a feature, and it is the main operational cost of
choosing certificates. It is acceptable at the scale this transport is for — a
small, enumerated set of callers — and it would not be acceptable at a scale
where certificates are issued automatically. Something that issues certificates
automatically should revoke them automatically too, and that is a different
design.

## Testing

- **Policy unreachability, over both transports.** The existing `policy_test.go`
  assertions become table-driven across a Unix listener and a TLS listener.
  Every field a request must not be able to set is asserted rejected over the
  network as well. This is the requirement that must be a test rather than a
  convention.
- **Configuration refusals.** `listen` without `address`; `listen` without
  `tls`; any missing TLS file; empty `allowed_client_cns`; neither `socket` nor
  `listen`.
- **Handshake gates.** A certificate from an unknown CA is rejected. A
  certificate from the configured CA whose CN is not in the allowlist is
  rejected — this is the test that would fail if the second gate were ever
  dropped as redundant. No client certificate is rejected.
- **The hijack path over TLS.** `DialPort` completes its upgrade and
  `CloseWrite` works, since that depends on a type assertion that a transport
  change could silently break.

## Out of scope

- **Per-caller quotas.** This design supplies the identity they need and stops
  there. The per-profile bound in #28 needs no identity at all and already
  exists.
- **Multi-daemon fan-out or scheduling across hosts.** One caller, one daemon,
  over a network instead of a socket. Choosing between several daemons is a
  different problem.
- **Replacing the Unix socket.** It stays, it stays the default, and same-host
  deployments are unaffected.
- **Certificate issuance tooling.** `docs/security.md` documents a minimal
  `openssl` recipe. A CA is the operator's, and a sandbox daemon should not
  become a PKI.
