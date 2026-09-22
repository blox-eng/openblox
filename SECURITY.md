# Security Policy

openblox exists to contain hostile code, so security reports take priority over
all other work.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

Report privately through
[GitHub private vulnerability reporting](https://github.com/blox-eng/openblox/security/advisories/new),
or email **security@openblox.sh**.

Include what you can of: the affected version or commit, the deployment mode
(library or `openbloxd`), the gVisor version (`runsc --version`), reproduction
steps, and the impact you believe it has. A failing property in the style of
`pkg/conformance` is the most useful form a report can take, but is not
required.

In scope: anything that lets code inside a sandbox reach something
[THREAT_MODEL.md](THREAT_MODEL.md) says it cannot; anything that lets an `openbloxd`
caller weaken a profile's policy; forging or misrouting preview tokens; and any
claim in the documentation that the code does not uphold. Vulnerabilities in gVisor,
Docker or the Linux kernel themselves belong with those projects, but tell us too
if openblox's defaults make one reachable.

## What to expect

- Acknowledgement within **72 hours**.
- An initial assessment — whether we can reproduce it, and how severe we think it
  is — within **7 days**.
- A fix or a documented mitigation as fast as severity warrants. We aim for
  **90 days** at most and will agree a disclosure date with you.
- Credit in the advisory and release notes, unless you prefer otherwise.

Please give us a reasonable chance to ship a fix before disclosing publicly, and do
not test against systems you do not own.

## How fixes are communicated

- A [GitHub Security Advisory](https://github.com/blox-eng/openblox/security/advisories),
  with a CVE where one applies. This also feeds `govulncheck` and Dependabot.
- A patch release. Its notes and the `Security` section of
  [CHANGELOG.md](CHANGELOG.md) say what was fixed and who is affected.
- For a vulnerability in the reference sandbox image, a new image version. Published
  image versions are never overwritten, so an image pinned by digest does not change
  underneath you; move the pin to pick up the fix.

## Supported versions

openblox is pre-1.0. Only the **latest release** receives security fixes. Upgrade
to it rather than expecting a backport.

| Version | Supported |
|---|---|
| latest `v0.x` release | yes |
| older releases | no |

## Security assumptions

openblox assumes the code in a sandbox is actively hostile. It trusts the host, its
kernel, Docker, gVisor, the sandbox image, `openbloxd`, and whoever configures
them. The full model — assets, trust boundaries, each attack with its defence and
test, and the residual risks — is in [THREAT_MODEL.md](THREAT_MODEL.md).

openblox narrows what untrusted code can reach. It does not guarantee that a sandbox
cannot be escaped: its isolation is gVisor's, and gVisor has had vulnerabilities.

## Recommended deployment

```
application ──Unix socket──► openbloxd ──Docker API──► Docker + gVisor ──► sandbox
 (no Docker access)          (holds the socket;
                              policy in its config)
```

- Run **`openbloxd`** on the host and have applications use `pkg/brokerclient`.
  Importing `pkg/docker` directly means your application holds the Docker socket,
  which is equivalent to root on the host.
- Install `openbloxd` from a release, verified as described in
  [RELEASING.md](RELEASING.md#verifying-a-release), and pin a version, not `latest`.
- Pin the sandbox image **by digest** in every profile.
- Keep `runsc` current; its security fixes are yours to apply.
- Serve preview URLs from an origin that shares no cookies with your application.

## The isolation runtime

The runtime decides **which kernel a guest syscall reaches**, and that is the
property the rest of this document rests on. It is an ordering, not a switch:

| Runtime | Kernel surface reached by the guest | Verdict |
|---|---|---|
| `runc` (the host default) | the host kernel, in full | Unsafe for untrusted code. A shared-kernel container is not a boundary against attacker-controlled native code. |
| `runsc` (gVisor) — **default** | the Sentry, a user-space kernel; the host kernel only past **B1** and **B2** | What openblox is built and tested against. |
| a microVM runtime, e.g. Kata | a separate guest kernel | **Stronger** than the default, at a higher cost per sandbox. Kata on amd64 is measured, with one layer lost: `/dev/shm` is not `noexec,nosuid` in its guest. One lifecycle claim — that `Exec` on a crashed sandbox fails promptly and `Create` recovers it — is unmeasured under Kata. See [THREAT_MODEL.md](THREAT_MODEL.md#under-kata). |

openblox does not rank runtimes at create time. `Create` requires only that the
named runtime is registered with Docker and fails with `ErrRuntimeUnavailable`
when it is not; it never falls back to the host default. Failing closed is a
property of *"is it registered"*, and is independent of how strong the runtime
is — so choosing a stronger one is supported, and choosing `runc` is refused by
this document rather than by the code.

Two caveats on going stronger. [THREAT_MODEL.md](THREAT_MODEL.md) §B1/§B2 is
written specifically against gVisor's Sentry, so under a microVM runtime those
two rows describe a boundary you are no longer relying on and the residual risks
differ; and every merge-gating test behind the claims below runs against
`runsc` in CI. Kata on amd64 is also measured by openblox — the conformance
suite, in a workflow that does not gate merges, with results in
[THREAT_MODEL.md](THREAT_MODEL.md#under-kata); on anything else you are trusting
the runtime's own evidence, not openblox's. The containment openblox configures
— no network interface, dropped capabilities, read-only root, non-root user,
resource caps — is set identically either way. What openblox leaves to Docker's
defaults is not honoured identically: under Kata, `/dev/shm` is not `noexec` or
`nosuid`.

## Security-sensitive configuration

| Setting | Safe value | Why it matters |
|---|---|---|
| `runtime` / `WithRuntime` | `runsc` (default), or a microVM runtime | `runc`, the host default, runs untrusted code on the host kernel. See [The isolation runtime](#the-isolation-runtime). |
| `egress` / `WithEgress` | `none` (default) | `unrestricted` gives the sandbox the host's network, including the LAN and cloud metadata. |
| `user` / `WithUser` | numeric, non-zero `uid:gid` (default `1000:1000`) | Root, group 0, user names and a bare uid are refused: names and a bare uid resolve inside the untrusted image. |
| `image` / `WithImage` | `name@sha256:…` | A tag can be repointed by whoever controls the registry. |
| `socket_group` | a group holding only trusted callers | Every member controls every sandbox. |
| `max_sandboxes`, `memory_mb`, `cpus` | sized to the host | Per-sandbox caps do not bound the total. |
| `idle_timeout`, `max_age` | positive (defaults apply when omitted) | Negative values are refused by `openbloxd`; in the library they disable the bound. |
| Preview key (`WithPreviews`) | ≥ 32 random bytes, kept secret | Anyone with the key can mint a preview token for any sandbox port. |

## What you must not do

- Do not mount the Docker socket — or any host path — into a sandbox.
- Do not run `openbloxd` in a container with the Docker socket mounted; it defeats
  the reason the daemon exists.
- Do not mount the Docker socket into an application container to use the library;
  use `openbloxd`.
- Do not set `egress: unrestricted` for untrusted code without an external firewall.
- Do not run untrusted code under `runc`, the host default, or any other
  shared-kernel runtime. Going the other way — a microVM runtime such as Kata —
  is a stronger boundary and is supported.
- Do not put secrets into a sandbox's environment, files or command arguments.
- Do not trust sandbox output: escape it before rendering, bound it before parsing,
  and treat it as potential prompt injection before handing it to a model.
- Do not rely on `Revoke` across replicas; rely on short preview TTLs.
- Do not treat openblox as a tenant boundary between callers of the same
  `openbloxd` (see [THREAT_MODEL.md §7](THREAT_MODEL.md#7-explicit-non-goals-and-residual-risks)).
