# Backend scope: one boundary shape, several strengths

Decision for [openblox#57 §1 and §4](https://github.com/blox-eng/openblox/issues/57).
Written 2026-09-21.

Records two answers that were being given ad hoc, and one correction. openblox
supports OCI runtimes of any strength, from gVisor upward, behind a single
`Backend`. It does not become an abstraction over fundamentally different
isolation technologies — specifically not an in-process WASM runtime — and this
is a scope decision rather than a backlog item.

## The problem

Two questions arrive repeatedly, and the repository answers neither:

- *Why not `wazero`, or any in-process WASM runtime? It is a stronger boundary
  than gVisor and it is not even a container.*
- *Which runtimes may I actually use?*

The second had a wrong answer rather than no answer, which is the more urgent
half.

## The correction

`SECURITY.md` said, in its security-sensitive-configuration table, that "any
other runtime runs untrusted code on the host kernel", and told the reader under
*What you must not do* not to "set a runtime other than `runsc` for untrusted
code".

Both are false for a microVM runtime. Kata Containers registers with Docker as
an OCI runtime exactly as `runsc` does, and gives each sandbox a **separate
guest kernel** — a stronger boundary than gVisor's user-space one, not a weaker
one. A deployment that had deliberately paid for the stronger boundary was being
told by the project's own security document that it had broken itself, and then
told to undo it.

Worth being precise about where the defect was, because it was not where it
looked. **Nothing in the code enforced a singleton.** `Backend.assertRuntime`
asks Docker whether a runtime of the given name is registered and nothing else:

```go
if _, ok := info.Runtimes[runtime]; !ok {
	return fmt.Errorf("%w: runtime %q is not registered with the docker daemon", sandbox.ErrRuntimeUnavailable, runtime)
}
```

`Spec` has no runtime validation and `internal/daemon` forwards a profile's
`runtime` verbatim, so Kata has worked since the backend was written. The
singleton existed only in prose. Correcting the prose is the whole of the fix;
there is no allowlist to widen and no `ErrRuntimeUnavailable` behaviour to
preserve, because failing closed is a property of *is it registered* and is
orthogonal to how strong the registered runtime is.

The model that replaces it is an ordering, recorded in
[SECURITY.md](../SECURITY.md#the-isolation-runtime): `runc` reaches the host
kernel in full, gVisor reaches the Sentry, a microVM reaches a separate guest
kernel. openblox refuses the first in documentation, defaults to the second, and
supports the third without claiming to have tested it.

That last clause is the honest limit. `THREAT_MODEL.md` §B1/§B2 is written
against gVisor's Sentry, and every test behind the threat model runs `runsc` in
CI. Under Kata those rows describe a boundary the operator is no longer relying
on, and the evidence for the new one is Kata's, not ours. §2 of #57 — running
the adversarial suite against Kata in CI — is what would close that gap, and it
is deliberately not part of this decision.

## Why a microVM runtime is in scope

It is the same integration point and the same shape of guarantee. Kata is
configured the way gVisor is configured: a runtime name in Docker's
configuration, selected per container. Every containment control openblox sets —
`NetworkMode: none`, `CapDrop: ALL`, read-only root, non-root user, `PidsLimit`,
resource caps — is set identically and means the same thing on both. `Files`,
`StartProcess`, ports and previews all behave as documented.

So supporting it costs one sentence of documentation and adds no interface
surface. The variation is entirely in *how strong* the boundary is, not in *what
a sandbox is*.

## Why WASM is not

The case for it is real and should be stated first. An in-process WASM runtime
executes guest code with **no host syscalls at all** — the guest cannot make one,
rather than having it serviced elsewhere. For workloads that fit, that is a
stronger boundary than gVisor, with a far smaller trusted computing base, and it
starts in microseconds rather than hundreds of milliseconds. `wazero` in
particular is pure Go with no cgo, so it would drop the Docker dependency
entirely. None of this is in dispute.

It is still the wrong shape for this interface, for two independent reasons.

**The interface does not survive it.** `sandbox.Backend` is a POSIX-shaped
contract, and most of it has no referent under WASM:

| Surface | Under WASM |
|---|---|
| `Files` — write, read, list a filesystem | No POSIX filesystem. WASI preview 1 offers a preopened-directory subset, not a filesystem. |
| `StartProcess` | No subprocesses. There is no `fork`, and no process model to have one. |
| Ports and preview links | No listening sockets, so nothing to proxy. |
| The image contract | No `pip install`, no apt, no arbitrary userland — every dependency must be compiled to `wasm32-wasi` ahead of time. |

That last row is the one that decides it. openblox exists to run *generated
code*, and generated code installs things. A backend that cannot run
`pip install` cannot run the workload the project is for, however good its
boundary is.

**The guarantee degrades.** An interface whose methods return `ErrUnsupported`
depending on which backend was configured no longer promises anything a caller
can rely on without knowing the deployment. The guarantee would go from *"gVisor
or stronger, and it never silently falls back"* to *"depends which backend was
configured"* — which reintroduces, one level up, precisely the
visible-but-unreachable confusion `openbloxd` exists to eliminate. openbloxd's
whole premise is that a caller cannot quietly end up with a weaker sandbox than
it believes it has. A pluggable-backend interface hands that failure mode back,
dressed as flexibility.

WASM is a different product that shares a problem statement. Someone should
build it. It should not be built behind this interface.

## The decision

1. Runtime strength is an ordering, documented as one. OCI runtimes from gVisor
   upward are supported; `runc` is refused in documentation for untrusted code.
2. `Create` continues not to rank runtimes. It checks registration, fails closed,
   and leaves the choice to the operator.
3. `sandbox.Backend` stays a POSIX-shaped, OCI-runtime-shaped contract. No
   method on it may return `ErrUnsupported` as a function of which backend is
   configured.
4. In-process WASM runtimes are out of scope, on the reasoning above rather than
   on merit. Reopen this if the target workload stops needing arbitrary
   userland, which is the premise that actually carries the argument.

## Out of scope

- **Testing against Kata** (#57 §2). Supporting a runtime and having evidence
  about it are different claims, and this decision makes only the first.
  Done: see specs/2026-09-22-kata-evidence.md.
- **Extracting the adversarial suite to run against any `Backend`** (#57 §3).
  That is about who the suite can be pointed at, not which backends exist.
- **A runtime allowlist in code.** Considered and rejected: it would have to
  carry a table of every microVM runtime's name to avoid refusing a stronger
  boundary than the default, and would fail closed on the wrong axis. Docker
  already answers the only question that has a reliable answer — is this runtime
  registered.
- **Ranking runtimes at create time.** openblox cannot tell what a registered
  runtime actually is; `THREAT_MODEL.md` §7 already says so. A `Strength` field
  would be a claim the code cannot check.
