# A portable conformance suite for sandbox.Backend

Design for [openblox#57 §3](https://github.com/blox-eng/openblox/issues/57).
Written 2026-09-22.

Follows [the backend scope decision](2026-09-21-backend-scope.md), which settled
that `sandbox.Backend` stays one shape of contract. This one settles who is
allowed to be measured against it.

## The problem

`pkg/docker/adversarial_integration_test.go` asserts 21 named properties — what
the guest cannot reach, cannot outlive, and cannot leave behind. It is the most
valuable code in the repository and it is nailed to one implementation, so it
answers "is openblox's Docker backend contained?" and nothing else.

The question it could answer instead is the one every evaluator asks: *why not
write my own?* The honest answer is that you can — it is ~3.3k lines — and that
an implementation is copyable in a week. A shared set of properties that
implementations are measured against is not, and it is worth more to the
ecosystem than another library.

That only holds if the suite cannot be gamed. A conformance suite whose skips
are unconstrained certifies nothing while looking authoritative, which is worse
than having none: it launders an unmeasured implementation into a measured-
looking one. Most of this design is about removing the levers.

## The public surface

A new package, `pkg/conformance`. Named for what it is rather than for Go's
`httptest`/`iotest` convention, because the word is the point.

```go
package conformance

// Config is what an implementation supplies. It is deliberately this small.
type Config struct {
    // New returns a fresh Backend. Called once per property, so a property
    // cannot be affected by state another one left behind.
    New func(t *testing.T) sandbox.Backend

    // Name identifies the implementation in output.
    Name string
}

// Run executes the Core tier. Every property runs against every
// implementation; there is no selector and nothing skips.
func Run(t *testing.T, cfg Config)

// RunHostLocal executes properties that are only meaningful when the backend
// and the test share a host. Opt-in, and never counted as Core.
func RunHostLocal(t *testing.T, cfg Config)
```

That is the whole API. What is absent carries the design:

- **No per-property selector.** Running 14 of 18 and calling it conformance is
  the failure mode; the suite owns the list.
- **No capabilities struct.** Every declared capability is a lever to avoid an
  inconvenient property. Where a property genuinely does not port, it moves
  tier — a decision the suite makes once, not one each implementation makes.
- **No image field.** See *Image integrity* below.
- **No probe targets.** See *Probe targets are constants*.

`Config.New` takes `*testing.T` so an implementation can `t.Fatalf` on a
construction it cannot perform, and register its own `t.Cleanup`.

## Tiers, and the no-skip rule

**Core** is the claim: 21 properties, expressed entirely through
`sandbox.Backend` and `sandbox.Sandbox`. No property in Core may skip for any
reason. An implementation that cannot satisfy one fails; that is the result.

The arithmetic, since "21 properties" appears on both sides of this extraction
and the two numbers are not the same 21. Of today's 21 test functions, 19 move
unchanged, one is rephrased (the control-plane socket probe), and one —
`TestRepeatedLifecycleLeaksNothing` — is really two properties wearing one name
and splits: *Destroy actually removes the sandbox* is portable and joins Core,
while *the host retains no process, goroutine or descriptor* is host-local.
So Core is 19 + 1 + 1 = 21, and Host-local is the other half of the split.

**Host-local** is everything whose evidence lives on the machine running the
test rather than inside the sandbox. It is real coverage — openblox runs it —
but an implementation that cannot run it has not conformed any less, so it
never contributes to a Core result.

There is exactly one legitimate abort: `Create` returning
`sandbox.ErrRuntimeUnavailable` means the host cannot provide the runtime at
all. That skips **the entire run**, reported once and loudly, rather than
letting individual properties evaporate. A per-property skip on that error
would be indistinguishable from containment, which is the exact confusion the
existing suite's fail-closed discipline exists to prevent.

## What the non-portable properties become

The non-portability was almost never in the property. It was in the check.

| Asserted today | Becomes | Tier |
|---|---|---|
| `b.cli.ContainerInspect` reports the container gone | `List` omits the name **and** `Open` returns `ErrNotFound` | Core |
| probes `/var/run/docker.sock`, `/run/docker.sock` | probes a suite-owned list of control-plane sockets: Docker, containerd, CRI-O, Podman | Core |
| scans host `/proc` for processes still serving a destroyed sandbox | unchanged | Host-local |
| counts goroutines and file descriptors in the test process | unchanged — it measures the client, not the sandbox | Host-local |

The other 19 — metadata and private-range reachability, loopback identity,
interface inventory, kernel knobs, block devices, path traversal, capability
sets, `noexec`/`nosuid` mounts, root refusal, the four timeout and cancellation
kill properties, `setsid`, output flooding, cross-sandbox state, crash recovery,
stopped-sandbox replacement and argv-not-shell — already use nothing but the
interface and move unchanged.

`TestSetsidEscapesTheTimeoutKill` deserves a note: it asserts a documented
*escape*, not a defence. It stays in Core as written, because a conformance
suite that quietly dropped the properties recording known limitations would be
overstating every implementation it measured, openblox's included.

## The negative control

A suite that passes vacuously is the thing to be afraid of: every property
green because every probe silently failed to run.

So `pkg/conformance` ships `badBackend`, an in-package fake with no isolation
whatsoever, and a test asserting that Core **fails** against it — property by
property, not merely in aggregate. A property that cannot be made to fail is
not testing anything, and the negative control is what surfaces that at the
moment the property is written rather than years later.

This is part of §3, not a follow-up. Without it the suite's central claim is
unevidenced, which is precisely the criticism §3 exists to answer.

## Image integrity

The suite pins the reference image **by digest**, not by tag. `SECURITY.md`
already says a tag can be repointed by whoever controls the registry; a
conformance suite that pulled a mutable tag would let that party silently
replace the probes' userland and turn every property green. Pinning the digest
is the same rule the project asks of its users, applied to itself. This is
OWASP A08 (software and data integrity failures) and it is not hypothetical —
the suite's whole output depends on the guest binaries being the expected ones.

`OPENBLOX_CONFORMANCE_IMAGE` overrides the pin for developing the suite itself.
A run that used it **says so in its output**, so an overridden run cannot be
presented as a conformant one.

**Migration risk, called out because it is easy to miss:** the existing
adversarial tests run against `alpine:3.20`, not the reference image
(`pkg/docker/backend_integration_test.go`, `const testImage`). Moving to
`ghcr.io/blox-eng/openblox-sandbox` changes the userland every probe executes
in — BusyBox applets versus the reference image's tools — so each of the 21
properties must be re-confirmed against the new image rather than assumed to
carry over. Expect real failures here; they are the migration, not a surprise.

## Probe targets are constants

Every address, path and port a probe reaches for is a package-level constant.
None is caller-supplied, and `Config` offers no way to add one.

Beyond the anti-gaming argument, this is a deliberate OWASP A10 (SSRF) posture.
The suite's probes exist to attempt exactly the requests a sandbox must not be
able to make — cloud metadata at `169.254.169.254`, the host's private ranges,
the container bridge. A `Config` field for probe targets would turn a testing
library into a general-purpose request-forgery gadget that runs inside somebody
else's isolation boundary and reports what it reached. It would also be the
kind of thing that reads as helpful in review.

## Injection

Probe scripts are constants; no probe is assembled by interpolating a value
into a shell string. Where a property needs a variable — a sandbox name, a path
— it is passed through `sandbox.Command.Argv`, never spliced into `sh -c`.

`TestArgvIsNeverAShellBuiltin` already asserts openblox does not hand argv to a
shell. A suite that built its own probes by string concatenation would be
asserting that property while violating its premise (OWASP A03).

## Go semantics and performance

- **Sequential by design.** No `t.Parallel`, matching the repository, which
  uses it nowhere. Each property creates a real sandbox; running them in
  parallel would contend for host memory and CPU and make the resource-bound
  properties — output flooding, PID caps, OOM behaviour — measure the test
  harness rather than the sandbox. Sequential is a correctness decision here,
  not a missing optimisation.
- **`t.Context()`**, already used in the repository (`pkg/docker/reap_test.go`),
  rather than `context.Background()` with hand-rolled cancellation. It is
  cancelled when the test finishes, so a wedged probe cannot outlive its
  property.
- **Sentinel errors compared with `errors.Is`**, never string matching:
  `ErrNotFound`, `ErrStopped`, `ErrInvalid`, `ErrRuntimeUnavailable`,
  `ErrImageUnavailable`. The suite asserts the contract `pkg/sandbox` documents,
  so it must compare the way callers are told to.
- **Properties as a table** — a slice of `{name string, fn func(*testing.T,
  Config)}` walked with `t.Run` — so the tier is a data structure rather than a
  sequence of calls, and the negative control can walk the same table.
- **One backend per property** via `Config.New`, not a shared one. Sharing would
  make a leaked sandbox in one property look like a failure in the next.
- `for i := range n` over the index form, consistent with the existing suite.

## Failure output

The suite's users are people diagnosing why an isolation boundary did not hold,
often in someone else's implementation. The output is the product, and Nielsen's
heuristics apply to it as much as to a UI.

- **Visibility of system status.** A run states the tier, the implementation
  name, the pinned image digest, and the property count before it starts —
  so what was measured is on the record, not inferred from what passed.
- **Match between the system and the real world.** Properties are named as
  claims about isolation rather than as test identifiers: a reader who has not
  read the source should be able to tell what was asserted from the name alone.
- **Error prevention.** The absent selector and the absent capabilities struct
  remove the two ways a run could quietly measure less than it claims.
- **Recognise, diagnose, recover.** A failure reports what was attempted, what
  was observed, and which `THREAT_MODEL.md` row it corresponds to. "Property
  failed" is useless to someone debugging their own backend; the threat-model
  reference is what turns a red test into a place to look.
- **Logging failures are the point (OWASP A09).** A skip that is not reported is
  the suite's worst outcome, so skips are impossible in Core and stated in
  Host-local.

## What happens to pkg/docker

`adversarial_integration_test.go` becomes a consumer:

```go
//go:build integration

func TestConformance(t *testing.T) {
    cfg := conformance.Config{Name: "docker", New: newConformanceBackend}
    conformance.Run(t, cfg)
    conformance.RunHostLocal(t, cfg)
}
```

Anything genuinely Docker-specific stays behind as a Docker test. openblox's own
coverage is unchanged in substance; what changes is that the same assertions now
run against anything else that claims the interface.

`pkg/conformance` itself carries **no build tag**, so `go build ./...` and
`go vet ./...` cover it on every run, the way `httptest` is an ordinary package
that imports `testing`. The tag stays on the caller, which is what needs a live
backend.

## Out of scope

- **A machine-readable score artifact.** `go test` already reports which
  properties failed. Designing a report format before the suite has run against
  a second implementation is designing for an imagined consumer; §2 is what
  would tell us whether one is wanted.
- **Running it against Kata in CI** (#57 §2). This makes the suite pointable;
  pointing it is separate work with its own infrastructure cost.
- **Preview and port properties.** Not in the adversarial file today, so not in
  this extraction.
- **Non-Go implementations.** Reaching those needs a wire protocol, which is a
  different project.

## Risks

- **Pinning the reference image** means an implementation on an architecture
  that image does not publish cannot be measured at all. Today that is amd64 and
  arm64, which is most of the field. It will bite exactly once, later, and the
  answer will probably be publishing more architectures rather than loosening
  the pin.
- **A public `pkg/conformance` on a 0.x project** makes adding a property
  arguably a breaking change, since someone's CI goes red without their code
  changing. The package doc will say plainly that Core grows and that this is
  intended — a suite that froze would stop tracking the threat model, which is
  the only thing making it worth running.
- **The alpine-to-reference-image move** is the largest source of unplanned work
  in this design. See *Image integrity*.
