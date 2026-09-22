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

## What implementation changed (2026-09-22, after Tasks 1–8)

This spec was written before any code existed. Four things below turned out
wrong once `pkg/conformance` was actually built. They are recorded here rather
than silently edited into the sections above, because the plan should stay
readable as the argument that was actually followed, warts included.

### A third non-portable property

*What the non-portable properties become* named two rephrasings. There is a
third: `propKillGroupWaitsForLateRecord` (`kill-group-waits-for-a-late-group-
record`). The original test reached into `dockerSandbox`'s unexported `exec`
and `killGroup` to force the specific race window between a command's process
group being recorded and the kill that follows a timeout. Expressed only
through `sandbox.Backend`, that hook does not exist, so the property is
reinterpreted: it forces the race approximately, via a 100ms `Timeout` on the
public `Exec`, chosen to put the exec and the kill as close together as the
interface still resolves reliably. This is weaker than the original in two
ways its doc comment (`pkg/conformance/process.go`) records: if a real
backend's own bookkeeping reliably lands before the 100ms fires, the race
never happens and the property silently degenerates into a shorter-timeout
duplicate of `propTimedOutCommandKillsChildren`; and the 100ms figure is a
guess at exec round-trip time that can simply be too short for a slower
backend or a loaded host, failing for a reason unrelated to a late group
record. It carries a liveness guard — a generously-timed exec on a distinct
marker, checked to actually be running before the tight-timeout exec runs —
so the property's pass cannot be explained by the command never existing in
the first place, independent of whether the race itself was won.

This means the extraction's arithmetic — "19 move unchanged, one is
rephrased, one splits" — undercounts the rephrasing by one: it is two
properties rephrased, not one, alongside the one split. Core is still 21;
what changed is how many of those 21 required inventing a new way to observe
the same claim through a narrower interface.

### The host-local tier has two properties, not one

*Tiers, and the no-skip rule* and *What the non-portable properties become*
both describe host-local as the single half of `TestRepeatedLifecycleLeaksNothing`
that measures the test process rather than the guest. Implementation found a
second, independent host-local property while splitting the socket probe:
`TestSandboxCannotSeeTheDockerSocketOrHostFiles` asserted two things under one
name — a fixed control-plane socket path (portable, and rephrased into Core as
`propNoControlPlaneSocket`) — and a host temp file planted by
`os.CreateTemp` in the test process itself, checked to be invisible from
inside the guest. That second assertion only means anything when the backend
and the test share a machine, exactly like the leak check's host-side half, so
it could not stay in Core either. It is now `propHostFilesAreInvisible`
(`host-files-are-invisible-to-the-guest`).

Host-local is therefore two properties: `host-retains-no-process-goroutine-or-
descriptor` and `host-files-are-invisible-to-the-guest`. This was found and
folded into the design during Task 4 (the socket-probe split) and Task 7 (the
leak-check split), not left for this document to catch after the fact; it is
recorded here because this spec's own tables still described one.

### The negative control needed an exemption mechanism

*The negative control* says Core properties must fail against `badBackend`,
"property by property, not merely in aggregate," but does not say what happens
when a property genuinely cannot be falsified by an unprivileged, unisolated
test process — which turns out to happen. `negativeControlExemptions`, added
in `negative_test.go` only, maps a property name to a written reason a real
person can check independently. It is deliberately not reachable from
`Config`, not environment-driven, and lives in a test file rather than
production code — the same reasoning this spec already applied to keep the
property selector and the probe targets out of `Config`. Every exempted
property is asserted to still *pass* against `badBackend` (the outcome its
listed confound predicts), and every entry is asserted to still name a real
Core property, so a stale exemption fails loudly instead of quietly drifting.
The suite's output now states both counts: `Core: 21 properties; negative
control covers 20` (or fewer, if the list grows).

**The boundary rule, which this spec did not anticipate needing:** an
exemption may only ever name a confound in the **host environment** — never a
property of `badBackend` itself, because a defect in the control is always
fixable and the fix is always to fix `badBackend`. The distinction is kind,
not count. "This host is unprivileged, so an unprivileged process gets the
same `/proc`/`/sys` denial on any host, isolated or not" is a fact about the
machine running the suite, outside anyone's control here — that one stays.
"`badBackend` happens to not use a shell, so a probe built to attack a shell
never ran" was a fact about code this package owns; the fix was to fix
`badBackend` (see `shellQuoteArgv` and the shell-copy rewrite in
`bad_backend_test.go` / `privilege.go`), not to document around it. The list
went from 3 entries to 1 under this rule during Task 8, when the last two —
which had been excusing gaps in `badBackend`'s own behavior rather than
genuine host confounds — were closed by fixing the probes instead. Without
this rule the list has no ceiling: for any property, `badBackend` could be
made incidentally correct and then documented why, and the negative control
would stop meaning anything. Under the rule it is structurally bounded by how
much of the host this suite cannot itself control — today, one entry
(`cannot-write-kernel-knobs`, exempted because an unprivileged test process
gets the same denial an unprivileged process gets on any host).

### The migration risk was right, and here is what actually happened

*Image integrity* predicted "expect real failures" moving from `alpine:3.20`
to the pinned reference image (Debian 12, `dash`, not BusyBox) and called that
"the migration, not a surprise." It was right to flag it, and the actual
outcome is worth recording because it is the strongest evidence available for
why the suite pins by digest and treats a vacuous pass as the thing to fear,
not a genuine failure:

- **One property genuinely failed.** The reference image ships no `kill`
  binary, so a probe that invoked `kill` directly as `Argv` could not deliver
  a signal at all. `propCrashedSandboxRecoversThroughCreate` now signals
  through an explicit `sh -c "kill -9 1"` — the shell's own builtin — which is
  also closer to what a real guest attacker reaching for a shell would do.
- **Three probes were passing vacuously, which is worse.** The reference
  image ships neither `wget` nor `nslookup`, so the egress probe's HTTPS and
  DNS attack steps never ran and their absent markers read as containment
  that had not actually been measured; that probe now goes through `python3`,
  which the image does provide, with its own socket layer checked to work
  before any absence downstream is trusted. The reference image also has no
  `/bin/busybox`, so the writable-mounts-are-`noexec`/`nosuid` probe's original
  approach — copying `/bin/busybox` to a renamed path — could not run at all,
  because BusyBox resolves its applet from `argv[0]` and refuses a renamed
  copy; that probe now copies `/bin/sh`, the one binary a POSIX userland must
  provide.
- **Seven probes gained an explicit positive control** — a check, run before
  the attack step, that the probe's own mechanism works at all (a loopback
  listener really is reachable, a file really can be written and read, `/dev`
  really is populated, environment really does propagate between sandboxes, a
  background process really is observed running) — precisely because the
  migration surfaced probes whose silent failure to run would otherwise have
  been indistinguishable from a passing result. This is the same discipline
  the deleted adversarial file already used in places; the migration is what
  made it necessary everywhere a probe depends on the image's userland.

None of this was hypothetical, and none of it was found by reasoning about the
image in the abstract — it was found by running the suite against the pinned
digest and watching properties that should have been red stay green. That is
the failure mode a digest pin and a negative control exist to catch, and this
migration is the evidence that they do.
