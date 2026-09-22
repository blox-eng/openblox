# Kata evidence: the conformance suite against a second runtime

Design for [openblox#57 §2](https://github.com/blox-eng/openblox/issues/57).
Written 2026-09-22.

Runs `pkg/conformance` against Kata Containers in CI and records what fails.
Nothing is made to pass. A property that fails under Kata is either a real
difference between the runtimes, to be documented in `THREAT_MODEL.md`, or a
property that was implicitly gVisor-shaped. Either finding is the output.

## The problem

The landing page can name Kata as a runtime (#60), and `SECURITY.md` says that
on anything but `runsc` the operator is trusting that runtime's evidence rather
than openblox's. Nothing measures Kata. The loudest surface the project has
names a runtime its own suite has never been pointed at.

## Feasibility, measured

Before this design existed, a throwaway workflow probed GitHub-hosted runners
on this repository (2026-09-22, since deleted):

| | `ubuntu-latest` (amd64) | `ubuntu-24.04-arm` |
|---|---|---|
| `/dev/kvm` | Present. AMD under Hyper-V, `kvm_amd` `nested=1`; `kvm-ok` passes once a udev rule opens the device | Absent. Kernel: `kvm: HYP mode not available` |
| Kata 4.2.0 (runtime-rs, QEMU) | Boots. Guest kernel `6.18.35`, host `6.17.0-azure` | Shim fails: `timed out waiting for QMP ready` |
| Cold start per sandbox | 7.1–7.4 s (`runc`: ~0.1 s) | — |
| `docker exec` round trip | ~30 ms, stable | — |
| Guest process in host `/proc` | Not visible; the host sees only `qemu-system-x86` and `virtiofsd` | — |
| Install (1 GB static tarball) | ~19 s | ~14 s |

The received wisdom that hosted runners cannot nest virtualisation is out of
date on amd64 and still true on arm64. On a public repository the amd64 job
costs nothing. The suite creates about thirty sandboxes; at ~7 s each that adds
roughly three and a half minutes to the ~98 s gVisor run.

## Decisions

### A separate workflow, never a gate

`.github/workflows/kata.yml`, not a job in `ci.yml`. `release.yml` gates on
`workflow_run: [CI]` and branch protection lists only CI's jobs, so a red Kata
run cannot block a merge or a release by construction rather than by
convention. gVisor remains the default runtime and the only one that gates.

Triggers:

- `push` to `main`: evidence for every commit that could be released.
- `schedule`, weekly: Kata, the runner image and KVM availability drift
  independently of this repository.
- `workflow_dispatch`.
- `pull_request` limited to `pkg/conformance/**`, `pkg/docker/**` and
  `.github/workflows/kata.yml`, so a change to the suite shows its effect under
  Kata before it lands. The `ci.yml` argument against path filters concerns
  required checks, which this is not.

One job, `Conformance (Kata, amd64)`, on `ubuntu-latest`, 30-minute timeout.

### Provisioning

1. A udev rule makes `/dev/kvm` accessible, then `kvm-ok` is asserted as its
   own step. A runner image that stops exposing KVM fails there, legibly,
   rather than as thirty identical `Create` errors.
2. Kata 4.2.0 `kata-static-4.2.0-amd64.tar.zst`, pinned by sha256
   (`b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8`), with the
   same bounded retry as the gVisor install.
3. The runtime-rs shim is linked onto `PATH` and registered with Docker as
   `kata` (`runtimeType: io.containerd.kata.v2`), merged into `daemon.json`.
4. Kata's shipped default configuration (runtime-rs, QEMU) is used unmodified:
   it is what an operator who installs Kata gets.
5. A verify step boots a guest and requires its `uname -r` to differ from the
   host's, mirroring the `runsc` step's `*gvisor*` check. A registered but
   broken runtime, or one that silently shares the host kernel, stops here.

### The consumer

One new file, `pkg/docker/conformance_kata_integration_test.go`, built only
under `//go:build integration && kata`. `TestConformanceKata` supplies a
`Config` whose `New` returns a thin wrapper: it embeds `*docker.Backend` and
overrides `Create` to append `sandbox.WithRuntime("kata")` after the suite's
own options. It then calls `conformance.Run` and `conformance.RunHostLocal`,
exactly as `TestConformance` does.

This works because the suite never passes `WithRuntime` itself, and it needs
nothing from `pkg/conformance`: no `Config` field, no environment variable, no
property selector. The runtime choice belongs to the implementation under test,
which is where `Config.New` already puts it.

The gVisor jobs never compile the file. So that it cannot rot unnoticed, the
compile-only job in `ci.yml` adds `kata` to the tags of its `go vet` — the only
change to `ci.yml`, and not to the integration matrix.

### Recording

`go test -tags 'integration kata' -run '^TestConformanceKata$' -json` writes to
a file. A `jq` step renders one row per property, PASS or FAIL, into the job
summary, and the raw JSON is uploaded as an artifact. The job's conclusion is
the test's exit code: red when properties fail, with no `continue-on-error`.
A red Kata run is the evidence, not a malfunction.

### From results to documentation

After the first real run, a follow-up change on this branch adds an *Under Kata*
section to `THREAT_MODEL.md` classifying each failing property as a real
difference or as gVisor-shaped, and amends `SECURITY.md`'s wording on
non-`runsc` evidence to "measured by openblox on amd64, not merge-gating".

## Predictions, recorded before the first run

- **Host-local tier:** the probe already shows a guest process is invisible to
  the host's `/proc`. The positive control from #61 should report "cannot
  measure" rather than pass.
- **`propKillGroupWaitsForLateRecord`:** feared to fail on exec latency inside
  its 100 ms `Timeout`. The measured round trip is ~30 ms, so it may hold; if
  it fails, the failure is still reported, not tuned.
- **`known-escape-setsid-survives-the-timeout-kill`:** unmeasured. Under a
  separate kernel the process-group semantics are the guest's own, so the
  result may differ in kind from gVisor's.

## Out of scope

- **arm64.** Hosted arm64 runners expose no KVM. The alternative is a
  self-hosted runner, which for a public repository means executing strangers'
  pull requests on our own hardware — the same reason `ci.yml` rejected one for
  gVisor.
- **QEMU TCG emulation.** A bare Kata kernel reaches init in ~1.6 s under TCG,
  but Kata's shim requires KVM. Measuring a configuration nobody deploys is not
  evidence about Kata.
- **Other Kata hypervisors** (Cloud Hypervisor, Firecracker, Dragonball). The
  default configuration is the one measured. Adding another is a new row, not
  a change to this design.
- **Making any property pass**, and any change to `pkg/conformance`.

## Risks

- **KVM on hosted runners is undocumented.** GitHub has not committed to it
  ([actions/runner-images#12933](https://github.com/actions/runner-images/issues/12933)
  closed without an answer). The `kvm-ok` step makes its disappearance a
  legible red, and the weekly schedule notices it within a week.
- **A permanently red workflow gets ignored.** Mitigated by it being separate
  from CI and by the job summary naming which properties fail, so a change in
  the set is visible even while the colour is not.
