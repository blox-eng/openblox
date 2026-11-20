Spec: specs/2026-11-20-rootless-docker.md
Spec approved: 2026-11-20
Test command: `CGO_ENABLED=0 go test -count=1 ./... && CGO_ENABLED=0 go test -tags integration -count=1 -timeout 20m ./...`
Plan approved: 2026-11-20 by the owner
Next: builder:build

# Rootless Docker evidence — implementation plan

What the code says today:
- `Create` (`pkg/docker/backend.go:194`) drops `created.Warnings`. Docker reports a discarded limit only there.
- `sandbox.ErrRuntimeUnavailable` already means "the host cannot provide the required isolation; never fall back". `pkg/brokerapi/errors.go:60` maps it to 503 `runtime_unavailable`. A dropped cap is this error. No new sentinel is needed.
- `New` uses `client.FromEnv`, so `DOCKER_HOST` points the whole suite at a rootless socket with no code change.
- The caps are proven by `TestForkBombIsBoundedByTheProcessCap`, `TestMemoryHogIsKilledAndTheHostSurvives` and `TestFillingScratchHitsTheDiskCapNotTheHost` (`pkg/docker/limits_integration_test.go`). No test proves the CPU cap. `pkg/conformance` has no cap property.
- `kata.yml` plus `conformance_kata_integration_test.go` plus `.github/scripts/kata-summary.sh` is the pattern this plan copies.

## File map

- `pkg/docker/limits.go` (create) — turns Docker's create-time warnings and refusals about resource limits into `ErrRuntimeUnavailable` with the fix.
- `pkg/docker/limits_test.go` (create) — unit tests of `limits.go`, on Docker's exact strings.
- `pkg/docker/backend.go` (change) — `Create` calls `limits.go` and removes the container it refuses.
- `pkg/docker/limits_integration_test.go` (change) — adds the CPU-cap test.
- `pkg/docker/rootless_integration_test.go` (create, tags `integration rootless`) — the preflight, then conformance and the four cap tests as subtests of one `TestRootless`.
- `pkg/docker/rootless_nopids_integration_test.go` (create, tags `integration rootless_nopids`) — the negative control: no `pids` controller, `Create` refuses.
- `.github/scripts/conformance-summary.sh` (rename from `kata-summary.sh`) — renders any top-level test's per-property table; takes the test name.
- `.github/workflows/kata.yml` (change) — calls the renamed script.
- `pkg/docker/guestkernel_integration_test.go` (create, R16/R17) — one guest-kernel check that the rootless and Kata preflights share.
- `pkg/docker/conformance_kata_integration_test.go` (change, R17) — the Kata preflight also proves a separate guest kernel booted.
- `.github/workflows/rootless.yml` (create) — the non-gating evidence run.
- `.github/workflows/ci.yml` (change) — the compile-only `go vet` line adds the two new tags.
- `docs/security.md` (change) — the rootless section: verdict, setup, warnings, link to the run.
- `SECURITY.md`, `THREAT_MODEL.md` (change, only for a cap that fails) — the warning in the normative docs.
- `CHANGELOG.md` (change) — `[Unreleased]` entries.
- `.github/scripts/host-weakening-guard.sh` (create, R3) — fails when the docs offer a host-weakening shortcut as a setup step.

## Tasks

**Order (R2, D4):** Task 3 → Task 1 → Task 2 → stop rule → Tasks 4–8. Stop rule: if Task 3 finds that `runsc` under rootless runs only with a `--TESTONLY-*` or `--ignore-cgroups` flag, stop after Tasks 1–2 and bring the evidence to the owner. Do not start Tasks 4–6. R13 (D15) returns to the owner with Task 3–4's per-cap results, whether or not the stop rule fires. Task 7's docs part still runs (R12, D14): `docs/security.md:137` becomes a dated "Not recommended with `runsc`" verdict that quotes Task 3's output and says the evidence is one local run, with the R3 guard and a CHANGELOG line.

### Task 1: Create refuses a sandbox when Docker drops one of its limits

- **Files:** `pkg/docker/limits.go`, `pkg/docker/limits_test.go`, `pkg/docker/backend.go`.
- **Test first:** `TestDiscardedLimitIsRefused`, table-driven over Docker's exact warning strings. Copy them from moby's `daemon/daemon_unix.go` at the engine version CI runs, and cite the file and tag in a comment. Cases:
  - the PIDs warning (`... PIDs limit discarded.`) → `errors.Is(err, sandbox.ErrRuntimeUnavailable)`, message contains `pids` and `docs/security.md#rootless`;
  - the memory-limit warning (`... Limitation discarded.`) → same, names `memory`;
  - the swap warning (`... Memory limited without swap.`) → same, names `swap`. openblox sets swap equal to memory, so swap without a limit breaks the memory cap;
  - an unrelated warning (the image-platform mismatch) → `nil`;
  - no warnings → `nil`.
  Any create error → returned unchanged, as today. (`classifyCreateError` and its test cut by R10, D12: the R1 gate refuses `CPUCfsQuota:false` first.)
- **Wiring test (R7, D9):** `TestCreateRemovesAContainerWhoseLimitWasDiscarded` runs `Create` against an `httptest` fake Docker API, as `fakeexec_test.go:38-83` does. A create that returns a PIDs "discarded" warning → the fake sees `DELETE /containers/<id>?force=1` and no `/start`, and the error `Is` `ErrRuntimeUnavailable`. Info with `PidsLimit:false` → the fake sees no create request.
- **Regression contract (R8, D10):** the same fake-daemon test has a healthy case: Info all-true and a create without warnings → `/start` called and the sandbox returned. CI's integration job passes with no existing test edited.
- **Matching (R4, D6):** match on the keywords `discarded` or `without swap`, not on full sentences. Name the limit by keyword, or else say "a resource limit". Add one reworded `discarded` line to the table. No 29.x wording research (R10, D12): this is a backstop behind the R1 gate.
- **Run:** `CGO_ENABLED=0 go test -count=1 -run 'Discarded|DaemonWithoutCgroups|CreateRemoves' ./pkg/docker/`. Before: the build fails, `undefined: checkLimitWarnings`. After: passes.
- **Do:**
  - `checkLimitWarnings(warnings []string) error` returns the first match, wrapped as `fmt.Errorf("%w: the docker daemon discarded the %s limit; delegate the %q cgroup controller to the daemon's user (see docs/security.md#rootless)", sandbox.ErrRuntimeUnavailable, ...)`.
  - In `Create`, after `ContainerCreate`, on warnings that match, `ContainerRemove(Force: true)` the created container, then return the error. The sandbox never starts.
- **Also (R1, D3):** `checkDaemonCaps(info system.Info) error` in `limits.go`, called from `assertRuntime`. It refuses `CgroupDriver == "none"` and a false `MemoryLimit`, `PidsLimit`, `CPUCfsQuota` or `SwapLimit` (R9, D11), each with `ErrRuntimeUnavailable` and a fix that names the setting. Test `TestDaemonWithoutCgroupsIsRefused` covers the cases `none`, each flag false, and all true → nil.
- **Also (R13, ruled 2026-11-20 after Task 3):** `checkDaemonCaps(info, runtime)` also refuses when `info.SecurityOptions` holds `name=rootless` and the requested runtime is runsc: its name is `runsc`, or its registered path ends in `/runsc`. The error wraps `ErrRuntimeUnavailable`: `rootless docker cannot cap a runsc sandbox: runsc runs there only with --ignore-cgroups, so memory, CPU and process limits do not apply; run openbloxd against the root docker daemon (see docs/security.md#rootless)`. Cases: rootless + `runsc` → refused; rootless + a runtime named `gvisor` with path `/usr/bin/runsc` → refused; rootless + `runc` → nil (not measured, out of scope); root + `runsc` → nil. The fake-daemon test adds: Info rootless + runsc → no create request.
- **Done when:** the three tests pass, and `go test ./pkg/brokerapi/...` still passes. The broker returns 503 `runtime_unavailable` with the message, so a `brokerclient` caller gets the fix text. Add one assertion for that in `pkg/brokerapi`'s error tests if they do not already carry the message.
- **Commit:** `fix(docker): Create refuses a sandbox when Docker drops one of its limits`

### Task 2: the CPU cap is proven, not only set

- **Files:** `pkg/docker/limits_integration_test.go`.
- **Test first:** `TestBusyLoopIsHeldToTheCPUCap`. Create with `WithResources` at `CPUs: 0.5`. Start 4 busy loops for 6 s. Read `ContainerStatsOneShot` before and after. Assert (R15, D17) that `cpu_stats.throttling_data.throttled_periods` rises during the loop (if runsc leaves it empty, read `nr_throttled` from the container cgroup's `cpu.stat`), and that CPU-time / wall-time ≤ 0.75. On failure, print the counter and the ratio.
- **Run:** `CGO_ENABLED=0 go test -tags integration -count=1 -run TestBusyLoopIsHeldToTheCPUCap ./pkg/docker/` on the root daemon with `runsc`. First run with the cap removed in a scratch edit: the test must fail (ratio ≈ cores). That is the proof that it bites. Then restore the cap: it passes.
- **Do:** only the test. If `docker stats` reports no CPU under `runsc`, read the container's host cgroup `cpu.stat` instead, and say so in the test comment.
- **Done when:** it passes on the root daemon, and it failed with the cap removed.
- **Commit:** `test(docker): a busy loop is held to the CPU cap`

### Task 3: spike — rootless Docker with runsc on the workstation

Outside the repository, approved on 2026-11-20.
- **Do:** `sudo apt install rootlesskit uidmap slirp4netns` (Ubuntu's `docker.io` host; see Changes during build). Then `dockerd-rootless-setuptool.sh install`. The root daemon is untouched. Register `runsc` in `~/.config/docker/daemon.json` with no extra flags first. Record each flag that it needed, for example `--ignore-cgroups`. A flag that turns off cgroups is a finding, not a fix.
- **Run:** with `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock`: `docker info` (look for `rootless` and the cgroup controllers), the four cap tests, `TestConformance`.
- **Record (R11, D13):** under a `Delegate=cpu memory` drop-in, `docker info` flags next to `cgroup.controllers` of `/user.slice/user-$UID.slice` and of `user@$UID.service`. Note any setup that makes Docker report `PidsLimit: false`.
- **Record:** in a local build log (not committed), each controller delegated by default, each step needed, each cap test result, with the output quoted. Task 7 writes it up. Nothing is committed.
- **Never (R3, D5):** change `kernel.apparmor_restrict_unprivileged_userns`. If rootlesskit is denied, load the deb's bundled AppArmor profile; if that fails, stop and report.
- **Done when:** each of the four caps has a local PASS or FAIL under rootless, with its output.

### Task 4: one rootless test that refuses to measure the wrong daemon

- **Files:** `pkg/docker/rootless_integration_test.go`, `.github/workflows/ci.yml`.
- **Test first:** `TestRootless`. It first runs `requireRootlessRunsc`: `Info().SecurityOptions` contains `name=rootless`, and a created sandbox's `HostConfig.Runtime` is `runsc`, and (R16, D18) `uname -r` or `dmesg` inside that sandbox shows gVisor's signature, as ci.yml's verify step checks. Otherwise `t.Fatalf` before anything is measured. Shared helpers live in one file that both rootless tags build (finding 8b). Also (R17, D19): `requireKataApplied` requires the guest `uname -r` to differ from the host's, reusing the same guest-kernel helper. Then come the subtests: `t.Run("limits/<name>", TestForkBomb...)` for each of the four cap tests, then `conformance.Run` and `conformance.RunHostLocal` with `Name: "docker+rootless"`. Also (R5, D7): `previews/dial-port` and `previews/serves-exposed-port`, which call the two existing tests in `preview_integration_test.go`.
- **Run:** against the root daemon: `go test -tags 'integration rootless' -run '^TestRootless$' ./pkg/docker/`. Before the preflight exists, it measures the root daemon in silence. After, it fails with `daemon is not rootless`. Against the rootless socket from Task 3, it runs the suite.
- **Do:** the preflight and the subtests as above. In `ci.yml`, the `integration-build` vet line adds the tags `rootless` and `rootless_nopids`.
- **Done when:** red with a one-line reason on the root daemon. It reaches the properties on the rootless one.
- **Commit:** `test(docker): measure the caps and the conformance suite under rootless Docker`

### Task 5: the negative control — no pids controller, no sandbox

- **Files:** `pkg/docker/rootless_nopids_integration_test.go`.
- **Test first:** `TestRootlessWithoutPidsControllerRefusesCreate`. The preflight asserts that the daemon is rootless and that Docker's own `Info().PidsLimit` is false, the fact the R1 gate reads (R11, D13). Otherwise `t.Fatalf("Docker still reports pids; this run proves nothing")`. Then `Create` with the default resources: the error `Is` `ErrRuntimeUnavailable` and contains `pids`. `ContainerList` with openblox's label returns no container for that name.
- **Precondition (R11, D13):** use the setup that Task 3 found makes `PidsLimit` false. If Task 3 found none, cut this task and the CI `negative-control` job, and Task 7 says the refusal is proven by unit tests only.
- **Run:** locally, with that setup (first candidate: a `user@.service.d` drop-in `Delegate=cpu memory`), the user manager restarted, and the rootless daemon restarted. Before Task 1, the sandbox starts uncapped and the test fails. After Task 1, it passes. Remove the drop-in afterwards.
- **Done when:** passes under the drop-in, and fails with the "proves nothing" line without it.
- **Commit:** `test(docker): without the pids controller, Create starts no sandbox`

### Task 6: the rootless workflow

- **Surface:** CI.
- **Files:** `.github/workflows/rootless.yml`, `.github/scripts/conformance-summary.sh` (renamed), `.github/workflows/kata.yml`.
- **Test first:** run the renamed script locally against three fixtures under the scratchpad: a real `-json` output from Task 4, an empty file, and a file with only a build error. The real output gives the table with `SKIP` rows kept. The other two exit 1 with "did not run" or "no property results". Also run `kata.yml`'s summary step logic on a Kata fixture with the `TestConformanceKata` argument. It produces the same table as before the rename.
- **Do:**
  - Rename the script. Its second argument is the top-level test name. Update `kata.yml` and its `paths:` filter.
  - `rootless.yml` copies `kata.yml`'s shape: `contents: read`, `persist-credentials: false`, SHA-pinned actions with the same pins, path-filtered PR, weekly cron, `workflow_dispatch`, no `continue-on-error`.
  - Steps: install `runsc` as `ci.yml` does → install the rootless extras → `dockerd-rootless-setuptool.sh install` as the runner user → register `runsc` with exactly the steps that Task 3 found → (R14, D16) `loginctl enable-linger "$USER"` and `XDG_RUNTIME_DIR=/run/user/$(id -u)` before setup; set `kernel.apparmor_restrict_unprivileged_userns=1` if the image ships `0`; fail with one `::error::` line unless the cgroup driver is `systemd` and that sysctl is `1` → verify that `docker info` says rootless and that the guest `uname -r` is gVisor's → `go test -tags 'integration rootless' -run '^TestRootless$' -json` → summary → upload.
  - A second job, `negative-control`, applies the `Delegate=cpu memory` drop-in and runs Task 5's test.
- **Hostile-input test for the CI anti-goal:** the workflow passes `actionlint`, and `grep -n 'uses:' rootless.yml` shows only 40-hex SHAs. A PR from a fork gets a read-only token, the same as `kata.yml`.
- **Run:** push the branch and dispatch the workflow (after the push yes). Before: no workflow. After: both jobs reach their tests, and the summary shows the table.
- **Done when:** the summary shows PASS, FAIL or SKIP for each conformance property and each `limits/*` row. The negative control is green.
- **Commit:** `ci: measure the caps and the conformance suite under rootless Docker`

### Task 7: the operator reads the verdict

- **Files:** `docs/security.md`, `CHANGELOG.md`, and `SECURITY.md` / `THREAT_MODEL.md` only if a cap fails.
- **Test first:** `.github/scripts/check-links.sh`, as Lint runs it, passes with the new anchor `#rootless`, which Task 1's error message names.
- **Do:** replace the one line at `docs/security.md:137` with a `## Rootless Docker` section, anchor `rootless`:
  - the verdict, dated, linking to the workflow run;
  - the setup steps from Task 3, including the `Delegate=` drop-in when `cpu` is not delegated by default;
  - a **Warning** block for each cap that failed, saying what an attacker gains;
  - what the `ErrRuntimeUnavailable` message means and its fix.
  Add a CHANGELOG `[Unreleased]` line for Task 1 (Fixed) and one for the workflow and the docs (Added).
- **Guard (R3, D5):** write `host-weakening-guard.sh` and add it to ci.yml's Lint job. Test first: a fixture with the sysctl in a setup step fails with the file and line; the same text on a `> **Warning` line passes; the real docs pass.
- **Done when:** the link check passes, and each statement in the section points to a row in the workflow's table.
- **Commit:** `docs(security): rootless Docker, measured: the verdict, the setup and its warnings`

### Task 8: review

Run the full test command above on the root daemon, then `TestRootless` on the rootless socket. Quote both outputs.
Before release (R6, D8): with the owner's yes for each host, run a read-only `docker info --format '{{.CgroupDriver}} {{.MemoryLimit}} {{.PidsLimit}} {{.CPUCfsQuota}} {{.SwapLimit}}'` on Blox staging and prod (SwapLimit added by R9, D11). A `none` driver or a false flag blocks the release.
Then load `builder:review` on the branch, against `specs/2026-11-20-rootless-docker.md`. There must be no open Critical or Important finding. Grep the staged diff for private names before each commit.

## Lens findings

- **Scope.** 12 files. The new parts are two test entry points and one workflow, mostly copies of the Kata pattern. Cut: a new sentinel error, because `ErrRuntimeUnavailable` already carries the meaning and the broker mapping. Cut: a second summary script, because the Kata one is generalised in Task 6.
- **Architecture: failure in production.** A host whose daemon is rootless and lacks the `pids` controller. Handled by Task 1, proven by Task 5.
- **Architecture: failure in production.** `runsc` needs `--ignore-cgroups` under rootless, so every cap is advisory while Docker reports nothing. Task 1 cannot see this. Tasks 3 and 4 measure it from inside, and Task 7 turns it into a warning. No change, because a measured FAIL is the spec's output.
- **Regression.** `Create`'s error for any other create failure stays as it was (Task 1's "returned unchanged" case). The Kata summary keeps its output (Task 6's fixture). Root-daemon runs see no warnings today, so Task 1 changes nothing there. Task 8's full run proves that.
- **Tests: map.** Discarded limit → Task 1. CPU refusal → Task 1. CPU cap holds → Task 2. Wrong daemon measured → Task 4. No pids, no sandbox → Task 5. Empty or broken run reads as green → Task 6. Broken doc link in the error → Task 7.
- **Performance.** One extra slice scan of the warnings per `Create`. The workflow is about 15 min on a hosted runner (estimated, from `kata.yml` minus the VM boots).
- **Design: the error.** 7/10 as drafted. A 10 names the limit, the cause and the fix in one line, with no Docker jargon beyond the controller name. The Task 1 format does that. Changed: the message names the controller in quotes and the docs anchor.
- **Design: the docs section.** Its states are measured supported, measured with warnings, and not measured yet (the run is red before the suite). Each needs its own words. Task 7 writes the verdict from the run, not from the plan. No change otherwise.
- **Architecture lens, error shape (#6).** The project's rule: one map in `pkg/brokerapi/errors.go`. Task 1 reuses it.

## Spec check

| Spec line | Task |
|---|---|
| The workflow's summary shows PASS, FAIL or SKIP per property and cap test | Task 6: the rootless workflow |
| The run fails before measuring unless rootless and `runsc` | Task 4: one rootless test that refuses to measure the wrong daemon |
| Each cap has a measured result under rootless | Task 2 (CPU test), Task 4, Task 6 |
| `docs/security.md` gives the verdict, setup and warnings, linked to the run | Task 7: the operator reads the verdict |
| Without `pids`, `Create` fails with the fix and starts no sandbox | Task 1, Task 5 |
| Anti-goal: a sandbox starts with a cap that does not bite, unreported | Task 1, Task 5 (Docker reports it); Tasks 2–4 (Docker does not report it) |
| Anti-goal: the docs say "supported" while a cap is advisory | Task 7: each statement points to a table row |
| Anti-goal: green while measuring nothing, or the wrong daemon or runtime | Task 4 preflight, Task 6 summary fixtures |
| Anti-goal: the docs widen the daemon user's privileges | Task 7: setup steps limited to what Task 3 proved necessary; Task 8 review |
| Surface CI: widened token or unpinned action | Task 6 hostile-input check |

## Calls

- The plan lives next to its spec in `specs/`, as `2026-09-22-kata-evidence-plan.md` does.
- Task 6 needs a push to run on GitHub. I ask before that push.

## Engineering review (/plan-eng-review, 2026-11-20)

Target: `specs/2026-11-20-rootless-docker-plan.md` (this file). Design doc: the approved spec `specs/2026-11-20-rootless-docker.md` (D1: /office-hours skipped).

### Scope record

feature answers: no cuts proposed; structure: A Original arrangement (D2); accepted scope: the 8 tasks and 12 files as planned, `pkg/docker/limits.go` + `limits_test.go` kept; pending remedies: R1, R2, R3, R4, R5.
Correction to D2's brief: it said `backend.go` is the longest file in `pkg/docker`. False: `sandbox.go` is 501 lines, `backend.go` 448 (`wc -l`). The answer stands; its reason was one job per file.
Scope Challenge result: scope accepted as-is.

## Decision ledger

### R1: refuse a daemon that cannot cap a sandbox, before Create
Finding: 1, P1, confidence 7/10, `pkg/docker/backend.go:299-307`, reviewer: Claude (plan-eng-review).
Plan baseline: Task 1 refuses only on Create-time warnings and the NanoCPUs refusal (plan approved 2026-11-20? no; original proposal).
Runtime evidence: static read only. Docker v28.5.2 `daemon/daemon_unix.go:592-593` picks cgroup driver `none` for a rootless daemon without systemd; `getSysInfo` (`:1636-1643`) then reads the root cgroup with no group path, so Create may warn about nothing. `info_unix.go:84-86` flags it in `docker info`. Unprobed on a live rootless daemon.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R1 Info gate in assertRuntime | absent (registered runtime only) | refuse `CgroupDriver == "none"` or any of `MemoryLimit`, `PidsLimit`, `CPUCfsQuota` false, as `ErrRuntimeUnavailable` naming the fix; unit test on an `Info` value + Task 5 control asserts it | no gate; Task 3 records whether `none` happens, and docs warn |
| Task 1 warning check | planned | planned, unchanged | planned, unchanged |
| R2–R5 | pending | pending | pending |
Question D3:
D3 — Refuse a Docker daemon that runs without cgroups, before creating anything?
ELI10: A rootless Docker daemon without systemd runs with no cgroups at all. Then Docker may accept a sandbox's memory and process limits and quietly drop them, with no warning, so the plan's Task 1 never sees it. docker info does say so. Checking it once per Create, next to the existing runtime check, closes that hole on every host, root or rootless.
Stakes if we pick wrong: a fork bomb or memory hog in a sandbox reaches the host, and openblox reports nothing.
Recommendation: A because it is the one silent path the warning check cannot see, and Info is already fetched in assertRuntime, so it costs no extra call.
Completeness: A=10/10, B=6/10
Header: D3 Info gate
Options:
A) Gate on docker info (recommended)
✅ Create refuses with ErrRuntimeUnavailable when the driver is "none" or info says memory, pids or CPU quota is unsupported, naming the fix. ✅ Reuses the Info call assertRuntime already makes, and a unit test plus the Task 5 control prove it. ❌ A host that reports an unsupported controller it never meant to use (for example no CPU quota) now refuses all sandboxes. (human: ~2 h / CC: ~15 min)
B) No gate, document it
✅ No new refusal path, so no host that works today can start failing after an upgrade. ✅ Task 3 still records whether the none driver happens in practice. ❌ The silent-drop path stays open, and only operators who read the docs avoid it.

State: approved
Actual answer: A) Gate on docker info (D3, 2026-11-20)
Accepted scope: `assertRuntime` refuses with `ErrRuntimeUnavailable`, naming the fix, when `Info().CgroupDriver == "none"` or `MemoryLimit` or `PidsLimit` is false, or `CPUCfsQuota` is false; unit test on `Info` values in `limits_test.go`; the Task 5 control asserts the refusal end to end. Task 1 warning check unchanged.
History: none

### R2: run the rootless spike first, with a stop rule
Finding: 2, P1, confidence 6/10, plan Task 3 and task order, reviewer: Claude (plan-eng-review).
Plan baseline: original proposal; the spike is Task 3, after Tasks 1–2, and has no stop rule.
Runtime evidence: unverified on this host. Public reports say `runsc` under rootless Docker needs `--ignore-cgroups` and `--TESTONLY-unsafe-nonroot` (gvisor.dev/docs/user_guide/rootless, google/gvisor#9918). The gVisor rootless guide says cgroup errors are ignored in rootless mode.
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| Spike position | Task 3 | first task | Task 3 | first task |
| Stop rule | none | if runsc runs only with a test-only or cgroup-ignoring flag: stop after Tasks 1–2, bring the evidence to the owner before Tasks 4–7 | none | none; measure under the flags, label the run "unsupported setup" |
| Tasks 1–2 (all hosts) | planned | unchanged | unchanged | unchanged |
| R1 | approved (D3) | approved, unchanged | approved, unchanged | approved, unchanged |
| R3–R5 | pending | pending | pending | pending |
Question D4:
D4 — Run the rootless spike first, and stop if runsc only works with test-only flags?
ELI10: Public gVisor reports say runsc under rootless Docker only starts with --ignore-cgroups and --TESTONLY-unsafe-nonroot. If that's true here, rootless + gVisor can't enforce caps, and a weekly CI workflow would keep re-proving an unsupported setup. Doing the one-hour spike first tells us before we build Tasks 4–7 around it. Tasks 1–2 help every host, so they go ahead either way.
Stakes if we pick wrong: about a day of CI and test plumbing built around a setup that turns out to be unsupportable, or a verdict published without a stop to re-plan.
Recommendation: A because it buys the deciding fact for an hour of work, and keeps the changes that help everyone.
Completeness: A=9/10, B=6/10, C=8/10
Header: D4 Spike
Options:
A) Spike first, stop rule (recommended)
✅ The deciding fact (does runsc run rootless without test-only flags?) arrives before any CI work. ✅ If it doesn't, you choose the next step with the evidence in hand: a warning-only verdict, or measuring anyway. ❌ One extra check-in, so this can pause mid-build. (human: ~1 h / CC: ~1 h, mostly install)
B) Keep the order
✅ No pause; the build runs straight through as approved. ✅ Tasks 1–2 still land first. ❌ Tasks 4–7 may be built and published around flags nobody should run in production.
C) Spike first, measure anyway
✅ No pause, and the workflow records exactly which caps fail under the flags that make it run. ✅ The weekly run notices when gVisor gains proper rootless support. ❌ The repo then carries CI for a setup its own docs advise against, and the flags appear in a committed workflow.

State: approved
Actual answer: A) Spike first, stop rule (D4, 2026-11-20)
Accepted scope: Task 3 runs first. If `runsc` under rootless Docker runs only with a test-only flag (`--TESTONLY-*`) or a cgroup-ignoring flag (`--ignore-cgroups`), the build stops after Tasks 1–2 and brings the evidence to the owner before Tasks 4–7. Tasks 1–2 proceed either way.
History: none

### R3: never weaken the host to make rootless work
Finding: 3, P1, confidence 8/10, plan Tasks 3 and 7, spec anti-goal "the operator follows the docs and weakens the host", reviewer: Claude (plan-eng-review).
Plan baseline: original proposal; Tasks 3 and 7 say nothing about the AppArmor userns restriction or test-only runsc flags.
Runtime evidence: Docker's rootless troubleshooting page says Ubuntu 24.04+ restricts unprivileged user namespaces; the deb `docker-ce-rootless-extras` ships the rootlesskit AppArmor profile; the common shortcut is `kernel.apparmor_restrict_unprivileged_userns=0`, which lifts the restriction for every program on the host. Not yet probed on this workstation.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Rule in Tasks 3 and 7 | absent | Task 3 and the docs use only the deb's AppArmor profile; never the sysctl; a `--TESTONLY-*` flag appears in docs only inside a Warning, never in setup steps | same rule |
| Automated guard | absent | a Lint step fails when `docs/`, `SECURITY.md` or `THREAT_MODEL.md` contain `apparmor_restrict_unprivileged_userns=0` or `TESTONLY` outside a line that starts with `> **Warning` | none; Task 8 review checks it by hand |
| R1, R2 | approved (D3, D4) | unchanged | unchanged |
| R4, R5 | pending | pending | pending |
Question D5:
D5 — Forbid the host-weakening shortcuts, and guard it in Lint?
ELI10: On Ubuntu 24.04 rootless Docker hits a kernel restriction on user namespaces. The quick fix people post is a sysctl that removes that protection for every program on the machine. gVisor's rootless reports also lean on a --TESTONLY flag. Our docs must never hand an operator either one as a setup step. The question is whether a Lint check enforces that, or only the review does.
Stakes if we pick wrong: an operator copies a line from openblox's security docs and lowers the protection of their whole host.
Recommendation: A because the spec names this harm as an anti-goal, and a rule that matters needs a check that fails, not a reviewer's memory.
Completeness: A=10/10, B=7/10
Header: D5 Host guard
Options:
A) Rule plus Lint guard (recommended)
✅ Task 3 and the docs use only the deb's AppArmor profile, so the workstation and every operator keep the userns restriction. ✅ A Lint grep fails any future edit that puts the sysctl or a TESTONLY flag outside a Warning. ❌ One more small Lint step to maintain, and a Warning that needs the words must use the exact prefix. (human: ~1 h / CC: ~10 min)
B) Rule only, review checks
✅ No new Lint step; the rule lives in the plan and Task 8's review. ✅ Same behavior for this PR. ❌ A later docs edit can add the shortcut with nothing failing.

State: approved
Actual answer: A) Rule plus Lint guard (D5, 2026-11-20)
Accepted scope: Task 3 and the docs use only the deb's AppArmor profile for rootlesskit; the sysctl `kernel.apparmor_restrict_unprivileged_userns` is never changed on the workstation or recommended; a `--TESTONLY-*` flag appears in docs only on a line starting `> **Warning`. New `.github/scripts/host-weakening-guard.sh`, run by ci.yml's Lint job, fails on `apparmor_restrict_unprivileged_userns=0` or `TESTONLY` in `docs/`, `SECURITY.md`, `THREAT_MODEL.md` outside such a line, with fixtures proving it fails and passes.
History: none

### R4: match Docker's warnings so an engine upgrade cannot blind the check
Finding: 4, P2, confidence 8/10, plan Task 1 ("copy them from moby's daemon/daemon_unix.go"), reviewer: Claude (plan-eng-review).
Plan baseline: original proposal; exact full-string match on the v28.5.2 strings.
Runtime evidence: the module cache holds Docker v28.5.2 (`daemon_unix.go:424`, `:429`, `:483`: "... Limitation discarded.", "... Memory limited without swap.", "... PIDs limit discarded."). The host engine is 29.1.3 (`docker version`). The 29.x wording is unchecked.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Match rule | exact v28.5.2 strings | any warning containing `discarded` or `without swap` refuses; the limit is named by keyword (`PIDs`, `memory`, `swap`), else "a resource limit" | exact v28.5.2 strings |
| Test table | v28.5.2 strings | v28.5.2 strings + the same lines from the 29.x engine source + a reworded line containing `discarded` | v28.5.2 strings |
| R1–R3 | approved | unchanged | unchanged |
| R5 | pending | pending | pending |
Question D6:
D6 — Match Docker's "limit discarded" warnings by keyword, not exact text?
ELI10: Docker tells us it dropped a limit only through a warning sentence. The plan matches the exact sentence from Docker 28, but this machine runs Docker 29. If a later Docker rewords the sentence, an exact match quietly stops firing and the cap drops with nobody told. Matching on the stable words "discarded" or "without swap" keeps catching it.
Stakes if we pick wrong: after an engine upgrade, openblox again starts sandboxes whose caps Docker dropped, with no error.
Recommendation: A because the check exists to catch silence, so it must not go silent itself on a reworded message.
Completeness: A=9/10, B=6/10
Header: D6 Matching
Options:
A) Keyword match (recommended)
✅ Any warning saying a limit was "discarded" or memory runs "without swap" refuses, whatever Docker version wrote it. ✅ The test table carries the 28 and 29 wordings plus a reworded line, so drift shows up as a failing test. ❌ An unrelated future warning that uses "discarded" would also refuse, and the fix there is to narrow the keyword. (human: ~30 min / CC: ~5 min)
B) Exact strings
✅ Refuses only on the sentences we've read in Docker's source, so there are no false refusals. ✅ The simplest code. ❌ A reworded warning in a future engine slips through silently, which is exactly the failure this check exists to stop.

State: approved
Actual answer: A) Keyword match (D6, 2026-11-20)
Accepted scope: `checkLimitWarnings` refuses any warning containing `discarded` or `without swap`, naming the limit by keyword (`PIDs`, `memory`, `swap`) or else "a resource limit". Its test table holds the v28.5.2 lines, the same lines from the 29.x engine source, and one reworded line containing `discarded`.
History: narrowed by R10 (D12, 2026-11-20): the 29.x wording lines are dropped from the table; the keyword match stands as a backstop.

### R5: answer the issue's preview-relay question
Finding: 5, P2, confidence 9/10, issue #6 ("Does the preview relay still work?"), plan Task 4, reviewer: Claude (plan-eng-review).
Plan baseline: original proposal; `TestRootless` runs conformance and the four cap tests, no preview test.
Runtime evidence: `pkg/docker/preview_integration_test.go:67` `TestDialPortReachesALoopbackServerWithNoNetwork` and `:100` `TestPreviewServesAnExposedPort` exist; conformance has no preview property (grep of `pkg/conformance` property names).
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Preview under rootless | unmeasured | `TestRootless` adds subtests `previews/dial-port` and `previews/serves-exposed-port`, calling the two existing tests; the docs verdict states the result | unmeasured; the docs say so plainly |
| R1–R4 | approved | unchanged | unchanged |
Question D7:
D7 — Measure the preview relay under rootless, as issue #6 asks?
ELI10: Issue #6 lists four questions; the plan answers three. The fourth is whether preview links (the relay that lets someone open a port inside a sandbox) still work under rootless Docker. Two tests for that already exist. Running them inside the rootless test answers the question for two lines of code.
Stakes if we pick wrong: the issue closes with one of its four questions unanswered, and an operator finds out on the Blox host that previews broke.
Recommendation: A because the tests exist and the issue asks for it by name.
Completeness: A=10/10, B=5/10
Header: D7 Previews
Options:
A) Add preview subtests (recommended)
✅ TestRootless runs the two existing preview tests as subtests, so the workflow table shows a PASS or FAIL for previews. ✅ The docs verdict covers every question issue #6 asks. ❌ Two more rows in a run that is already about 15 minutes (estimated). (human: ~15 min / CC: ~2 min)
B) Leave it, say so
✅ Nothing more to run. ✅ The docs are honest that previews are unmeasured. ❌ The issue's own acceptance list stays incomplete, so #6 can't honestly be closed by this PR.

State: approved
Actual answer: A) Add preview subtests (D7, 2026-11-20)
Accepted scope: `TestRootless` adds `previews/dial-port` (`TestDialPortReachesALoopbackServerWithNoNetwork`) and `previews/serves-exposed-port` (`TestPreviewServesAnExposedPort`); the Task 7 verdict states the preview result.
History: none

### R6: check the Blox hosts against the new gate before release
Finding: A1 (Section 1), P2, confidence 6/10, plan Task 8 and the approved R1 gate, reviewer: Claude (plan-eng-review).
Plan baseline: R1 approved (D3): Create refuses when `docker info` reports driver `none` or `MemoryLimit`, `PidsLimit` or `CPUCfsQuota` false. Task 8 runs the suites on this workstation only.
Runtime evidence: live probe on this workstation's root daemon: `driver=systemd mem=true pids=true cfs=true swap=true`, so the gate passes here. Blox staging and prod hosts: unknown. Blox picks up daemon changes by upgrading openbloxd on the host, so a host with one flag false would refuse every Blox sandbox after that upgrade.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Blox host check | none | Task 8 adds: read `docker info` flags on Blox staging and prod (read-only, after the owner's yes for each host); a false flag blocks the release until fixed or ruled | none; the release note names the new refusal and its fix |
| R1–R5 | approved | unchanged | unchanged |
Question D8:
D8 — Read docker info on the Blox hosts before this gate ships?
ELI10: The new gate refuses to create sandboxes on a host where Docker says it can't enforce a limit. That's right for safety, but if a Blox host happens to report one flag as false, the openbloxd upgrade would stop every Blox code run at once. A read-only `docker info` on staging and prod before release tells us in a minute.
Stakes if we pick wrong: Blox code execution goes down on upgrade, and the fix happens under pressure.
Recommendation: A because it's one read-only command per host, and Blox in production is the current priority.
Completeness: A=10/10, B=6/10
Header: D8 Blox hosts
Options:
A) Check hosts first (recommended)
✅ A read-only `docker info` on Blox staging and prod, after your yes for each host, shows whether the gate would refuse. ✅ A false flag blocks the release before Blox ever sees a refusal. ❌ It needs host access and a yes for each host, so it adds a step outside the repo. (human: ~10 min / CC: ~5 min)
B) Release note only
✅ No host access needed from this session. ✅ The 503 error itself names the fix if a host is affected. ❌ The first sign of a problem would be Blox's code runs failing in production.

State: approved
Actual answer: A) Check hosts first (D8, 2026-11-20)
Accepted scope: Task 8 adds a read-only `docker info --format '{{.CgroupDriver}} {{.MemoryLimit}} {{.PidsLimit}} {{.CPUCfsQuota}}'` on Blox staging and prod, each after the owner's yes; a `none` driver or a false flag blocks the release until fixed or ruled by the owner.
History: none

### R7: prove Create removes a container whose limit Docker discarded
Finding: T1 (Section 3), P2, confidence 8/10, plan Task 1 ("ContainerRemove(Force: true) the created container, then return the error") and Task 5, reviewer: Claude (plan-eng-review).
Plan baseline: Task 1 unit-tests only the classifiers; Task 5's live control now refuses at the R1 Info gate before ContainerCreate, so no planned test reaches the remove-on-warning wiring.
Runtime evidence: `pkg/docker/fakeexec_test.go:38-83` already runs an `httptest` fake Docker API and builds a client with `client.WithHost` (also `attach_test.go:21-47`); `Backend.cli` is a concrete `*client.Client` (`backend.go:95`), so a fake daemon needs no production seam.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Remove-on-warning wiring test | none | `TestCreateRemovesAContainerWhoseLimitWasDiscarded` in `limits_test.go`: fake daemon answers inspect 404, Info all-true with `runsc`, image present, create 201 with a PIDs "discarded" warning; asserts `DELETE /containers/<id>?force=1` called, no `/start`, error `Is` `ErrRuntimeUnavailable`. A second case: Info `PidsLimit:false` → no create request at all | none; the classifier unit tests and code review stand in |
| R1–R6 | approved | unchanged | unchanged |
Question D9:
D9 — Unit-test Create's "remove the container and refuse" path with a fake Docker API?
ELI10: When Docker says it dropped a limit, Create must delete the half-made container and refuse. With the new Info gate, no live host reaches that code, because the gate refuses first. So only a fake Docker can prove the delete happens and the sandbox never starts. The repo already has a fake Docker API in its unit tests, so this needs no new hooks in the product code.
Stakes if we pick wrong: a later refactor drops the delete or starts the container anyway, and every test stays green.
Recommendation: A because it's the only test that can see this path, and it reuses an existing pattern.
Completeness: A=10/10, B=6/10
Header: D9 Wiring test
Options:
A) Fake-daemon unit test (recommended)
✅ Proves that a discarded-limit warning deletes the container and never starts it, and that a false Info flag sends no create at all. ✅ Reuses the httptest fake from fakeexec_test.go, with no production seam and no live daemon. ❌ The fake encodes our reading of Docker's API, so it can drift from the real daemon. (human: ~1.5 h / CC: ~10 min)
B) Classifier tests only
✅ Less test code to keep up. ✅ The classification logic is still fully covered. ❌ The delete-and-refuse wiring has no test at all, and a regression there is silent.

State: approved
Actual answer: A) Fake-daemon unit test (D9, 2026-11-20)
Accepted scope: `TestCreateRemovesAContainerWhoseLimitWasDiscarded` in `limits_test.go` on an `httptest` fake Docker API (pattern of `fakeexec_test.go:38-83`): a PIDs "discarded" warning → `DELETE /containers/<id>?force=1`, no `/start`, error `Is` `ErrRuntimeUnavailable`; Info `PidsLimit:false` → no create request.
History: none

### R8: regression contract for Create on hosts that work today
Finding: T2 (Section 3, REGRESSION RULE), P1, confidence 9/10, `pkg/docker/backend.go:186` (`if err := b.assertRuntime(ctx, spec.Runtime); err != nil {`) gains the R1 gate, and `:194` gains the warning check; reviewer: Claude (plan-eng-review).
Plan baseline: R1 (D3) and R7 (D9) approved; no explicit contract for what must not change.
Runtime evidence: live probe: this workstation's root daemon reports `systemd true true true`; CI's gating `integration` job (ci.yml:176-261) runs the full suite on a root daemon with `runsc`.
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| Behavior to preserve | implicit | on a daemon with driver `systemd` or `cgroupfs`, all four flags true, and no limit warnings: Create sends the same requests and returns the same results as today | same |
| Intentional change | R1, R4, R7 | refuse on `none`, a false flag, or a discarded-limit warning | same |
| Acceptance | none named | (1) fake-daemon happy case in the R7 test: Info all-true + create without warnings → `/start` called, sandbox returned; (2) `checkDaemonCaps` all-true → nil; (3) CI's gating integration job green with no test edited | (2) and (3) only |
| R1–R7 | approved | unchanged | unchanged |
Question D10:
D10 — How do we prove Create still works on hosts that work today?
ELI10: The new checks run on every Create, including Blox's normal root-Docker hosts. We need to pin down that those hosts see no change: the same Docker calls and the same result. The CI integration suite already runs on such a host. The question is whether a fast unit case also proves the happy path, so a break shows up in seconds instead of after a full integration run (about 2 minutes locally per the testing note; CI allows up to 20).
Stakes if we pick wrong: a check that wrongly refuses healthy hosts reaches Blox, and only the slow suite, or production, notices.
Recommendation: A because the happy case costs a few lines in the fake-daemon test you just approved, and it fails fast.
Completeness: A=10/10, B=8/10
Header: D10 Regression
Options:
A) Unit happy path + CI (recommended)
✅ The fake-daemon test also asserts that a healthy host starts the sandbox, so a wrong refusal fails in seconds. ✅ The CI integration job stays the real-daemon proof, with no test edited. ❌ A few more lines in the fake, which encodes our reading of Docker's API. (human: ~30 min / CC: ~5 min)
B) CI integration only
✅ Proof comes from a real daemon, with no fake involved. ✅ Nothing extra to write beyond the gate's own unit table. ❌ A wrong refusal shows up only after a full integration run, locally or in CI.

State: approved
Actual answer: A) Unit happy path + CI (D10, 2026-11-20)
Accepted scope: Contract: on a daemon with driver `systemd` or `cgroupfs`, all four flags true and no limit warnings, Create sends the same requests and returns the same results as today. Proof: (1) the R7 fake-daemon test adds a healthy case: Info all-true + create without warnings → `/start` called, sandbox returned; (2) `checkDaemonCaps` all-true → nil; (3) CI's gating integration job green with no existing test edited.
History: D10's brief first said "a 20-minute run"; corrected before sending to "about 2 minutes locally; CI allows up to 20".

### Outside voice (Claude subagent, native fallback; Codex not installed)
Completed in 168 s, before the 300 s timer (stopped). 8 findings: 4 High, 2 Medium, 2 Low. Parent verification: finding 2 confirmed (`daemon_unix.go:656` `sysInfo := daemon.RawSysInfo()`, the same sysinfo `info_unix.go:35-44` reports); finding 3 confirmed (`info_unix.go:36` `v.SwapLimit = sysInfo.SwapLimit`, absent from R1 and R6); finding 1 plausible (`pkg/sysinfo/cgroup2_linux.go:31` loads `sysInfo.cg2GroupPath`, set to the user slice by `getSysInfo`), unprobed.

### R9: gate and host-check SwapLimit too
Finding: OV3, High (outside voice), confidence 9/10 after parent check, `info_unix.go:36`; R1 accepted scope and R6 format string omit `SwapLimit`; reviewer: Claude subagent, verified by parent.
Plan baseline: R1 (D3) gates `none`, `MemoryLimit`, `PidsLimit`, `CPUCfsQuota`; R6 (D8) reads those four on Blox hosts; Task 1 refuses a "without swap" warning.
Runtime evidence: this workstation's root daemon reports `swap=true` (earlier probe). Blox hosts unknown. openblox sets swap equal to memory (`backend.go:356-357`), so no swap accounting means memory+swap is unbounded.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| SwapLimit in R1 gate | absent | `checkDaemonCaps` also refuses `SwapLimit == false`, fix names swap accounting | absent; Task 1 refuses the warning per Create | read SwapLimit on Blox hosts first (R6), then decide | unresolved |
| SwapLimit in R6 host check | absent | added to the format string | absent | added (read only) | unresolved |
| R1–R8 | approved | unchanged | unchanged | unchanged | unchanged |
Question D11:
D11 — Gate and host-check Docker's SwapLimit flag too? <outside voice finding 3>
ELI10: openblox caps memory and turns swap off by setting the two limits equal. If Docker can't account swap, that pairing breaks, and today's plan only notices per Create through a warning, while the pre-release check on the Blox hosts never looks. If a Blox host lacks swap accounting, the upgrade would refuse every sandbox and nothing before release would tell us.
Stakes if we pick wrong: either Blox code execution stops on upgrade, or memory caps leak into swap on hosts without accounting.
Recommendation: A because swap belongs with the other three flags, and adding it to the host check is what catches the Blox risk before release.
Completeness: A=10/10, B=5/10, C=8/10
Header: D11 SwapLimit
Options:
A) Apply this change (recommended)
✅ The gate refuses `SwapLimit:false` up front with a fix, like the other flags, and the Blox host check reads it before release. ✅ It closes the one flag the outside voice found missing from both. ❌ A host without swap accounting that works today will refuse sandboxes after upgrade, which the host check is there to catch first. (human: ~20 min / CC: ~3 min)
B) Keep this row's current value
✅ No change to approved R1 and R6. ✅ Task 1 still refuses the swap warning per Create. ❌ The Blox host check stays blind to the one flag that can refuse every sandbox on upgrade.
C) Investigate before choosing
✅ Reads SwapLimit on the Blox hosts first, so the decision rests on their real state. ✅ No gate change until then. ❌ The gate question stays open into the build, and the host read needs your yes per host anyway.
D) Defer this proposed change only
✅ Nothing changes now. ✅ Leaves the row visible as unresolved. ❌ Both the release risk and the swap leak stay open.

State: approved
Actual answer: A) Apply this change (D11, 2026-11-20)
Accepted scope: `checkDaemonCaps` also refuses `SwapLimit == false` (fix: enable swap accounting); the Task 8 Blox host check adds `{{.SwapLimit}}`. R1 and R6 otherwise unchanged.
History: the sent D11 labels for B–D were shortened ("B) Keep current value", "C) Investigate first", "D) Defer this change") versus the saved ones; descriptions identical; the chosen A label matched the saved label exactly.

### R10: shrink Task 1 to what the R1 gate cannot already see
Finding: OV2, High (outside voice), confidence 9/10 after parent check, `daemon_unix.go:656` (`sysInfo := daemon.RawSysInfo()`); reviewer: Claude subagent, verified by parent. Reopens part of R4 (D6) on new evidence: every limit warning and the NanoCPUs refusal derive from the same sysinfo that `Info` reports, so the R1 gate (now with SwapLimit, R9) refuses those hosts before ContainerCreate.
Plan baseline: Task 1 = `checkLimitWarnings` (keyword match, R4/D6) + `classifyCreateError` (NanoCPUs refusal) + a test table of the v28 and 29.x wordings + the R7/R8 fake-daemon tests.
Runtime evidence: static read of v28.5.2 only. Whether 29.x keeps one sysinfo for both paths is unchecked.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| `classifyCreateError` (NanoCPUs) | planned | cut, with its test | planned | read 29.x source, then decide | unresolved |
| Warning backstop | keyword match, R4 | kept as a backstop for engines whose Info and create paths diverge; table: the v28 lines + one reworded `discarded` line; no 29.x wording research | keyword match + 29.x table | unchanged until read | unresolved |
| R7/R8 fake-daemon tests | approved | unchanged | unchanged | unchanged | unchanged |
| R1–R3, R5, R6, R9 | approved | unchanged | unchanged | unchanged | unchanged |
Question D12:
D12 — Cut the CPU-refusal classifier and the 29.x wording research from Task 1?
ELI10: Docker decides whether to warn or refuse using the same host facts that `docker info` reports. Our new gate already refuses when those facts are bad, so Docker's own CPU refusal can never reach us, and its classifier would be dead code. The warning check stays as a cheap backstop in case a future Docker version splits the two paths. We stop researching every Docker version's exact wording because the gate is now the main defence.
Stakes if we pick wrong: we keep untestable dead code, or we drop a backstop that a future engine would have needed.
Recommendation: A because it removes code no live host can reach and keeps the one backstop that costs almost nothing.
Completeness: A=9/10, B=7/10, C=9/10
Header: D12 Trim T1
Options:
A) Apply this change (recommended)
✅ Cuts `classifyCreateError` and its test, which no host can reach once the gate refuses `CPUCfsQuota:false`. ✅ Keeps the keyword backstop and the fake-daemon tests, so a future engine that diverges is still caught. ❌ Relies on a static read of Docker 28's source for the claim that the CPU refusal is unreachable. (human: saves ~1 h / CC: saves ~5 min)
B) Keep this row's current value
✅ Belt and braces: every Docker refusal path keeps a classifier. ✅ No reopened decision. ❌ Dead code and a wording table to maintain for paths the gate already closes.
C) Investigate before choosing
✅ Reads the 29.x daemon source to confirm one sysinfo feeds both paths. ✅ The decision then rests on the engine we actually run. ❌ About 15 minutes of reading for a choice that changes little either way.
D) Defer this proposed change only
✅ Task 1 stays exactly as approved. ✅ The row stays visible. ❌ The build starts with a known-dead classifier in scope.

State: approved
Actual answer: A) Apply this change (D12, 2026-11-20)
Accepted scope: cut `classifyCreateError` and `TestCPURefusalIsRuntimeUnavailable`; keep `checkLimitWarnings` (keyword match) as a backstop, tested on the v28.5.2 lines plus one reworded `discarded` line; no 29.x wording research; R7/R8 fake-daemon tests unchanged.
History: R4 (D6) approved the keyword match on 2026-11-20; that answer stands for the backstop.

### R11: make the negative control test what Docker actually reads
Finding: OV1, High (outside voice), confidence 6/10 (plausible, unprobed), plan Task 5 and spec "Things that can go wrong" #1; `daemon_unix.go:1638-1640` sets the sysinfo group path to `/user.slice/user-$EUID.slice`, and `pkg/sysinfo/cgroup2_linux.go:31` loads that path's controllers; reviewer: Claude subagent, checked by parent.
Plan baseline: Task 5 removes `pids` with a `user@.service.d` `Delegate=cpu memory` drop-in; its preflight checks "the daemon's cgroup controllers"; R1 (D3) says the Task 5 control proves the refusal end to end.
Runtime evidence: unprobed. If systemd keeps `pids` enabled at the user slice, Docker's `PidsLimit` stays true under the drop-in, so neither the gate nor the backstop fires.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Task 3 records | caps tests, `docker info` | also, under the drop-in: `docker info` flags next to `cgroup.controllers` of the user slice and of `user@$UID.service` | as now | same as A, then decide Task 5 | unresolved |
| Task 5 preflight | daemon's own cgroup | Docker's `Info().PidsLimit == false` (what the gate reads); otherwise `t.Fatalf("Docker still reports pids; this run proves nothing")` | daemon's own cgroup | unchanged until Task 3 | unresolved |
| If no setup makes `PidsLimit` false | not considered | cut Task 5; the end-to-end claim rests on R1/R7/R8 unit tests, and the docs say so | not considered | decided after Task 3 | unresolved |
| R1–R10 | approved | unchanged except R1's "Task 5 control" proof moves to the units if Task 5 is cut | unchanged | unchanged | unchanged |
Question D13:
D13 — Make the "no pids" control check what Docker reads, and drop it if no setup can trigger it?
ELI10: The plan's negative test removes the pids controller from the user's systemd service and expects Docker to notice. But Docker looks one level up, at the user slice, where systemd usually keeps pids on. So the test might pass its own setup check and still prove nothing. The fix is to check Docker's own report, record both cgroups in the spike, and drop the live test if no setup really hides pids from Docker.
Stakes if we pick wrong: a green negative control that proves nothing, or a refusal claim in the docs that no test backs.
Recommendation: A because the test must check the same fact the gate reads, or its green result is meaningless.
Completeness: A=10/10, B=4/10, C=9/10
Header: D13 Neg control
Options:
A) Apply this change (recommended)
✅ Task 5's precondition becomes Docker's own `PidsLimit == false`, the exact fact the gate reads, so a green run means the refusal really happened. ✅ The spike records both cgroups, and if no setup hides pids from Docker, Task 5 is cut and the docs say the claim rests on unit tests. ❌ The live end-to-end proof may disappear if no real setup can produce the condition. (human: ~30 min / CC: ~5 min)
B) Keep this row's current value
✅ No reopened decision; Task 5 stays as approved. ✅ It still exercises a real rootless daemon. ❌ It may check the wrong cgroup and report green without testing the gate at all.
C) Investigate before choosing
✅ The spike measures both cgroups first, so the choice rests on what this host does. ✅ No plan change until then. ❌ Task 5's precondition stays wrong in the plan until someone comes back to it.
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ The build may produce a meaningless green control.

State: approved
Actual answer: A) Apply this change (D13, 2026-11-20)
Accepted scope: Task 3 also records, under the `Delegate=cpu memory` drop-in, `docker info` flags next to `cgroup.controllers` of `/user.slice/user-$UID.slice` and `user@$UID.service`. Task 5's preflight requires Docker's `Info().PidsLimit == false`, else `t.Fatalf("Docker still reports pids; this run proves nothing")`. If no setup found in Task 3 makes `PidsLimit` false, Task 5 and the CI negative-control job are cut, R1's end-to-end proof rests on the R1/R7/R8 unit tests, and Task 7's docs say so.
History: none

### R12: the stop rule still ships the "not recommended" docs
Finding: OV4, High (outside voice), confidence 9/10, plan line "Order (R2, D4)" ("Do not start Tasks 4–7") and `docs/security.md:137` ("**Run the Docker daemon rootless**, so a socket compromise yields an unprivileged user"); reviewer: Claude subagent, verified by parent.
Plan baseline: R2 (D4): if runsc needs a test-only or cgroup-ignoring flag, stop after Tasks 1–2 and bring the evidence to the owner before Tasks 4–7.
Runtime evidence: public reports (gVisor rootless guide, google/gvisor#9918) make that outcome likely; `docs/security.md:137` recommends rootless today without caveat.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Docs when the stop rule fires | none (Task 7 blocked) | Task 7's docs part still runs: `docs/security.md:137` becomes a dated "Not recommended with `runsc`" verdict citing Task 3's quoted output, with the R3 guard; CHANGELOG line; Tasks 4–6 still wait for the owner | none until the owner rules | owner rules at the stop, with this option offered | unresolved |
| R2 stop rule itself | approved | unchanged for Tasks 4–6 | unchanged | unchanged | unchanged |
| R1, R3–R11 | approved | unchanged | unchanged | unchanged | unchanged |
Question D14:
D14 — If the spike says runsc can't run rootless safely, still fix the docs right away?
ELI10: Our security docs tell operators "run Docker rootless" today. The spike will likely show that gVisor only runs rootless with test-only flags that turn the caps off. The stop rule as written pauses everything after the spike, including the docs, so the risky advice stays live while we decide. This change makes the docs flip to "not recommended with runsc", citing the spike's output, while the CI work still waits for you.
Stakes if we pick wrong: operators keep following advice we have evidence against.
Recommendation: A because correcting known-wrong security advice shouldn't wait on a decision about CI plumbing.
Completeness: A=10/10, B=6/10, C=8/10
Header: D14 Stop docs
Options:
A) Apply this change (recommended)
✅ When the stop rule fires, docs/security.md still changes at once to a dated "Not recommended with runsc" verdict that quotes the spike, guarded by the R3 Lint check. ✅ Tasks 4–6 (CI and harness) still wait for your call. ❌ That verdict rests on one local run until CI evidence exists, and the docs say so. (human: ~1 h / CC: ~10 min)
B) Keep this row's current value
✅ One decision point covers everything after the spike. ✅ No docs change without your review of the evidence. ❌ The rootless recommendation stays live in the security docs while we wait.
C) Investigate before choosing
✅ You decide at the stop, with the spike output in hand. ✅ This option is then offered explicitly. ❌ Same as B until you answer; the risky line stays.
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ The plan can end its first phase with the security docs still wrong.

State: approved
Actual answer: A) Apply this change (D14, 2026-11-20)
Accepted scope: when the R2 stop rule fires, Task 7's docs part still runs: `docs/security.md:137` becomes a dated "Not recommended with `runsc`" verdict quoting Task 3's output and saying the evidence is one local run, with the R3 guard and a CHANGELOG line; Tasks 4–6 still wait for the owner.
History: none

### R13: refuse rootless + runsc at runtime if its caps are measured advisory
Finding: OV5, Medium (outside voice), confidence 7/10, spec anti-goal "a sandbox starts under rootless with a cap that does not bite, and nothing reports it"; plan Task 7 answers an advisory-cap result with docs only; reviewer: Claude subagent, checked by parent.
Plan baseline: R1/R9 gate refuses only what `docker info` admits; a cap that runsc ignores while Docker reports support (for example under `--ignore-cgroups`) passes the gate.
Runtime evidence: none yet; Tasks 3 and 4 produce it. `Info().SecurityOptions` carries `name=rootless` on a rootless daemon (Docker docs; unprobed here).
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Runtime refusal of rootless + runsc | none | now: `checkDaemonCaps` refuses `name=rootless` with runtime `runsc`, always (TestRootless would then measure only refusals) | none; docs warning only | pending: Tasks 3–4 record per-cap PASS/FAIL under rootless + runsc; the refusal choice returns to the owner with that evidence; no refusal is approved now | unresolved |
| R1–R12 | approved | unchanged | unchanged | unchanged | unchanged |
Question D15:
D15 — Should openblox refuse rootless Docker with runsc when the caps don't hold there?
ELI10: Our gate catches hosts where Docker admits it can't enforce a limit. It can't catch gVisor quietly ignoring cgroups under rootless while Docker reports everything fine. If the spike shows that happens, a docs warning alone leaves the anti-goal open: sandboxes start uncapped and nothing reports it. Refusing rootless + runsc in code closes it, but only makes sense if the measurement says the caps fail.
Stakes if we pick wrong: either uncapped sandboxes on rootless hosts with only a docs warning, or a refusal that blocks a setup that actually works.
Recommendation: C because the right answer depends on what Tasks 3–4 measure, and you then decide with that evidence in hand.
Completeness: A=7/10, B=5/10, C=10/10
Header: D15 Refuse rr
Options:
A) Apply this change
✅ Closes the gap now, whatever the measurement says. ✅ Simple: one more condition in the existing gate. ❌ Refuses a setup that might turn out to work, and TestRootless could then only measure refusals. (human: ~30 min / CC: ~5 min)
B) Keep this row's current value
✅ No new refusal path; operators get a docs warning. ✅ No risk of blocking a working setup. ❌ If a cap is advisory, sandboxes start uncapped on such hosts and nothing reports it, which is the spec's own anti-goal.
C) Investigate before choosing (recommended)
✅ Tasks 3–4 record per-cap PASS or FAIL under rootless + runsc, and this choice comes back to you with that evidence. ✅ Approves no refusal now, so nothing blocks a setup that may work. ❌ One more decision after the spike, and the gap stays open until then. (human: 0 now / CC: 0 now)
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ The anti-goal gap has no owner.

State: resolved
Actual answer: C) Investigate before choosing (D15, 2026-11-20), then refuse (owner, 2026-11-20, after Task 3's evidence)
Accepted scope: investigation only. Tasks 3–4 record per-cap PASS/FAIL under rootless + runsc; this refusal choice returns to the owner with that evidence. No refusal is approved.
History: D15 was sent with option C listed first (recommended-first) rather than the saved A–D order; labels and descriptions matched the saved record.

### R14: the CI runner proves it matches the documented setup before measuring
Finding: OV6, Medium (outside voice), confidence 7/10, plan Task 6 ("register `runsc` with exactly the steps that Task 3 found"); `daemon_unix.go:588-594` (`cgroupDriver` returns `none` for rootless without systemd); reviewer: Claude subagent, checked by parent.
Plan baseline: Task 6 copies the workstation steps to `ubuntu-latest` and verifies only "rootless" and the gVisor guest kernel.
Runtime evidence: unprobed on a hosted runner. Hosted runners have no logged-in user session; the runner image's `kernel.apparmor_restrict_unprivileged_userns` value is unknown.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Runner user session | not addressed | `loginctl enable-linger "$USER"` and `XDG_RUNTIME_DIR=/run/user/$(id -u)` before setup | not addressed | probe the runner first in a throwaway dispatch | unresolved |
| Pre-measure asserts | rootless, gVisor guest | also: `docker info` cgroup driver is `systemd`, and `kernel.apparmor_restrict_unprivileged_userns` is `1` (set it to `1` if the image ships `0`, so CI measures the protected setup the docs prescribe); each a one-line `::error::` | rootless, gVisor guest | same asserts, chosen after the probe | unresolved |
| R1–R13 | as recorded | unchanged | unchanged | unchanged | unchanged |
Question D16:
D16 — Make the CI runner prove it matches the documented rootless setup before measuring?
ELI10: GitHub's runners have no logged-in user session and may ship with the Ubuntu user-namespace protection already turned off. Then rootless Docker would run with no cgroups, our gate would refuse every sandbox, and the run would measure only refusals. Or it would run on a weakened host the docs tell operators never to create. A few asserts before measuring make either case one clear red line instead of a misleading table.
Stakes if we pick wrong: the evidence table measures a different setup than the one the docs recommend, and nobody notices.
Recommendation: A because the evidence is only worth something if it was taken on the setup we document.
Completeness: A=10/10, B=5/10, C=9/10
Header: D16 CI setup
Options:
A) Apply this change (recommended)
✅ The workflow enables linger and sets XDG_RUNTIME_DIR, then fails with one named line unless Docker's cgroup driver is systemd and the userns restriction is on. ✅ If the image ships the restriction off, the job turns it on, so CI measures the protected setup. ❌ Changing a sysctl on the runner is one more step that GitHub image updates could break. (human: ~1 h / CC: ~10 min)
B) Keep this row's current value
✅ Fewer steps in the workflow. ✅ The rootless and gVisor checks still run. ❌ A none-driver or weakened-host run can produce a table that looks like evidence and isn't.
C) Investigate before choosing
✅ A throwaway dispatch shows the runner's real session and sysctl state first. ✅ The asserts are then written against facts. ❌ Needs a push and a dispatch before the workflow exists, which is one more outside write needing your yes.
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ Task 6 is built without the asserts.

State: approved
Actual answer: A) Apply this change (D16, 2026-11-20)
Accepted scope: `rootless.yml` runs `loginctl enable-linger "$USER"` and sets `XDG_RUNTIME_DIR=/run/user/$(id -u)` before setup; before measuring it fails with one `::error::` line unless `docker info` reports cgroup driver `systemd` and `kernel.apparmor_restrict_unprivileged_userns` is `1`; if the image ships `0`, the job sets it to `1` first.
History: none

### R15: make the CPU-cap test resistant to noisy runners
Finding: OV7, Low (outside voice), confidence 6/10, plan Task 2 (`CPU-time / wall-time ≤ 0.5 × 1.3, and > 0.1`, in `limits_integration_test.go`, tag `integration`, which the gating CI job runs); reviewer: Claude subagent, checked by parent.
Plan baseline: ratio test with a 1.3× tolerance and a 0.1 floor, in the gating suite.
Runtime evidence: Docker's stats API carries `cpu_stats.throttling_data` (`ThrottledPeriods`) in the vendored client types; whether runsc fills it is unknown. Ratio flakiness on shared runners is estimated, not measured.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Proof the cap bites | ratio ≤ 0.65, > 0.1 | `ThrottledPeriods` rises during the busy loop (or the container cgroup's `cpu.stat` `nr_throttled`, if runsc leaves stats empty), plus a looser ratio ≤ 0.5 × 1.5; no floor | ratio ≤ 0.65, > 0.1 | run the ratio test 20× locally and on CI first | unresolved |
| Suite | gating `integration` | gating `integration` | same | same | same |
| Cap-removed control | must fail | must fail | must fail | must fail | must fail |
| R1–R14 | as recorded | unchanged | unchanged | unchanged | unchanged |
Question D17:
D17 — Prove the CPU cap with Docker's throttling counter instead of a tight timing ratio?
ELI10: The new CPU test checks that a busy loop gets about half a CPU. On a busy shared CI machine a timing ratio can wobble and fail the build for no real reason. The kernel counts every time it throttles the container, and that counter only rises when the cap is really biting. Using it, with a looser ratio as a sanity check, gives the same proof with less noise.
Stakes if we pick wrong: a flaky red in the gating CI job, or a CPU test that no longer proves the cap.
Recommendation: A because the throttle counter is the direct evidence that the cap bites, and it doesn't depend on runner load.
Completeness: A=9/10, B=7/10, C=8/10
Header: D17 CPU test
Options:
A) Apply this change (recommended)
✅ The test asserts that the throttle counter rises during the busy loop, which only happens when the cap bites, with a looser ratio ≤ 0.75 as a sanity check. ✅ The cap-removed control must still fail, so the test still proves something. ❌ If runsc leaves the stats counter empty, the test must read the host cgroup file instead, which is a bit more code. (human: ~1 h / CC: ~10 min)
B) Keep this row's current value
✅ Simplest test: one ratio, and the cap-removed control already proves it bites. ✅ No dependence on stats fields that runsc may not fill. ❌ A tight timing bound in the gating job can flake on a loaded runner.
C) Investigate before choosing
✅ Runs the ratio test 20 times locally and on CI to measure the real flake rate first. ✅ The choice then rests on numbers. ❌ Costs a CI dispatch (outside write, needs your yes) for a Low finding.
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ The flake risk ships as planned.

State: approved
Actual answer: A) Apply this change (D17, 2026-11-20)
Accepted scope: Task 2 asserts that `cpu_stats.throttling_data.throttled_periods` rises during the busy loop (or the container cgroup's `cpu.stat` `nr_throttled`, if runsc leaves stats empty) and that CPU-time/wall-time ≤ 0.75; no floor; the cap-removed control must still fail.
History: none

### Outside voice finding 8: dispositions
- 8a (weekly cron red while a cap fails): no change, the project's rule. `.github/workflows/kata.yml:7-8` ("Red is the expected colour while properties fail under Kata; the job summary says which, and a change in that set is the signal"). `rootless.yml` follows it.
- 8b (one `go vet -tags 'integration kata rootless rootless_nopids'` builds both rootless tag files together): factual correction, no behavior change. Plan note: shared helpers are never duplicated. The guest-kernel check lives in `pkg/docker/guestkernel_integration_test.go` (`//go:build integration`), which the rootless, rootless_nopids and kata builds all compile (R17); rootless-only helpers live in a file tagged `integration && (rootless || rootless_nopids)`.

### R16: prove runsc ran inside the test, not only in the workflow
Finding: OV8c, Low (outside voice), confidence 8/10, plan Task 4 (`requireRootlessRunsc`: "a created sandbox's `HostConfig.Runtime` is `runsc`"); same pattern as `pkg/docker/conformance_kata_integration_test.go` (`if got := inspect.HostConfig.Runtime; got != kataRuntime {`); reviewer: Claude subagent, checked by parent.
Plan baseline: the test checks the requested runtime name; only the workflow checks the guest kernel.
Runtime evidence: `HostConfig.Runtime` echoes the create request; a daemon that maps `runsc` to another binary would pass it.
Comparison grid:
| Choice | Current | A Apply | B Keep | C Investigate | D Defer |
|---|---|---|---|---|---|
| Preflight proof | `HostConfig.Runtime == "runsc"` | also exec `dmesg` or `uname -r` in the preflight sandbox and require gVisor's signature (as ci.yml's verify step does), else `t.Fatalf` | runtime name only | unresolved | unresolved |
| Kata test | runtime name only | unchanged (out of scope) | unchanged | unchanged | unchanged |
| R1–R15 | as recorded | unchanged | unchanged | unchanged | unchanged |
Question D18:
D18 — Make the rootless test itself prove the sandbox ran under gVisor?
ELI10: The test's safety check asks Docker which runtime it used, but Docker just repeats back what we asked for. The real proof is asking the sandbox's kernel who it is, which the workflow does but the test doesn't. Putting that check in the test means anyone running it locally gets the same guarantee.
Stakes if we pick wrong: a local run on a misconfigured daemon reports rootless+gVisor results that were measured under something else.
Recommendation: A because the check is a few lines and moves the guarantee into the test, where every run gets it.
Completeness: A=10/10, B=7/10
Header: D18 Guest check
Options:
A) Apply this change (recommended)
✅ The preflight runs `uname -r` (or `dmesg`) inside the sandbox and fails unless it shows gVisor's signature, the same check ci.yml uses. ✅ Local runs get the guarantee too, not only CI. ❌ A few more lines, and the gVisor signature string must stay in sync with ci.yml's check. (human: ~20 min / CC: ~3 min)
B) Keep this row's current value
✅ Matches the Kata test's existing pattern exactly. ✅ The workflow's guest-kernel step still guards CI. ❌ A local run can report results under the wrong runtime without any failure.
C) Investigate before choosing
✅ Leaves the decision open. ✅ No change now. ❌ There's nothing left to investigate; the facts are already known.
D) Defer this proposed change only
✅ Nothing changes now. ✅ The row stays visible. ❌ The gap ships as planned.

State: approved
Actual answer: A) Apply this change (D18, 2026-11-20)
Accepted scope: `requireRootlessRunsc` also execs `uname -r` (or `dmesg`) in the preflight sandbox and `t.Fatalf`s unless it shows gVisor's signature, matching ci.yml's verify step. The Kata test is unchanged.
History: none

### R17: TODO — the Kata preflight trusts the echoed runtime name
Finding: TODO from R16, Low, confidence 8/10, `pkg/docker/conformance_kata_integration_test.go` (`if got := inspect.HostConfig.Runtime; got != kataRuntime {`); reviewer: Claude (plan-eng-review).
Plan baseline: out of scope; the Kata test is unchanged.
Runtime evidence: `kata.yml` step "Verify Kata boots a separate kernel" guards CI; local runs have no guest-kernel check.
Comparison grid:
| Choice | Current | A GitHub issue | B Skip | C Build in this PR |
|---|---|---|---|---|
| Kata preflight | runtime name only | unchanged; issue filed after the owner's yes | unchanged | `requireKataApplied` also requires the guest `uname -r` to differ from the host's, reusing the R16 guest-kernel helper |
| R1–R16 | as recorded | unchanged | unchanged | unchanged |
Question D19: TODO: the Kata conformance preflight trusts Docker's echoed runtime name. What should happen to it? (A GitHub issue, recommended; B Skip; C Build it in this PR.)
Header: D19 TODO
State: approved
Actual answer: C) Build it in this PR (D19, 2026-11-20)
Accepted scope: Task 4 also changes `requireKataApplied` to require the guest `uname -r` to differ from the host's, reusing the R16 helper; file map adds `pkg/docker/conformance_kata_integration_test.go` (change).
History: D19 was sent before this pending record was saved (procedure miss, recorded here); the question, header, labels and descriptions above match what was sent. The skill's "Add to TODOS.md" option was adapted to "GitHub issue" because the owner's CLAUDE.md keeps dev tracking in GitHub only.

Approval readiness: PASS. Approved with their own answers: R1 (D3), R2 (D4), R3 (D5), R4 (D6, narrowed by R10), R5 (D7), R6 (D8), R7 (D9), R8 (D10, regression contract), R9 (D11), R10 (D12), R11 (D13), R12 (D14), R14 (D16), R15 (D17), R16 (D18), R17 (D19). Pending by the owner's choice: R13 (D15, investigate after Tasks 3–4). Factual notes without a question: D2 correction, finding 8a (project's rule), finding 8b and the guest-kernel helper placement.

## Review body

### NOT in scope
- Rootless Kata, rootless Podman and `userns-remap`: the spec's non-goals; this work measures rootless Docker with `runsc` only.
- Refusing rootless + runsc at runtime (R13): deferred by the owner until Tasks 3–4 measure the caps.
- Changing Blox's own staging or prod hosts: the spec's non-goal; R6 only reads `docker info` there, after a yes per host.
- Gating merges on rootless: the spec's ruling 2; `rootless.yml` stays non-gating like `kata.yml`.
- A docs-content linter beyond the two R3 keywords: nothing else is known to weaken a host.

### What already exists
- `sandbox.ErrRuntimeUnavailable` (`pkg/sandbox/errors.go:24-30`) and its broker mapping to 503 `runtime_unavailable` (`pkg/brokerapi/errors.go:60`, `:84-86`): reused for every new refusal, no new sentinel.
- `assertRuntime` already calls `Info` per Create (`backend.go:299-307`): the R1/R9 gate reuses that call.
- The Kata evidence harness (`conformance_kata_integration_test.go`, `kata.yml`, `kata-summary.sh`): copied for rootless; the summary script is generalised, not duplicated.
- The `httptest` fake Docker API (`fakeexec_test.go:38-83`): reused for the R7/R8 wiring and regression tests.
- The cap tests (`limits_integration_test.go:119`, `:180`, `:245`) and preview tests (`preview_integration_test.go:67`, `:100`): rerun under rootless as subtests, not rewritten.

### Diagram: Create after this plan

```
Create(name, opts)
  ├─ Open existing? ── running → return it
  │                └─ stopped → Destroy, continue
  ├─ assertRuntime(runtime)
  │    ├─ runtime not registered ............ ErrRuntimeUnavailable (today)
  │    └─ checkDaemonCaps(Info)  [R1, R9]
  │         ├─ CgroupDriver == "none" ....... ErrRuntimeUnavailable + fix
  │         ├─ Memory/Pids/CPUCfsQuota/Swap false ... ErrRuntimeUnavailable + fix
  │         └─ all true → continue
  ├─ ensureImage
  ├─ ContainerCreate
  │    ├─ error → conflict? Open : "create sandbox: %w" (unchanged, R10)
  │    └─ Warnings contain "discarded" | "without swap"  [backstop, R4/R10]
  │         └─ ContainerRemove(force) → ErrRuntimeUnavailable + fix   [R7 test]
  ├─ ContainerStart (rollback on failure, unchanged)
  └─ Open → sandbox                                                  [R8 test]
        │
openbloxd: errors.Is(ErrRuntimeUnavailable) → 503 runtime_unavailable, message kept
```

### Failure modes
| Path | Production failure | Test | Error handling | Visible? |
|---|---|---|---|---|
| R1/R9 gate | Blox host reports a flag false after upgrade | R8 unit + R6 host read before release | 503 with fix | yes |
| R1 gate | rootless daemon without systemd (`none`) | R1 unit (`TestDaemonWithoutCgroupsIsRefused`) | 503 with fix | yes |
| Warning backstop | a future engine warns while Info says supported | R7 fake-daemon test | remove + 503 | yes |
| runsc ignores cgroups under rootless while Info says supported | sandbox uncapped | Tasks 3–4 measure it (cap tests in-guest) | none at runtime until R13 is decided; docs warning (R12) | docs only: tracked as R13 |
| Rootless workflow | runner lacks systemd session or has userns restriction off | R14 asserts | one `::error::` line | yes |
| Summary | run dies before the suite | Task 6 fixtures | "did not run" + exit 1 | yes |
Critical gaps (no test, no handling, silent): 0. The runsc-ignores-cgroups row has a test (Tasks 3–4) and a pending owner decision (R13).

### Worktree parallelization strategy
| Step | Modules touched | Depends on |
|------|----------------|------------|
| Task 3 spike | host only (no repo files) | — |
| Tasks 1, 2 | pkg/docker | — |
| R3 guard | .github/scripts, .github/workflows | — |
| Tasks 4, 5, R17 | pkg/docker | Task 3, Tasks 1–2, stop rule |
| Task 6 | .github/workflows, .github/scripts | Task 4 |
| Task 7 | docs, SECURITY.md, THREAT_MODEL.md, CHANGELOG.md | Task 3 (stop path) or Tasks 4–6 |
Lane A: Task 1 → Task 2 → Tasks 4, 5, R17 (pkg/docker, sequential). Lane B: R3 guard (independent). Task 3 runs first on the host. Execution order: Task 3; then launch A + B; merge; stop rule; Task 6; Task 7; Task 8. Conflict flags: `.github/workflows/ci.yml` is touched by Lane B (Lint step) and Task 4 (vet tags): sequence them.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific finding above. Run with Claude Code or Codex; checkbox as you ship. Effort ratios assume tests ~50x, features ~30x, research ~3x.

- [ ] **T1 (P1, human: ~2h / CC: ~15min)** — pkg/docker — Refuse a daemon that cannot cap a sandbox (`checkDaemonCaps`: `none`, Memory/Pids/CPUCfsQuota/Swap)
  - Surfaced by: Scope Challenge finding 1 (R1, D3); outside voice finding 3 (R9, D11)
  - Files: pkg/docker/limits.go, pkg/docker/limits_test.go, pkg/docker/backend.go
  - Verify: `CGO_ENABLED=0 go test -count=1 -run 'DaemonWithoutCgroups' ./pkg/docker/`
- [ ] **T2 (P1, human: ~1.5h / CC: ~10min)** — pkg/docker — Fake-daemon tests: remove-on-warning, healthy-host regression contract
  - Surfaced by: Test review T1 and T2 (R7 D9, R8 D10)
  - Files: pkg/docker/limits_test.go
  - Verify: `CGO_ENABLED=0 go test -count=1 -run 'CreateRemoves' ./pkg/docker/`
- [ ] **T3 (P1, human: ~1h / CC: ~1h)** — host — Spike first with stop rule; record docker info next to both cgroups
  - Surfaced by: Scope Challenge finding 2 (R2, D4); outside voice finding 1 (R11, D13)
  - Files: none (task record only)
  - Verify: the local build log holds quoted `docker info`, both `cgroup.controllers`, and per-cap results
- [ ] **T4 (P1, human: ~1h / CC: ~10min)** — docs + CI — Never weaken the host; Lint guard
  - Surfaced by: Scope Challenge finding 3 (R3, D5)
  - Files: .github/scripts/host-weakening-guard.sh, .github/workflows/ci.yml
  - Verify: guard fixtures fail and pass as specified; `.github/scripts/host-weakening-guard.sh` exits 0 on main's docs
- [ ] **T5 (P1, human: ~1h / CC: ~10min)** — docs — Stop rule still ships the "Not recommended with runsc" verdict
  - Surfaced by: outside voice finding 4 (R12, D14)
  - Files: docs/security.md, CHANGELOG.md
  - Verify: `docs/security.md` no longer recommends rootless without the measured verdict; link check passes
- [ ] **T6 (P2, human: ~30min / CC: ~5min)** — pkg/docker — Keyword backstop only; cut the CPU classifier
  - Surfaced by: Scope Challenge finding 4 (R4, D6); outside voice finding 2 (R10, D12)
  - Files: pkg/docker/limits.go, pkg/docker/limits_test.go
  - Verify: `go test -run Discarded ./pkg/docker/`
- [ ] **T7 (P2, human: ~15min / CC: ~2min)** — pkg/docker — Preview subtests in TestRootless
  - Surfaced by: Scope Challenge finding 5 (R5, D7)
  - Files: pkg/docker/rootless_integration_test.go
  - Verify: workflow table shows `previews/*` rows
- [ ] **T8 (P2, human: ~10min / CC: ~5min)** — release — Read docker info on Blox staging and prod (incl. SwapLimit) before release
  - Surfaced by: Architecture A1 (R6, D8); outside voice finding 3 (R9, D11)
  - Files: none
  - Verify: quoted output per host; no `none` driver or false flag
- [ ] **T9 (P2, human: ~1h / CC: ~10min)** — CI — Runner proves the documented setup before measuring
  - Surfaced by: outside voice finding 6 (R14, D16)
  - Files: .github/workflows/rootless.yml
  - Verify: dispatch shows the linger, driver and sysctl asserts passing before the suite
- [ ] **T10 (P2, human: ~1h / CC: ~10min)** — pkg/docker — CPU test asserts the throttle counter
  - Surfaced by: outside voice finding 7 (R15, D17)
  - Files: pkg/docker/limits_integration_test.go
  - Verify: passes with the cap, fails with it removed
- [ ] **T11 (P2, human: ~30min / CC: ~5min)** — pkg/docker — Guest-kernel proof in the rootless and Kata preflights
  - Surfaced by: outside voice finding 8c (R16, D18); TODO (R17, D19)
  - Files: pkg/docker/guestkernel_integration_test.go, pkg/docker/rootless_integration_test.go, pkg/docker/conformance_kata_integration_test.go
  - Verify: `go vet -tags 'integration kata rootless rootless_nopids' ./...`; preflight fails on a runc-mapped daemon
_No new tasks from Code Quality or Performance._

### Unresolved decisions that may bite you later
- R13 (D15): refuse rootless + runsc at runtime if a cap is advisory. Answer: investigate; the refusal choice returns to the owner after Tasks 3–4.

### Completion summary
- Step 0: Scope Challenge — scope accepted as-is (5 findings, all remedies approved: R1–R5)
- Reality rows: 7/7 tier-1 rows emitted by hand (`gstack-plan-reality` needs `bun`, absent), 2 unverified premises
- Architecture Review: 1 issue found (A1 → R6)
- Code Quality Review: 0 issues found
- Test Review: diagram produced, 2 gaps identified (T1 → R7, T2 regression → R8)
- Performance Review: 0 issues found
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 1 item proposed to user (built in this PR per D19; the repo tracks dev work in GitHub, not TODOS.md)
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 1 in this review (R13)
- Outside voice: Codex not installed; native Claude Plan subagent completed in 168 s with 8 findings (no outside coverage credit)
- Parallelization: 2 lanes, 1 parallel / 1 sequential (plus the host spike first)
- Lake Score: 12/16 answers picked a 10/10 option
- Persistence: review log NOT saved; `gstack-review-log` needs `bun`, which is not installed

## Changes during build

- 2026-11-20, Task 3: this workstation runs Ubuntu's `docker.io` 29.1.3, not `docker-ce`, so `docker-ce-rootless-extras` does not exist in its apt sources. Ubuntu packages the binaries as `rootlesskit` (with `uidmap` and `slirp4netns`), but not the two scripts. The spike takes `dockerd-rootless.sh` and `dockerd-rootless-setuptool.sh` from moby `docker-v29.1.3/contrib`, matching the daemon version. Ubuntu's `apparmor` package already ships `/etc/apparmor.d/rootlesskit` for `/usr/bin/rootlesskit`, so the userns sysctl stays untouched. Task 6 is unchanged: hosted runners use `docker-ce`, where `docker-ce-rootless-extras` exists. Taken by this session; the operator docs (Task 7) name both install paths.
- 2026-11-20, Task 3 → stop rule fired. runsc under rootless Docker starts only with `--ignore-cgroups` (no flags: "systemd error: Interactive authentication required."; `--rootless`: "Rootless mode not supported with \"create\""). Measured against the root daemon as control: memory 128m held 400 MiB (root: OOM 137), pids 50 ran 205 (root: forks refused), CPU 0.5 used 410% (root: 50.6%), tmpfs 64m stopped at 64 MiB (holds). Docker reported every limit flag true and gave no create warning. Tasks 4–6 do not start.
- 2026-11-20, Task 7: the plan's link check, `check-links.sh`, checks only the HTML landing site (`www/`), and `mkdocs build --strict` does not check anchors. Replaced by `TestFixDocResolves`, which fails while `docs/security.md` has no `{ #rootless }` heading (the anchor every refusal message names), plus a local `mkdocs build --strict`. The guard's fixtures live in `host-weakening-guard-test.sh`, run by Lint. Under the stop rule the section is a verdict with evidence, not setup steps, and links #6 in place of a workflow run. Taken by this session.
- 2026-11-20, R13 ruled by the owner: refuse rootless + runsc in `checkDaemonCaps`. Task 1 gains that case (see Task 1, "Also (R13)").

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Outside Review | native Claude Plan subagent (Codex not installed) | Independent 2nd opinion | 1 | unavailable (native fallback completed) | 8 findings: 4 High, 2 Medium, 2 Low |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 (not persisted) | ISSUES OPEN | 3 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** Codex, plan-review phase: unavailable (not installed). Native Claude Plan subagent completed with 8 findings; dispositions: R9–R12, R14–R16 approved, R13 pending, 8a no change (project's rule), 8b factual note. No external coverage.
- **VERDICT:** no review CLEAR. Eng review issues are mapped to approved tasks; eng review required (this run's log is not persisted: `bun` missing).

**UNRESOLVED DECISIONS:**
- R13 (D15): refuse rootless + runsc at runtime if a cap is advisory; returns to the owner after Tasks 3–4.
