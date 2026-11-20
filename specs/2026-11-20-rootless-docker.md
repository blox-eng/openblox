# An operator knows, from a measured run, whether rootless Docker still caps a sandbox

Design for [openblox#6](https://github.com/blox-eng/openblox/issues/6).
Written 2026-11-20.

## Who, and the moment

The operator who sets up the host for `openbloxd`, first for Blox on staging and then on prod.
They hold a fresh host and the docs. They decide whether the Docker daemon runs rootless.
Evidence: `docs/security.md:137` says "Run the Docker daemon rootless" and links #6.
No document says whether the caps still hold under rootless. The repository measures nothing about rootless.

## Why it matters

Today the operator has two options.
- They follow the advice blind. A rootless daemon gets only the cgroup controllers that systemd delegates to the user, often just `memory` and `pids`.
  `runsc` also manages cgroups itself. A cap can become advisory, and a fork bomb or a memory hog then reaches the host.
- They ignore the advice. A socket compromise then yields root on the host, not an unprivileged user.

The cost of a wrong choice is a host outage or a host compromise. Both are estimated. Nothing is measured.

## The experience

1. The operator opens `docs/security.md` (or a page it links). They see one of two verdicts, with the date and the run that measured it:
   - **Supported.** The setup steps follow, with each required step, for example the systemd `Delegate=` drop-in for `cpu`.
   - **Not recommended with `runsc`.** A warning names each cap that does not hold and what that costs.
2. They see a per-property table: PASS, FAIL or SKIP for each conformance property and each resource-cap test under rootless Docker with `runsc`.
3. Things that can go wrong:
   - The host lacks a delegated controller. `Create` fails, and the error names the missing limit and the fix:
     `pids limit discarded by the docker daemon: delegate the "pids" cgroup controller to the daemon's user (see docs/security.md#rootless)`.
     The sandbox does not start.
   - `runsc` does not register under the rootless daemon. The existing `ErrRuntimeUnavailable` error appears. The docs give the registration step.

## Non-goals

- Rootless Podman, `userns-remap`, or any setup other than rootless Docker plus `runsc`.
- Rootless Kata.
- A setup script or `install.sh` change that configures rootless for the operator.
- Gating merges on rootless.
- Changing Blox's own staging or prod hosts.

## Anti-goals (failure even if it works)

- A sandbox starts under rootless with a memory, CPU or process cap that does not bite, and nothing reports it.
- The docs say "supported" while a cap is advisory.
- The workflow shows green while it measured nothing, or ran under the root daemon or under `runc`.
- The operator follows the docs and weakens the host, for example by widening the daemon user's privileges more than rootless requires.

## Surfaces

- **CI**: a new workflow runs on hosted runners. Harm to avoid: a widened token or an unpinned action. It uses `contents: read`, no persisted credentials, and SHA-pinned actions, as `kata.yml` does.
- No other sensitive surface touched. Checked: authentication, money, uploads, webhooks, secrets, an agent's tools, personal data.

## Rulings

- 2026-11-20 — Pick #6 over #57 §5 and #71 — because it is the only open issue that is not parked and it hardens the host Blox runs on. — the owner.
- 2026-11-20 — Ways shown:
  (1) local measurement only: fastest, but nobody can rerun it;
  (2) a non-gating `rootless.yml`, like `kata.yml`: reproducible, and the docs cite it;
  (3) a gating matrix entry: the strongest guard, but it gates on an unproven setup.
  Pick: (2), developed locally first. — the owner.
- 2026-11-20 — Both calls ruled yes: `Create` fails closed on a discarded-limit warning, and the rootless tooling is installed on the workstation. — the owner.
- 2026-11-20: spec approved. Decided by: the owner.
- 2026-11-20 — Nothing is made to pass. A failing property is a finding, documented as a warning. — the issue's acceptance, the owner.

## Left to the builder

- How the workflow installs rootless Docker and registers `runsc` with it.
- How the CPU cap is measured. No test covers it today.
- Where the setup section lives, in `docs/security.md` or `docs/production.md`, with one link from the other.

## Calls to check

- Should `Create` fail when Docker reports in `ContainerCreate`'s warnings that it discarded a limit? Today `pkg/docker/backend.go:194` ignores those warnings.
  Recommendation: yes, fail closed. This also covers root daemons on hosts without the controller. Cost if wrong: a cap silently becomes advisory, and this is the anti-goal above.
- Can I install the rootless tooling on this workstation (`apt install docker-ce-rootless-extras uidmap`, plus a per-user daemon on its own socket, with the root daemon untouched)?
  Recommendation: yes. It is the fast loop before CI. Cost if wrong: the per-user daemon and its packages must be removed by hand.

## Done when

- [ ] The `rootless` workflow runs on a PR and on demand. Its summary shows PASS, FAIL or SKIP for each conformance property and each cap test.
- [ ] The run fails before it measures anything unless the live daemon is rootless and the sandbox runtime is `runsc`.
- [ ] Each cap (memory, CPU, processes, scratch disk) has a measured result under rootless in that table.
- [ ] `docs/security.md` gives the verdict, the setup steps, and a warning for each cap that does not hold, each with a link to the run.
- [ ] On a host without the `pids` controller delegated, `Create` fails with an error that names the fix. No sandbox starts. (This applies if the first call above is ruled yes.)
