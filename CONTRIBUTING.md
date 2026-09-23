# Contributing

## Scope

Read this before proposing a feature. One rule decides what belongs in openblox:

> **How a sandbox is isolated is openblox's problem.
> Which sandbox runs where is yours.**

Isolation is in scope: runtimes, egress policy, filesystem, users, capabilities,
resource caps, lifetime bounds. Placement is not: scheduling, multi-node, tenancy,
metering, snapshot/resume, a control-plane API server, a database.

openblox is the layer below a sandbox platform. Anything on the placement side is
something you can build on top, and keeping it out is what keeps this small enough
to audit. A PR that crosses the rule will be declined on that basis, however good
it is — so please open an issue before writing one. [ARCHITECTURE.md](ARCHITECTURE.md)
has the reasoning.

## Setup

```bash
git clone https://github.com/blox-eng/openblox
cd openblox
make            # vet + lint + test
```

Requires Go 1.25+ and [golangci-lint](https://golangci-lint.run) v2.

### What `make test` does to your machine

`pkg/conformance` ships a negative control: a deliberately unisolated backend
that Core must fail against, property by property, because a conformance suite
which passes vacuously certifies nothing while looking authoritative. It runs
on every plain `go test ./...` — untagged, on purpose, since a control that can
be skipped is not a control.

Running it means the probes execute **on your own machine, as you**, not inside
a sandbox. Two consequences worth knowing before you see them in a log:

- **It opens TCP connections** to `172.17.0.1:22`, `172.17.0.1:2375`,
  `10.0.0.1:80`, `192.168.0.1:80`, `169.254.169.254:80`, `1.1.1.1:443`,
  `8.8.8.8:53` and `[2606:4700:4700::1111]:443`. These are the addresses a
  sandbox must not reach — the Docker bridge gateway, RFC1918 space, the cloud
  metadata endpoint, and public DNS/HTTPS. Under `-tags integration` they are
  dialled from inside the sandbox; against the negative control they are
  dialled from the host. On a corporate network this can trip an IDS; on a
  cloud VM the metadata dial reaches the real endpoint.
- **It writes and then removes files** under `/tmp` and `/dev/shm`, including a
  setuid copy of `/bin/sh` — that is the attack `writable-mounts-are-noexec-nosuid`
  measures. Every path carries a per-run unique suffix, so nothing of yours is
  overwritten, and `TestMain` removes them all before the binary exits.

Nothing here needs privilege, and nothing persists. If your environment cannot
tolerate the dials, run `go test` on the packages you are changing rather than
disabling the control.

**Install golangci-lint before you push.** `go vet` and `go test` catch less than
CI does — the lint step adds revive, gosec, errorlint, and bodyclose. Without it
on your PATH, `make lint` fails open and you learn about a style violation from a
red PR instead of from your terminal.

## Integration tests

Unit tests run anywhere. Integration tests are behind the `integration` build tag
and need a Docker host with [gVisor](https://gvisor.dev/docs/user_guide/install/)
registered as the `runsc` runtime:

```bash
make test-integration
```

CI runs them on every PR, on hosted amd64 and arm64 runners with gVisor
installed — including the conformance suite (`pkg/conformance`, run against
this repo's backend by `pkg/docker/conformance_integration_test.go`). If you
cannot run them locally, at least keep them compiling
(`go vet -tags integration ./...`) and let CI run them.

The conformance suite also runs under Kata, on a host with KVM and Kata
registered with Docker as `kata`:

```bash
go test -tags 'integration kata' -run '^TestConformanceKata$' -count=1 ./pkg/docker/
```

`.github/workflows/kata.yml` runs it on amd64 as evidence, not as a gate; the
results are recorded in [THREAT_MODEL.md](THREAT_MODEL.md#under-kata).

A security-relevant change should come with a conformance property that fails
without it. Phrase the attack so the test fails closed: print a marker only when
the attack *succeeds*, and assert the marker is absent — so a probe that silently
fails to run can never read as containment.

## Conventional commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/);
CI enforces it and releases are cut from it.

```
feat(sandbox): add per-command timeout clamping
fix(docker): drop CAP_NET_RAW on create
docs: explain the egress default
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `revert`.
A `feat` bumps the minor version, a `fix` the patch. Breaking changes need a
`!` and a `BREAKING CHANGE:` footer.

## Pull requests

- One concern per PR.
- Tests for behaviour you add or change.
- Godoc on every exported symbol — this is a library, and the doc comment is the API.
- CI must be green: vet, lint, race tests, vulnerability scan, and the gVisor
  integration suites. The Kata workflow is not part of that.

## Changing security defaults

The zero-option case being locked down is the property the whole library rests
on. Any PR that loosens a default, adds a fallback, or makes an escape hatch
easier to reach must say so explicitly in its description and explain the threat
model change. `TestNewSpecDefaultsAreLockedDown` is a tripwire, not a formality —
if you need to edit it, that is the conversation, not a detail.
