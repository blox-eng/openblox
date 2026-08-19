# Contributing

## Scope

Read this before proposing a feature. One rule decides what belongs in openblox:

> **How a sandbox is isolated is openblox's problem.
> Which sandbox runs where is yours.**

Isolation is in scope: runtimes, egress policy, filesystem, users, capabilities,
resource caps, lifetime bounds. Placement is not: scheduling, multi-node, tenancy,
metering, snapshot/resume, an API server, a database.

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
installed — including the adversarial suite in
`pkg/docker/adversarial_integration_test.go`. If you cannot run them locally,
at least keep them compiling (`go vet -tags integration ./...`) and let CI run
them.

A security-relevant change should come with an adversarial test that fails
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
  integration suites.

## Changing security defaults

The zero-option case being locked down is the property the whole library rests
on. Any PR that loosens a default, adds a fallback, or makes an escape hatch
easier to reach must say so explicitly in its description and explain the threat
model change. `TestNewSpecDefaultsAreLockedDown` is a tripwire, not a formality —
if you need to edit it, that is the conversation, not a detail.
