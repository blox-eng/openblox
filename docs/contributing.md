# Contributing

The full guide lives in
[CONTRIBUTING.md](https://github.com/blox-eng/openblox/blob/main/CONTRIBUTING.md). This
is the short version.

## Setup

```sh
git clone https://github.com/blox-eng/openblox
cd openblox
make            # vet + lint + test
```

Requires Go 1.25+ and [golangci-lint](https://golangci-lint.run) v2.

**Install golangci-lint before you push.** `go vet` and `go test` catch less than CI
does — the lint step adds revive, gosec, errorlint and bodyclose. Without it on your
PATH, `make lint` fails open and you learn about a violation from a red PR instead of
from your terminal.

## Tests

Unit tests run anywhere. Integration tests are behind the `integration` build tag and
need a Docker host with gVisor registered as `runsc`:

```sh
make test-integration
```

CI runs them on every PR, under gVisor on amd64 and arm64. If you cannot run them
locally, keep them compiling (`go vet -tags integration ./...`) and let CI run them.

The conformance suite also runs under Kata, given Kata registered as `kata` on a host
with KVM:

```sh
go test -tags 'integration kata' -run '^TestConformanceKata$' -count=1 ./pkg/docker/
```

CI runs that on amd64 in a separate workflow that does not gate merges.

## Working on the docs

```sh
pip install -r requirements-docs.txt
mkdocs serve      # http://127.0.0.1:8000
```

The docs are markdown in `docs/`, so a change to behaviour and the change to its
documentation belong in the same pull request.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/) — CI enforces it, and
releases are cut from it.

```
feat(sandbox): add per-command timeout clamping
fix(docker): drop CAP_NET_RAW on create
docs: explain the egress default
```

## Where to start

Issues labelled [`good first issue`](https://github.com/blox-eng/openblox/labels/good%20first%20issue),
or anything in the open backlog that looks like your kind of problem. If you are
planning something substantial, open an issue first so the design can be discussed
before you spend the effort.
