# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are cut automatically from [Conventional Commits](https://www.conventionalcommits.org/);
see [RELEASING.md](RELEASING.md). While on `0.x`, a breaking change bumps the minor
version.

Sections: **Breaking** changes need action from you; **Security** entries fix a
weakness, and say who was affected; the rest are as in Keep a Changelog.

## [Unreleased]

### Added

- **`setup.sh`: a dedicated sandbox host from a fresh OS install.**
  `curl -fsSL https://openblox.sh/setup.sh | sh` takes a Debian 13 or Ubuntu
  24.04 machine to a working, hardened `openbloxd` host. It installs Docker,
  gVisor, the daemon and its service, a pinned sandbox image, an nftables
  firewall and automatic security updates. With `OPENBLOX_LISTEN`, it adds an
  mTLS listener with one client bundle per caller. It sizes `max_sandboxes`
  from RAM and finishes with a smoke-test sandbox. A re-run never rewrites
  your config or certificates. The generated `openblox-uninstall.sh` removes
  exactly what setup added. A new CI job, *Host setup (Ubuntu 24.04)*, runs
  all of it on a fresh VM. See
  [A dedicated host](https://docs.openblox.sh/self-hosting/).

- **Kata evidence: the conformance suite against a second runtime.** A new,
  non-gating workflow (`kata.yml`) runs `pkg/conformance` under Kata
  Containers on hosted amd64 runners and records which properties fail;
  the findings are in THREAT_MODEL.md under *Under Kata*. gVisor remains the
  default and the only runtime that gates merges. arm64 is not measured:
  hosted arm64 runners expose no KVM.

## [0.9.0] - 2026-09-22

### Added

- **`pkg/conformance`: a public conformance suite for `sandbox.Backend`.**
  `pkg/docker/adversarial_integration_test.go` was the most valuable code in
  the repository and the least reusable — 21 attacks nailed to one
  implementation. Its properties now live in `pkg/conformance`, expressed
  against the `sandbox.Backend` interface, so any implementation can be
  measured against the same claims `pkg/docker` is: `conformance.Run` (Core,
  21 properties, no skips — an implementation that cannot satisfy one fails
  it) and `conformance.RunHostLocal` (2 properties whose evidence only means
  something when the backend and the test share a machine, opt-in and never
  a Core result). `pkg/docker`'s own `TestConformance` is now the first
  consumer, in place of the deleted file. Ships with a negative control:
  a fake backend with no isolation whatsoever, asserted to fail every Core
  property but a documented, narrowly-scoped handful whose absence is a host
  confound rather than a defect in the control — so a probe that silently
  stopped asserting anything is caught at the moment it breaks, not years
  later. The reference image is pinned by digest, not by tag, for the same
  reason `SECURITY.md` already asks of every openblox user: a mutable tag
  lets whoever controls the registry replace what the probes run against and
  turn every property green.

### Breaking

- **`OPENBLOX_LEAK_ITERATIONS` is gone**, along with the test file it
  configured. The leak check it tuned is now `pkg/conformance`'s
  `host-retains-no-process-goroutine-or-descriptor` property, whose iteration
  count is a package constant (`hostLeakIterations`, `pkg/conformance/hostlocal.go`)
  rather than an environment variable — a caller-supplied lever is a run that
  can quietly measure less than it claims. To run a longer soak, raise the
  constant in source and re-run `go test -tags integration -run
  'TestConformance/host-retains-no-process-goroutine-or-descriptor' ./pkg/docker/`.

### Changed

- **The documentation site moves to `docs.openblox.sh`, and `openblox.sh`
  becomes a landing page.** Same pages, same MkDocs build, same workflow — only
  the domain changes — and the apex now says what openblox is instead of asking
  a reader to infer it from a documentation nav. The two halves are hosted
  separately, because one repository gets one custom domain on GitHub Pages;
  the DNS and hosting changes that complete the move are made outside this
  repository. Every documentation URL that used to sit on the apex
  (`/getting-started/`, `/production/`, `/security/`, `/image/`,
  `/contributing/`) redirects permanently to the same path on the subdomain,
  deep anchors included, so nothing you have linked or bookmarked breaks. The
  shields.io badge endpoints under `/badges/` moved with the site and redirect
  the same way; the README's badge URLs now point at the subdomain directly.
  `security@openblox.sh` and `conduct@openblox.sh` are unaffected — the mail
  records stay on the apex.
- **`openbloxd` can be installed with one command.** `install.sh` resolves the
  release for this machine, downloads the binary and the checksum published
  beside it, and installs nothing unless they match. Where the `gh` CLI is
  present it also verifies the Sigstore build attestation, because a checksum
  that ships in the same release as the binary proves the bytes arrived intact
  and not that the release is the one CI built. It refuses anything but Linux
  on amd64 or arm64 by name rather than failing obscurely later, and it is one
  function invoked on its last line, so a truncated download does nothing
  instead of running half a script. `go install` and `go get` still work and
  are still on the landing page.
- **The README leads with installing, and says where the installer comes from.**
  The landing page's first instruction is to pipe a script from `openblox.sh`
  into a shell, and the audience for a sandboxing project is the one that will
  refuse to do that without reading it — but nothing in the repository said the
  script was `www/install.sh`, so there was no way to tell that the URL serves
  what the repository contains. Both the README and
  [Running in production](https://docs.openblox.sh/production/) now name that
  file and link it, and both fetch the script once and run it from disk rather
  than piping `curl` into `sh` — otherwise the bytes a reader inspects are not
  the bytes that run, which is a poor thing to teach from this repository in
  particular.
  Production keeps the by-hand download-and-verify sequence beside the
  one-liner, because watching each step succeed on its own is the point when
  what you are installing is a policy broker.
- **The social card matches the site again.** It still carried the wording from
  before the landing page existed, so every link unfurl of `openblox.sh` showed
  a description the page itself no longer used. It now leads with what openblox
  does and carries the site's motto, and `make social-preview` renders it from
  [`social-preview.svg`](.github/assets/social-preview.svg) to the two PNGs that
  ship — the one GitHub serves for the repository and the one `og:image` points
  at — so the two cannot drift apart by hand again.
- The README and the landing page no longer claim "under 3,000 lines of Go".
  The `loc` badge, which is measured from the source on every deploy, had
  already reached 3,348 — so the one number in the prose was being contradicted
  by a badge three lines above it. The claim is now "small enough to read in an
  afternoon", which is the thing the number was standing in for and which no
  commit can quietly falsify; the badge keeps reporting the figure.
- openblox.sh counts page views with [Umami](https://umami.is), which sets no
  cookies and builds no cross-site identity. It is the only third-party request
  the page makes, and the Content-Security-Policy names its script host and its
  collection host in separate directives rather than widening to admit both.

### Added

- **The runtime named on openblox.sh is a control, and both runtimes are
  credited.** Clicking `gVisor` in the subhead walks the approved runtimes and
  the line under the install command follows it, each one linking to its own
  project — neither was attributed before, which was an oversight for two pieces
  of someone else's work the whole design rests on. The two are deliberately not
  presented as equals: selecting Kata says it is a separate kernel per sandbox
  and stronger than the default, and in the same breath that gVisor is what CI
  exercises, which is what
  [`SECURITY.md`](SECURITY.md#the-isolation-runtime) says at greater length.
  `runc` is not in the rotation; it is not an option, it is the absence of one.

### Fixed

- **The footer carries the real Blox Engineering mark.** It had been a
  hand-drawn hexagon standing in for a logo that exists. The mark is a single
  path with `fill="currentColor"`, which an `<img>` resolves in its own context
  and paints black — wrong on the dark theme — so it is drawn as a CSS mask
  tinted by the text beside it, and the attribution stays one object in both
  themes.
- **openblox.sh answers a missing page with a 404 instead of the landing page.**
  Cloudflare Pages falls back to `index.html` when nothing matches, so every
  mistyped or retired URL returned `200` with the front page — a soft 404, which
  tells a reader nothing and invites search engines to index every wrong address
  as a copy of the home page. `www/404.html` is that answer: the site's own
  chrome, what happened, and the four places worth going next, including
  `docs.openblox.sh` for the documentation links that used to live on this apex.
  It carries no script, because `app.js` drives widgets that page does not have
  and reaches for them unguarded, and because `_headers` sets `script-src 'self'`
  with no `'unsafe-inline'` — a policy worth more than a theme toggle on an
  error page. The theme still follows `prefers-color-scheme`.
- **`check-links.sh` no longer dies on a page that carries no `id`.** It
  collects every `id` on a page to resolve fragments with, and under `set -e` a
  `grep` that matches nothing exits non-zero and takes the script with it. A
  page with no `id` anywhere is perfectly valid — the new `404.html` is one —
  but the checker would stop there having printed only that page's name, which
  reads as a broken reference it declined to name. It was latent until now
  because `index.html` has ids. Both greps tolerate no matches; a reference that
  genuinely does not resolve still fails the build.
- **`SECURITY.md` no longer tells you that a stronger runtime is a weaker one.**
  It said "any other runtime runs untrusted code on the host kernel", and listed
  "do not set a runtime other than `runsc`" under *What you must not do*. Both
  are false for a microVM runtime such as [Kata](https://katacontainers.io),
  which registers with Docker as an OCI runtime exactly as `runsc` does and
  gives each sandbox a **separate guest kernel** — a stronger boundary than
  gVisor's user-space one. Anyone who had deliberately paid for that boundary
  was being told by the project's own security document that they had broken
  their deployment, and then told to undo it. Runtime strength is now documented
  as an ordering — `runc` reaches the host kernel in full, gVisor reaches the
  Sentry, a microVM reaches its own kernel — with the caveat that
  `THREAT_MODEL.md` §B1/§B2 and every test behind it are written against
  `runsc`, so on anything else you are trusting that runtime's evidence rather
  than openblox's. Nothing in the code changes: `Create` never enforced a single
  approved runtime, only that the configured one is registered with Docker, so
  Kata has worked since the backend was written and still fails closed
  (`ErrRuntimeUnavailable`) exactly as before.
- Why openblox is not a multi-backend abstraction is now written down in
  [`specs/2026-09-21-backend-scope.md`](specs/2026-09-21-backend-scope.md),
  rather than being answered one thread at a time. In short: an in-process WASM
  runtime is a genuinely stronger boundary than gVisor and still the wrong shape
  here, because `Files`, `StartProcess` and preview ports have no referent under
  it and the target workload installs things; and an interface whose methods
  return `ErrUnsupported` depending on configuration gives back, one level up,
  the visible-but-unreachable confusion `openbloxd` exists to remove. A microVM
  runtime is in scope precisely because it is the same integration point.
- The project now has a [Discord](https://discord.gg/ksxTebDjj), linked from
  the README, the landing page and the documentation, so a question that is not
  an issue has somewhere to go.
- After cutting a tag, the release workflow now opens the `docs:` PR that
  promotes `[Unreleased]` to that version, instead of leaving it for a
  maintainer. Only the heading and compare link are machine-written; the entries
  themselves stay hand-written, because the prose is the point. This closes a
  gap the changelog guard could report but not fix: every release blocked the
  next PR's Lint until someone did it by hand.

## [0.8.1] - 2026-09-21

### Fixed

- An operation against a stopped sandbox no longer flattens into an opaque
  `500 {"kind":"internal"}`. Exec, file and process calls now report the new
  `sandbox.ErrStopped` sentinel, sent over the broker as `409` with kind
  `stopped`, so a caller can tell "your sandbox is gone" from "the daemon is
  broken" without a second request to disambiguate. A sandbox that exhausts
  `memory_mb` is killed — ordinary behaviour for untrusted code, and the reason
  the cap exists — so this was a predictable state being reported as a server
  fault. The kill takes the whole sandbox rather than the offending process,
  which is now stated in the troubleshooting table: recovery is to create a new
  sandbox, not to retry.

## [0.8.0] - 2026-09-21

### Added

- Releases now attach `THIRD_PARTY_LICENSES.txt`: the full licence text of every
  module linked into the `openbloxd` binaries, plus the `NOTICE` files of the
  two that ship one. The binaries are statically linked, so they contain their
  dependencies' code, and Apache-2.0, MIT and BSD alike allow that copy only if
  the notices travel with it — previously nothing in a release carried them. The
  bundle is generated per release from `go list -deps`, never committed, so it
  cannot go stale against the dependencies it claims to describe. `make licenses`
  builds the same file locally.

## [0.7.0] - 2026-09-20

### Added

- `openbloxd`: an optional `listen` block for a mutual-TLS network listener,
  alongside (or instead of) the Unix socket — `socket` is now optional once
  `listen` is set. Every caller presents a client certificate; only Common
  Names on the configured allowlist are accepted, so a shared or mis-issued
  CA cannot silently grant access. The caller's verified CN is recorded on
  every request the daemon handles.
- `pkg/brokerclient`: `NewRemote` and `TLSFiles`, so a caller can reach
  `openbloxd` over the network with the same `sandbox.Backend` contract the
  Unix-socket client satisfies.

## [0.6.2] - 2026-09-20

### Fixed

- The CI step that installs gVisor had neither a timeout nor a retry, so a
  stalled package mirror consumed the job's whole budget and the run was
  *cancelled* rather than failed. A cancelled run is indistinguishable from no
  run at all to the release workflow, which gates on a green CI run, so a
  transient dependency stall could skip a release while reporting nothing. The
  step is now bounded well below the job's budget, and the three commands that
  reach the network retry with linear backoff.

## [0.6.1] - 2026-09-20

### Security

- **Release pipeline.** Published image versions can no longer be overwritten:
  the check that a version is unpublished now distinguishes the registry saying
  so from a network, registry or authentication fault, which it previously read
  as permission to push. The post-publish verification holds the `attestations:
  read` scope its own `gh attestation verify` needs, so it cannot fail for want
  of a permission after the assets are already public.

### Fixed

- The post-publish check of the sandbox image only ever got through the first
  platform. The local image store keys images by digest, and one index digest
  cannot hold two platforms' manifests at once, so pulling the `linux/arm64`
  manifest over the `linux/amd64` one already held under the same reference was
  refused — before the contract check ran on arm64, and before the attestation
  was verified at all, which sits after the loop. The image is now removed
  between platforms.

## [0.6.0] - 2026-09-20

### Breaking

- `WithUser` and the `openbloxd` profile `user` now accept only an explicit,
  numeric, non-zero `uid:gid`. Root (`0:0`), group 0, user names and a bare uid
  (`"1000"`) are refused: `Create` returns `ErrInvalid`, and `openbloxd` refuses
  to load such a config. A name is refused because the untrusted image resolves
  it and can map it to uid 0; a bare uid because Docker then takes its primary
  and supplementary groups from that image's `/etc/passwd` and `/etc/group`,
  which can include group 0. The default, `1000:1000`, is unaffected.
- `Create` on a stopped sandbox now replaces it with a fresh one under the
  options of that call (see Fixed).
- `Exec` keeps at most `sandbox.MaxOutputBytes` (16 MiB) of each of stdout and
  stderr. Output past that is drained and discarded, and the new
  `Result.Truncated` is set. Read large results with `ReadFile`, which streams.

### Security

- **Preview proxy could route a request to the wrong sandbox.** `preview.Handler`
  pooled upstream keep-alive connections under one shared host, so a request
  authorised for one sandbox port could be served over an idle connection to a
  *different* sandbox port that the same handler had proxied before. Anyone
  holding a valid preview token could receive another sandbox's responses when
  that sandbox's server kept connections alive. Every (sandbox, port) now has its
  own pool, and the dialler refuses an address that does not match the
  authorised route. Affects every release with previews (since v0.1.0), in both
  the library and `openbloxd` deployments.
- **Unbounded command output.** `Exec` buffered stdout and stderr without limit,
  so a sandbox printing continuously until its timeout could exhaust the memory
  of the calling process — or of `openbloxd`, taking down every sandbox it
  brokers. Output is now capped per stream (see Breaking).
- **Timed-out commands kept running.** On timeout or cancellation `Exec` stopped
  waiting, but the command — and anything it started — ran on inside the sandbox
  until the sandbox was reaped, and `ErrTimeout` said it had been killed. The
  command's process group is now killed with SIGKILL. A process that deliberately
  leaves the group (`setsid`) still survives; it stays bounded by the sandbox's
  CPU and process caps and its lifetime. This also applies when an `openbloxd`
  client disconnects mid-command. A command cancelled in the moment between the
  runtime starting it and its wrapper recording the group had no record to be
  killed by, which is the likeliest case for a client that disconnects as soon
  as it has asked; the kill now waits briefly for the record to appear.
- **An unknown egress policy gave the sandbox a network.** Backends ask whether
  the policy is `EgressNone` and attach an interface when it is not, so an
  `EgressPolicy` that was neither defined value — an unchecked conversion, or a
  constant from a newer version of the package — silently resolved to the
  permissive answer. `Create` now refuses it with `ErrInvalid`.
- **Root was not refused.** `WithUser` documented that root was forbidden but did
  not enforce it (see Breaking).
- **Swap doubled the memory bound.** Sandboxes are now created with
  `MemorySwap` equal to `Memory`; previously Docker allowed as much swap again
  on hosts with swap enabled.
- **Release pipeline.** The vulnerability gate passed when `govulncheck` itself
  failed to run; it now fails closed. The release workflow no longer runs the
  third-party semantic-release binary (downloaded unpinned at run time) with the
  release token, refuses to act on `workflow_run` events from pull requests
  (including those from a fork's `main`), and tags exactly the commit CI
  verified.

### Added

- `Result.Truncated`, `sandbox.MaxOutputBytes`, and `truncated` on the
  `openbloxd` exec response.
- `Spec.Validate`, called by `Create` before anything is created.
- Release artifacts are signed: GitHub artifact attestations (Sigstore) for SLSA
  build provenance of the `openbloxd` binaries and the sandbox image, and for a
  CycloneDX SBOM of each binary, published as `openbloxd-linux-<arch>.cdx.json`.
  Each release is downloaded, verified and executed on native amd64 and arm64
  runners after publishing. See [RELEASING.md](RELEASING.md#verifying-a-release).
- An adversarial integration suite (`pkg/docker/adversarial_integration_test.go`,
  `pkg/brokerclient/broker_adversarial_integration_test.go`): network, filesystem,
  privilege, process and timeout, output flooding, cross-sandbox isolation, crash
  recovery, daemon restart, client disconnect, and a create/destroy leak check.
- The gVisor integration suites now also run on arm64 in CI.
- [THREAT_MODEL.md](THREAT_MODEL.md) and [RELEASING.md](RELEASING.md).

### Changed

- Cancelling the context of an `Exec` now returns the context's error rather than
  `ErrTimeout`; `ErrTimeout` means the deadline passed.
- A command is now started through `sh`, which records its process group so a
  timeout can kill it, and then `exec`s the program — argv is still never
  parsed as shell syntax, and argv[0] is never taken for a shell builtin. A
  program that does not exist now yields exit code 127 with the shell's message
  on stderr. Images already needed `/bin/sh`.
- The sandbox image's base is pinned by digest.
- `publish-daemon.yml` and `publish-image.yml` no longer take a `tag` input: to
  re-publish a release, dispatch the workflow on the tag itself, so its
  attestation names the tag as its source.

### Fixed

- `Create` on a stopped sandbox returned it still stopped, so every `Exec`
  failed, although `Stop` documented that `Create` would bring it back. It now
  replaces it — not restarts it, which would revive the policy the sandbox was
  created under rather than the one asked for now; its tmpfs storage would not
  have survived either way. This also recovers a sandbox whose guest killed its
  own PID 1.
- `Create` handed back a stale sandbox when the daemon could not be reached for
  the liveness check that decides whether to replace a halted one, or when the
  sandbox was removed between being opened and being checked. The inspection
  error is now returned, and a sandbox that has vanished is replaced.
- `openbloxd` crashed at start-up on a negative `reap_interval`; it is now a
  config error.
- `ErrTimeout`'s documentation claimed the command had been killed.

## [0.5.0] - 2026-08-18

### Added

- `openbloxd`: `max_sandboxes` per profile, bounding how many sandboxes exist
  at once — the one resource dimension a profile did not otherwise cover.
  Exceeding it returns `429` with the new `at_capacity` error kind
  (`brokerapi.ErrAtCapacity`), distinct from a malformed request because the
  request is valid and may succeed once the reaper frees a slot. Unset means
  unlimited, so existing deployments are unchanged.

## [0.4.1] - 2026-08-17

### Fixed

- Restarting `openbloxd` broke clients that bind-mount its socket directory; the
  unit now keeps its runtime directory across restarts.

## [0.4.0] - 2026-08-17

### Added

- `openbloxd` binaries for `linux/amd64` and `linux/arm64` attached to each
  release, with the systemd unit and example config, and `openbloxd --version`.

## [0.3.0] - 2026-08-15

### Added

- `openbloxd`: a daemon that owns the Docker connection so its callers never
  need `/var/run/docker.sock`, with per-profile isolation policy resolved
  server-side from configuration alone.
- `pkg/brokerclient`: a drop-in `sandbox.Backend` that talks to `openbloxd`
  over its Unix socket, satisfying the same contract the Docker backend does.
- `docker.WithRegistryAuth` for pulling from a private registry.
- `Info.Labels`, so a caller's own bookkeeping labels round-trip through
  `List`/`Open`.

### Breaking

- `sandbox.Info` gained a `Labels map[string]string` field and is no longer
  comparable. `info1 == info2` and `map[sandbox.Info]T` now fail to compile.
  Compare the fields you care about instead.

## [0.2.1] - 2026-08-14

### Fixed

- The release workflow publishes the sandbox image again; Go 1.25.13.

## [0.2.0] - 2026-08-13

### Added

- A reference sandbox image, `ghcr.io/blox-eng/openblox-sandbox`, published from CI
  for `linux/amd64` and `linux/arm64` with an SBOM and build provenance.

## [0.1.0] - 2026-08-12

### Added

- Sandbox contract: `Backend`, `Sandbox`, options, and errors, with a restrictive
  default for every option.
- Docker backend on the gVisor (`runsc`) runtime: create, open, list, destroy,
  with containment applied at create and never relaxed by omission.
- `Exec` with per-call timeouts, a configurable ceiling, stdin, and stdout and
  stderr returned separately.
- `WriteFile` and `ReadFile`, streaming, over the runtime's control channel.
- `StartProcess` for detached background processes, idempotent per name.
- `Expose` and `Revoke`: HMAC-signed, expiring preview credentials, and an HTTP
  handler that proxies to a port inside a sandbox without giving it a network.
- `Reap` for idle and max-age lifetime bounds, holding no state of its own.
- Images are pulled when absent.

[Unreleased]: https://github.com/blox-eng/openblox/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/blox-eng/openblox/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/blox-eng/openblox/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/blox-eng/openblox/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/blox-eng/openblox/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/blox-eng/openblox/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/blox-eng/openblox/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/blox-eng/openblox/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/blox-eng/openblox/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/blox-eng/openblox/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/blox-eng/openblox/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/blox-eng/openblox/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/blox-eng/openblox/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/blox-eng/openblox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/blox-eng/openblox/releases/tag/v0.1.0
