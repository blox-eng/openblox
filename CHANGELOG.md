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

[Unreleased]: https://github.com/blox-eng/openblox/compare/v0.8.1...HEAD
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
