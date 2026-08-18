# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut automatically from [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- Sandbox contract: `Backend`, `Sandbox`, options, and errors, with a secure
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
- `docker.WithRegistryAuth` for pulling from a private registry.
- `Info.Labels`, so a caller's own bookkeeping labels round-trip through
  `List`/`Open`.
- `openbloxd`: a daemon that owns the Docker connection so its callers never
  need `/var/run/docker.sock`, with per-profile isolation policy resolved
  server-side from configuration alone.
- `pkg/brokerclient`: a drop-in `sandbox.Backend` that talks to `openbloxd`
  over a Unix socket, satisfying the same contract the Docker backend does.
- `openbloxd`: `max_sandboxes` per profile, bounding how many sandboxes exist
  at once — the one resource dimension a profile did not otherwise cover.
  Exceeding it returns `429` with the new `at_capacity` error kind
  (`brokerapi.ErrAtCapacity`), distinct from a malformed request because the
  request is valid and may succeed once the reaper frees a slot. Unset means
  unlimited, so existing deployments are unchanged.
- `openbloxd`: an optional `listen` block for a mutual-TLS network listener,
  alongside (or instead of) the Unix socket — `socket` is now optional once
  `listen` is set. Every caller presents a client certificate; only Common
  Names on the configured allowlist are accepted, so a shared or mis-issued
  CA cannot silently grant access. The caller's verified CN is recorded on
  every request the daemon handles.
- `pkg/brokerclient`: `NewRemote` and `TLSFiles`, so a caller can reach
  `openbloxd` over the network with the same `sandbox.Backend` contract the
  Unix-socket client satisfies.

### Changed

- `sandbox.Info` gained a `Labels map[string]string` field and is no longer
  comparable. `info1 == info2` and `map[sandbox.Info]T` now fail to compile.
  This is additive in shape but breaking in Go's comparability sense — a
  reasonable trade pre-1.0, but callers relying on `Info` being comparable
  need to switch to comparing the fields they care about.
