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
  over its Unix socket, satisfying the same contract the Docker backend does.
- `openbloxd`: `max_sandboxes` per profile, bounding how many sandboxes exist
  at once — the one resource dimension a profile did not otherwise cover.
  Exceeding it returns `429` with the new `at_capacity` error kind
  (`brokerapi.ErrAtCapacity`), distinct from a malformed request because the
  request is valid and may succeed once the reaper frees a slot. Unset means
  unlimited, so existing deployments are unchanged.

### Changed

- `sandbox.Info` gained a `Labels map[string]string` field and is no longer
  comparable. `info1 == info2` and `map[sandbox.Info]T` now fail to compile.
  This is additive in shape but breaking in Go's comparability sense — a
  reasonable trade pre-1.0, but callers relying on `Info` being comparable
  need to switch to comparing the fields they care about.
