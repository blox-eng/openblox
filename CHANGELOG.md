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
