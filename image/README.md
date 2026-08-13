# openblox-sandbox

The reference image openblox runs sandboxes in, published to
`ghcr.io/blox-eng/openblox-sandbox`.

You do not have to use it. openblox runs any image you point it at:

```go
sb, err := backend.Create(ctx, "my-sandbox", sandbox.WithImage("my-own-image:1.0"))
```

This one exists so that the default works — `Create()` with no options pulls it
and runs.

## Tags

| Tag | What it is |
|-----|------------|
| `:latest` | the most recent release |
| `:X.Y.Z` | that release, immutable by convention |
| `:edge` | tip of `main`, republished whenever `image/` changes |

**Pin the digest, not the tag.** The image is the sandbox's entire userland, so
it is worth the same scrutiny as a dependency:

```
ghcr.io/blox-eng/openblox-sandbox@sha256:...
```

Every publish prints the digest to its job summary.

## The contract

An openblox image must provide:

- **`/bin/sh`** — openblox replaces the entrypoint with its own idle loop, so the
  image needs a shell but no `CMD`/`ENTRYPOINT` of its own. One it declares is
  overridden.
- **a non-root default `USER`** — sandboxes must not run as uid 0. openblox does
  its own privileged bookkeeping as root explicitly, per exec.
- **`nc` or `python3`** — the preview relay reaches a port inside the sandbox
  over the exec channel, because the container has no network interface. It
  prefers `nc` and falls back to `python3`. An image with neither builds and runs
  fine but cannot serve previews.

The Dockerfile asserts all of it at build time, and the publish workflow
re-asserts it against the pushed manifest.

## What is in it

`python:3.12-slim-bookworm`, plus `bash`, `netcat-openbsd`, and `ca-certificates`,
running as `sandbox` (uid/gid 1000) with a writable `/workspace`.

Debian rather than Alpine deliberately: sandboxes run Python, musl has no
manylinux wheels, and on Alpine every `numpy`/`pandas` install compiles from
source inside the sandbox.

## Building it yourself

```sh
make image          # build locally as openblox-sandbox:dev
make image-verify   # assert the contract against that build
```

Layer your own on top:

```dockerfile
FROM ghcr.io/blox-eng/openblox-sandbox:latest
USER root
RUN pip install --no-cache-dir pandas
USER sandbox
```
