# The image contract

openblox runs whatever image you point it at. The contract it requires is small, and all
of it is checkable.

## What an image must provide

**`/bin/sh`** — openblox replaces the entrypoint with its own idle loop, so the image
needs a shell but no `CMD` or `ENTRYPOINT` of its own. One it declares is overridden.

**A non-root default `USER`** — sandboxes must not run as uid 0. openblox performs its
own privileged bookkeeping as root explicitly, per exec, rather than by running the
workload that way.

**`nc` or `python3`** — the preview relay reaches a port inside the sandbox over the
exec channel, because the container has no network interface. It prefers `nc` and falls
back to `python3`. An image with neither builds and runs fine but cannot serve previews,
and the failure names both.

That is the whole contract. Anything else is your application's business.

## The reference image

```
ghcr.io/blox-eng/openblox-sandbox
```

A Debian-slim Python base plus `bash`, `netcat-openbsd` and `ca-certificates`, running
as `sandbox` (uid/gid 1000) with a writable `/workspace`.

It exists so the default works — you should not have to author a Dockerfile before
running your first sandbox.

Debian rather than Alpine is deliberate: sandboxes run Python, musl has no manylinux
wheels, and on Alpine every `numpy`/`pandas` install compiles from source *inside the
sandbox*.

## Pin the digest, not the tag

```go
sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox@sha256:...")
```

The image is the sandbox's entire userland, so it deserves the same scrutiny as a
dependency. A tag can be repointed by whoever controls the registry; a digest cannot.
Every publish prints the digest it produced.

openblox pulls an absent image on create, but **never re-pulls a tag it already has** —
a mutable tag must not be able to silently change the guest's userland underneath a
running deployment.

## Building your own

Layer on top of the reference image and the contract is satisfied for you:

```dockerfile
FROM ghcr.io/blox-eng/openblox-sandbox:latest
USER root
RUN pip install --no-cache-dir pandas
USER sandbox
```

Starting from something else is fine too — assert the contract at build time so a
missing piece is a failed build rather than a broken preview in production:

```dockerfile
RUN command -v sh && command -v python3 && command -v nc
USER myuser
```

## Things that trip people up

**A read-only rootfs and `noexec` scratch.** Only `/tmp`, `/workspace` and openblox's
state directory are writable, and all three are `noexec`. Tooling that downloads an
executable at runtime and then runs it — `npx` fetching a package into `~/.npm`, for
instance — will fail. Bake it into the image and invoke it from a rootfs path.

**Scratch comes out of memory.** It is tmpfs, so a large `disk` budget consumes the
memory budget. Keep disk at or below memory.

**Image init does not run.** openblox overrides the entrypoint, so anything an image
expects to do at startup will not happen.
