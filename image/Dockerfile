# openblox-sandbox — the reference userland openblox runs untrusted code in.
#
# openblox is a library and will run ANY image; this is the one it ships so that
# `go get` followed by Create() works without first authoring a Dockerfile. It is
# a starting point, not a requirement — build your own and pass WithImage().
#
# The contract an openblox image must satisfy is small, and all of it is here:
#
#   /bin/sh          openblox replaces the entrypoint with its own idle loop, so
#                    the image needs a shell but no CMD or ENTRYPOINT of its own.
#   a non-root USER  sandboxes must not run as uid 0. openblox does its own
#                    privileged bookkeeping as root explicitly, per exec.
#   nc or python3    the preview relay reaches a port inside the sandbox over the
#                    exec channel, because the container has no network
#                    interface. It uses nc when present and falls back to
#                    python3. An image with neither cannot serve previews.
#
# Debian rather than Alpine on purpose: sandboxes run Python, and musl has no
# manylinux wheels, so on Alpine every numpy/pandas install compiles from source
# inside the sandbox.
FROM python:3.12-slim-bookworm

# netcat-openbsd gives the preview relay its fast path; without it the relay
# falls back to python3, which works but pays interpreter startup per connection.
# bash because callers routinely hand the sandbox bash scripts, and /bin/sh on
# Debian is dash.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# uid/gid 1000 is the conventional first non-system user, and pinning it means a
# bind-mounted host directory maps to a predictable owner.
RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash sandbox

# The workdir callers get by default. openblox resolves relative paths against
# it, so it must exist and be writable by the sandbox user.
RUN mkdir -p /workspace && chown sandbox:sandbox /workspace
WORKDIR /workspace

# Fail the build rather than ship an image that silently cannot serve previews
# or run code. This is the contract above, asserted.
RUN command -v sh && command -v bash && command -v python3 && command -v nc

USER sandbox

# Deliberately no ENTRYPOINT or CMD: openblox sets its own. An image that
# insists on a foreground process of its own would be overridden anyway.
