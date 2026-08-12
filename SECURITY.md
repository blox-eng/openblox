# Security Policy

openblox exists to contain hostile code. Security reports get priority over everything else.

## Reporting a vulnerability

**Do not open a public issue.**

Use [GitHub private vulnerability reporting](https://github.com/blox-eng/openblox/security/advisories/new),
or email **security@openblox.sh**.

Please include a description, reproduction steps, and the impact you believe it has.
We will acknowledge within 72 hours and keep you updated until it is resolved.
Credit is given unless you prefer otherwise.

## Threat model

openblox assumes the code running inside a sandbox is **actively hostile**, and
that the data it processes is attacker-controlled. It is designed to contain:

- arbitrary code execution inside the guest, including compiled native code
- attempts to reach the host, the host network, or link-local metadata endpoints
- resource exhaustion: CPU, memory, disk, and process count
- data exfiltration over the network, including via DNS

## What openblox does not protect against

Stated plainly, because a threat model that only lists wins is marketing:

- **A gVisor escape.** We inherit gVisor's threat model and its CVEs. Keep `runsc` patched.
- **A malicious sandbox image.** The image is the guest's entire userland and is
  the caller's responsibility. Pin digests, not tags.
- **Side channels** between sandboxes co-resident on one host.
- **What you do with the output.** openblox contains execution; it does not
  sanitise results. Treat everything a sandbox returns as untrusted input.
- **A misconfigured host.** Mounting the container runtime's socket into a
  sandbox, or overriding the runtime to the host default, defeats the boundary
  entirely. openblox never does either; your deployment must not either.

## Supported versions

Pre-1.0: only the latest release receives fixes.
