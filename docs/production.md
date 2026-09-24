# Running in production

The quick start imports the library directly, which is the shortest path to a
working sandbox. It is not how to run openblox where it matters.

## Architecture

```
┌──────────────────────┐   Unix socket    ┌────────────┐  Docker API  ┌──────────────────┐
│ your application     │ ───────────────► │ openbloxd  │ ───────────► │ Docker + gVisor  │
│ pkg/brokerclient     │  (socket_group)  │ (profiles) │              │  └► sandbox      │
│ no Docker access     │                  │ holds the  │              │    (runsc, no    │
└──────────────────────┘                  │ socket     │              │     network)     │
                                          └────────────┘              └──────────────────┘
```

- **`openbloxd`** owns the Docker socket. Your application talks to it over a Unix
  socket and never touches Docker.
- **Profiles** in `openbloxd`'s config are the whole isolation policy: image,
  runtime, egress, user, resources, lifetime. A request names a profile; it cannot
  set any of these.
- **The container is the state.** There is no database. Restarting `openbloxd`
  loses nothing, and it reaps sandboxes on its own schedule.

!!! danger "Direct library mode holds root"
    Importing `pkg/docker` means your process talks to the Docker daemon, and access
    to the Docker socket is equivalent to root on the host. If that process is
    compromised — or tricked, for instance by a prompt injection reaching a code path
    you did not intend — the host is. Use direct mode for development, or where the
    process is as trusted as the host. Otherwise use `openbloxd`.

The full trust model is in
[THREAT_MODEL.md](https://github.com/blox-eng/openblox/blob/main/THREAT_MODEL.md).

## Supported environments

| Component | Supported | Tested |
|---|---|---|
| Host OS | Linux | Ubuntu (GitHub-hosted runners, every PR) |
| Architecture | `linux/amd64`, `linux/arm64` | both, natively, with the full gVisor integration suite on every PR |
| Docker Engine | a current release, with the API version negotiated | the release on GitHub's `ubuntu-latest` image; Docker 29.1 |
| gVisor (`runsc`) | a current release, registered as a Docker runtime named `runsc`; the default `systrap` platform needs no KVM | the latest release at CI time; `release-20260803.0` |
| Kata (optional) | a microVM runtime instead of gVisor, registered with Docker and named in the profile; needs KVM, nested on a VM host ([setup](getting-started.md#using-kata-instead)) | 4.2.0 (runtime-rs + QEMU), amd64 only, conformance suite in a separate workflow that does not gate merges; arm64 not measured |
| Go (library users) | the version in `go.mod` (1.25) or newer | 1.25 |
| macOS, Windows, Docker Desktop | not supported — gVisor and Kata run on Linux only | — |

## Compatibility

| Pair | Rule |
|---|---|
| `openbloxd` ↔ `pkg/brokerclient` | Use the same release. The wire format is not versioned separately; fields are only added, and older clients ignore new ones, but only matching versions are tested together. |
| openblox ↔ sandbox image | Any image that satisfies [the image contract](image.md). The reference image version `X.Y.Z` is built from the openblox tag `vX.Y.Z`, but any version of it works with any openblox release that has the same contract. |
| openblox ↔ runtime | Any runtime Docker can start: `runsc` unless the profile names another. openblox checks that the named runtime is registered and fails with `ErrRuntimeUnavailable` if not — it never falls back to `runc`. A microVM runtime such as Kata is a stronger boundary and is supported; of those, only Kata on amd64 is measured, and not as a merge gate. |
| openblox ↔ Docker | Any Engine whose API the bundled client can negotiate with. |

## Deploying `openbloxd`

Install it **on the host, not in a container**. Running it in a container with the
Docker socket mounted puts back the privilege it exists to remove.

Giving openblox a machine of its own? [A dedicated host](self-hosting.md) does
every step below, and the firewall, with one script.

**1. Install a verified release.** Pick a version rather than `latest`, and verify it
before installing (details in
[RELEASING.md](https://github.com/blox-eng/openblox/blob/main/RELEASING.md#verifying-a-release)).

The installer does the download, the checksum and — where `gh` is present — the
attestation. Its source is
[`www/install.sh`](https://github.com/blox-eng/openblox/blob/main/www/install.sh),
which is the file `https://openblox.sh/install.sh` serves. Fetch it once, read
it, and run that same file: piping `curl` into `sh` reads one response and runs
another, which on this host is not a distinction worth losing.

```sh
curl -fsSL https://openblox.sh/install.sh -o install.sh
less install.sh
sudo OPENBLOX_VERSION=v0.8.1 sh install.sh
/usr/local/bin/openbloxd --version   # must print v0.8.1, not "dev"
```

It installs the binary and nothing else — no unit, no config, no user. Steps 3
and 4 below need two more files from the same release:

```sh
gh release download v0.8.1 -R blox-eng/openblox \
  -p openbloxd.service -p openbloxd.example.yaml
```

The same steps by hand, for watching each one succeed on its own:

```sh
VERSION=v0.8.1; ARCH=amd64
gh release download "$VERSION" -R blox-eng/openblox \
  -p "openbloxd-linux-$ARCH" -p "openbloxd-linux-$ARCH.sha256" \
  -p openbloxd.service -p openbloxd.example.yaml
sha256sum -c "openbloxd-linux-$ARCH.sha256"
gh attestation verify "openbloxd-linux-$ARCH" -R blox-eng/openblox \
  --signer-workflow blox-eng/openblox/.github/workflows/publish-daemon.yml \
  --source-ref "refs/tags/$VERSION"

sudo install -m 0755 "openbloxd-linux-$ARCH" /usr/local/bin/openbloxd
openbloxd --version      # must print $VERSION, not "dev"
```

**2. Create its user and the socket group.**

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin openbloxd
sudo usermod -aG openbloxd <the user your application runs as>
```

`openbloxd`'s primary group is `openbloxd`, which is the example config's
`socket_group`. See the [security model](security.md#deploying-the-policy-broker-openbloxd)
before choosing a different group.

**3. Configure profiles.** Start from `openbloxd.example.yaml` and install it as
`/etc/openbloxd/config.yaml`. Pin every image **by digest**, and size
`max_sandboxes × memory_mb` across all profiles to what the host can hold, with
headroom. For untrusted code keep `egress: none`, and set `runtime` to `runsc` (the
default) or a microVM runtime such as `kata` — never `runc`.
Unknown keys, negative bounds and root users are refused at start-up.

**4. Install the unit and start it.**

```sh
sudo install -m 0644 openbloxd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openbloxd
```

**5. Use it from your application.**

```go
client, err := brokerclient.New("/run/openbloxd/openbloxd.sock")
if err != nil {
    return err
}
defer client.Close()

sb, err := client.Create(ctx, "session-1", brokerclient.WithProfile("code-exec"))
```

`brokerclient.Client` implements the same `sandbox.Backend` as the Docker backend.
A containerized application mounts the **directory** `/run/openbloxd`, not the socket
file, so it survives a daemon restart.

## Operating it

- **Previews**: serve them from an origin that shares no cookies or storage with your
  application, since the content is written by the sandbox. Keep TTLs short.
- **Output**: `Exec` keeps up to 16 MiB of each stream (`Result.Truncated` tells you
  when it cut). Treat everything a sandbox returns as untrusted input.
- **Timeouts**: a timed-out command is killed with its process group. Code that
  detaches with `setsid` survives until the sandbox is reaped; `Destroy` the sandbox
  when work must certainly stop.
- **Lifetime**: `openbloxd` runs the reaper every `reap_interval`. In direct library
  mode *you* must call `Backend.Reap` periodically, or idle and max-age bounds are
  never enforced.

## Upgrading

1. Read the release's **Breaking** and **Security** entries in the
   [changelog](https://github.com/blox-eng/openblox/blob/main/CHANGELOG.md).
2. Download and verify the new binary as in step 1 above.
3. `sudo install` it over the old one, then `sudo systemctl restart openbloxd`.
   Running sandboxes are not interrupted and are found again by name. If the new
   version rejects your config, it refuses to start and says why.
4. Upgrade `pkg/brokerclient` in your application to the same version.
5. To move to a new sandbox image, update the profile's digest and restart.
   Existing sandboxes keep the image they were created with until they are
   destroyed or reaped; new ones use the new image.

To roll back, reinstall the previous binary and profile, and restart. Sandboxes carry
no version state, so nothing needs migrating in either direction.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ErrRuntimeUnavailable` / `runtime "runsc" is not registered` | Register gVisor: `sudo runsc install && sudo systemctl restart docker`, then check with `docker info --format '{{json .Runtimes}}'`. |
| A container starts but `uname -r` inside is not `…-gvisor` | The runtime named `runsc` is not gVisor. Fix the path in `/etc/docker/daemon.json`. |
| `ErrRuntimeUnavailable` / `runtime "kata" is not registered` | Register Kata: put `containerd-shim-kata-v2` on `PATH`, add `"kata": {"runtimeType": "io.containerd.kata.v2"}` under `runtimes` in `/etc/docker/daemon.json`, and `sudo systemctl restart docker` ([details](getting-started.md#using-kata-instead)). |
| Under Kata, every sandbox fails to start and `/dev/kvm` does not exist | Kata boots a VM per sandbox and needs KVM. Enable hardware virtualisation, or nested virtualisation if the host is a VM, and check that `/dev/kvm` is accessible. gVisor's default platform needs no KVM. |
| `ErrImageUnavailable` | The image is not present and could not be pulled. For a private registry, set `registry_auth` in the profile (or `docker.WithRegistryAuth`). |
| `ErrInvalid: user …` (root, not numeric, or a bare uid) | Set `user` to an explicit, numeric, non-zero `uid:gid`, such as `"1000:1000"`. |
| HTTP 429, kind `at_capacity` | The profile is at `max_sandboxes`. Retry after the reaper frees a slot, destroy unused sandboxes, or raise the cap if the host can hold it. |
| HTTP 409, kind `conflict` | The name already exists under another profile. Use a different name, or destroy the old sandbox. |
| HTTP 409, kind `stopped` (`ErrStopped`) | The sandbox exists but is not running, so it cannot serve exec, files or processes. Usually it hit `memory_mb` and was killed. The kill takes the whole sandbox, not the offending process, so anything it held is gone: create a fresh one rather than retrying. `GET /sandboxes/{name}` still resolves, so you can confirm the state. |
| `EACCES` on the socket | Your process is not in `socket_group`, or `socket_group` differs from the unit's group — see the [security model](security.md#deploying-the-policy-broker-openbloxd). |
| `ENOENT` on the socket after a daemon restart | A container mounted the socket file rather than `/run/openbloxd`. Mount the directory. |
| Preview returns 502 | Nothing is listening on `127.0.0.1:<port>` inside the sandbox, or the image has neither `nc` nor `python3`. |
| `Exec` returns `ErrTimeout` | The command exceeded its timeout, or the profile's `max_timeout` clamped a longer one. |
| `Result.Truncated` is true | A stream exceeded 16 MiB. Write the result to a file and use `ReadFile`. |
| Sandboxes accumulate (library mode) | Nothing is calling `Reap`. |
| Docker logs `Your kernel does not support swap limit capabilities` | cgroup v1 without swap accounting. The swap limit is dropped, so a sandbox may use swap on top of its memory limit. Prefer a cgroup v2 host. |

## When not to use openblox

- You need **tenants isolated from each other at the API**: every `openbloxd`
  caller can reach every sandbox. Put your own authorisation in front of it.
- You need **several hosts**, scheduling, or fair sharing: openblox is one host,
  one daemon.
- You need protection from **side channels** between co-resident workloads. A microVM
  runtime such as [Kata](getting-started.md#using-kata-instead) removes the shared
  kernel, not the shared CPU: microarchitectural side channels remain.
- You need **sub-second cold starts**, snapshots, or fork/resume.
- Your sandboxes need **general network access**. `unrestricted` egress exists, but
  then the network boundary is yours to build.
- You cannot run **Linux with gVisor or a microVM runtime**, or cannot keep that
  runtime patched.
