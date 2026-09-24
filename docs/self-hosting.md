# A dedicated host

Give openblox a machine of its own, and one command takes it from a fresh OS
install to a hardened sandbox host. It installs Docker, gVisor, `openbloxd` and
its service, plus an optional mTLS listener for remote callers, a firewall and
automatic security updates. Then it runs a sandbox to prove the host works.

```sh
curl -fsSL https://openblox.sh/setup.sh | sh
```

Or fetch it once, read it, and run what you read:

```sh
curl -fsSL https://openblox.sh/setup.sh -o setup.sh
less setup.sh
sudo sh setup.sh
```

The source is [`www/setup.sh`](https://github.com/blox-eng/openblox/blob/main/www/setup.sh).
Its design follows k3s's installer. It runs named phases in a fixed order, and
each phase checks before it changes anything, so running it again is safe. It
also writes an uninstaller that removes exactly what it added.

If you already run Docker and gVisor, or want to put the daemon on a machine
that does other work, you don't need this. Install the binary and follow
[Running in production](production.md) instead.

## Hardware

- **CPU:** amd64 or arm64, at least 4 cores.
- **Disk:** an SSD. Every sandbox's writable layer lives on it.
- **Memory:** the RAM decides how many sandboxes can run at once. A sandbox
  holds about 1.4× its `memory_mb` before the kernel's limit lands
  ([#30](https://github.com/blox-eng/openblox/issues/30)), and the host keeps
  1 GiB for itself:

    `max_sandboxes = floor((RAM − 1 GiB) / (1.4 × memory_mb))`, at least 1

    At the default `memory_mb` of 2048:

    | RAM    | Concurrent sandboxes |
    |--------|----------------------|
    | 8 GiB  | 2                    |
    | 16 GiB | 5                    |
    | 32 GiB | 11                   |
    | 64 GiB | 22                   |

    These are nominal sizes. The kernel reports a little less than the
    installed RAM, so the script may compute one fewer. It prints its
    arithmetic.

## Choosing an OS

- **Debian 13, minimal** (recommended). It is small, has no snap, and has
  long support.
- **Ubuntu 24.04 LTS** is also supported.

Install it with an SSH server and nothing else: no desktop. The script
refuses any other system and says so. On other systems, install Docker and
gVisor yourself and use [`install.sh`](getting-started.md#install).

## Run it

As root, or as a user with `sudo`: the script re-runs itself through `sudo`.
Settings are environment variables, so they work with `curl … | sh`. Each is
also a flag when you run the script from a file.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `OPENBLOX_VERSION` | `--version` | latest release | daemon and image version, in lockstep |
| `OPENBLOX_LISTEN` | `--listen` | none (Unix socket only) | `host:port` for the mTLS listener |
| `OPENBLOX_CLIENTS` | `--client` (repeatable) | `sandbox-caller` when listening | client certificate names to issue and allow |
| `OPENBLOX_ALLOW_FROM` | `--allow-from` | any source | CIDR allowed to reach the listener |
| `OPENBLOX_MEMORY_MB` | `--memory-mb` | `2048` | per-sandbox memory |
| `OPENBLOX_MAX_SANDBOXES` | `--max-sandboxes` | sized from RAM | concurrent sandboxes |

The phases, in order:

1. **`verify_system`:** checks the OS, the architecture and cgroup v2, and
   sizes `max_sandboxes` from RAM.
2. **`install_docker`:** installs Docker Engine from Docker's apt repository.
   If Docker is already installed, it is left as it is.
3. **`install_gvisor`:** installs `runsc` from gVisor's apt repository and
   registers it with Docker.
4. **`install_openbloxd`:** installs the binary through `install.sh`, which
   verifies the checksum and, when `gh` is present, the build attestation.
   It also creates the `openbloxd` system user.
5. **`pin_image`:** pulls the sandbox image for the same version and pins
   its digest.
6. **`write_config`:** writes `/etc/openbloxd/config.yaml` with one profile,
   `code-exec`: no network, non-root, capped CPU, memory, disk and processes.
7. **`issue_certs`:** runs only with a listener. It issues the server
   certificate and one client bundle per caller.
8. **`harden`:** adds an nftables firewall and turns on automatic security
   updates. The firewall drops inbound traffic except SSH and the listener.
9. **`create_uninstall`:** writes `/usr/local/bin/openblox-uninstall.sh`.
10. **`create_systemd_service`**, then **`service_enable_and_start`:**
    install, enable and start the service.
11. **`smoke_test`:** creates a sandbox, requires that its kernel is gVisor
    and that it cannot reach the network, then removes it.

If a phase fails, the script names it and says what to do next.

## Remote callers

Your application usually runs on another machine. Give the daemon a listener
on a private address and name one client per caller:

```sh
curl -fsSL https://openblox.sh/setup.sh |
  OPENBLOX_LISTEN=10.0.0.5:9443 OPENBLOX_CLIENTS="app-staging app-prod" \
  OPENBLOX_ALLOW_FROM=10.0.0.0/24 sh
```

Each caller gets a bundle in `/etc/openbloxd/clients/<name>/`:

- `client.crt` and `client.key`: the caller's identity.
- `ca.crt`: the CA that signed the daemon's certificate, which the caller
  verifies the daemon against.

Copy the directory to that caller over a channel you trust, such as `scp`.
The key is the one secret in this setup, and it never needs to go anywhere
else. Then connect:

```go
client, err := brokerclient.NewRemote("10.0.0.5:9443", brokerclient.TLSFiles{
    CertFile: "/etc/app/openblox/client.crt",
    KeyFile:  "/etc/app/openblox/client.key",
    CAFile:   "/etc/app/openblox/ca.crt",
})
```

The client CA and the server CA are separate. The daemon trusts every
certificate the client CA signs, so that CA signs callers and nothing else.
Both CA keys stay on the host.

To add a caller, run the script again with the new name added to the list.
Only the new bundle is issued. The script never rewrites your config, so it
prints the one-line change instead: add the name to `allowed_client_cns` and
run `systemctl restart openbloxd`. To remove a caller, delete its name there
and restart. There is no revocation list.

The listener is bound to the address you give it. How your callers reach
that address, whether over a LAN, a VPN or a tailnet, is up to you.

## Upgrading

Run the script again with the new version:

```sh
curl -fsSL https://openblox.sh/setup.sh | OPENBLOX_VERSION=vX.Y.Z sh
```

It upgrades the daemon and pulls the matching image. It never rewrites
`config.yaml`, because you may have edited it. Instead it prints a diff
against what it would write now, and leaves that version in
`config.yaml.new`. Copy the new `image:` line across by hand, then run
`systemctl restart openbloxd`.

## Uninstalling

```sh
sudo openblox-uninstall.sh
```

Setup records everything it creates in `/var/lib/openblox/installed`, and the
uninstaller removes exactly that list:

- the sandboxes
- the service, the binary and the `openbloxd` user
- `/etc/openbloxd`, including the CAs and client bundles
- the firewall table
- the pinned image
- the apt sources setup added
- the packages setup installed

Anything that was there before setup first ran stays, including a Docker you
had already installed. `/var/lib/docker` is always kept. Delete it yourself if
you no longer need it.

## Known limits

- **A client certificate is not bound to a profile.** Every allowed caller
  can use every profile on the host. Give callers that need different
  limits different hosts.
- **Kata is not provisioned.** The script installs gVisor, the default
  runtime. To use Kata, see [Using Kata instead](getting-started.md#using-kata-instead).
