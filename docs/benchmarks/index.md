# Compared with other sandboxes

We ran openblox and six other open-source ways to run untrusted code on the same
host, with the same image, the same workload and the same limits. Every number
below comes from [`compare.py`](compare.py) and is stored raw in
[`results/`](https://github.com/blox-eng/openblox/tree/main/docs/benchmarks/results).
[`report.py`](report.py) turns those results into the tables. The tables include
the rows where openblox loses.

Measured 2026-09-29 on one small, old host. Treat the numbers as relative, not
absolute: a newer CPU moves all of them.

## What we found

**Where openblox loses**

- **Cold start and exec latency.** microsandbox (libkrun microVMs):
  - creates a sandbox in 636 ms, against openblox's 1154 ms;
  - runs `true` in 20 ms, against 39 ms;
  - deletes one in 61 ms, against 806 ms.

  If sub-second cold starts matter to you, openblox is not the fastest option,
  and this is the result we expected.
- **Throughput on a CPU-bound job.** At saturation, microsandbox finished
  9.5 jobs/s and plain runc 9.4 jobs/s; openblox finished 8.2. That gap is
  gVisor's syscall cost: the same Python job takes 388 ms under openblox and
  371 ms under runc.
- **What happens at a limit.** Under gVisor, going over the memory limit or the
  pids limit kills the *whole sandbox*: the exec returns 128, and the sandbox
  is stopped afterwards. Under runc only the offending process fails: it exits
  137, or `fork` stops at 253 processes. This is gVisor's behaviour, so every
  gVisor row shares it.

**Where it matches**

- **Speed against the same runtime.** openblox is as fast as driving
  Docker + gVisor by hand with the same hardening flags; every latency median
  is within noise. The broker adds no measurable cost.

**Where it wins**

- **Defaults.** openblox is the only tool here whose out-of-the-box sandbox
  already has everything below. Every other tool either needs flags to get
  there or cannot get there at all:
  - no network;
  - a read-only root filesystem;
  - no capabilities and `no_new_privs`;
  - a non-root user;
  - memory, process and disk caps.
- **What the caller holds.** Callers of `openbloxd` name a profile over a unix
  socket or mTLS. Plain Docker, Kata-through-Docker and llm-sandbox all need the
  caller to hold the Docker socket, which is root on the host.
- **Footprint.** Each idle openblox sandbox costs 41 MiB (PSS), against 74 MiB
  for microsandbox and 205 MiB for Kata. The daemon itself uses 23 MiB, against
  167 MiB for the OpenSandbox server.
- **Tested claims.** openblox runs its isolation claims as an adversarial suite
  ([`pkg/conformance`](https://github.com/blox-eng/openblox/tree/main/pkg/conformance))
  on every pull request. We found no equivalent suite in the other tools that
  probes a running sandbox from inside. OpenSandbox has unit tests for its
  optional in-sandbox bubblewrap layer.

**Per tool**

- **Kata Containers** (QEMU, through Docker):
  - It took 8.0 s to create a sandbox on this 2012 CPU and costs 205 MiB per
    idle VM.
  - Throughput peaked at 5.8 jobs/s.
  - Docker's `--pids-limit` does not reach inside the guest: 300 forks succeed.
    The VM boundary still contains them.
- **OpenSandbox** (Docker mode, on runsc):
  - Every exec takes about 1 s, `true` included. Its execd agent holds the
    response stream open for a graceful-shutdown sleep before closing it.
  - Under gVisor the server rejects egress policies, and the SDK reaches the
    sandbox over its bridge network. There is therefore no way to switch the
    network off.
  - Its memory limit leaves swap at Docker's default of twice the limit, so a
    768 MB allocation inside a 512 MiB sandbox succeeds.
  - It publishes each sandbox's execd port on all interfaces by default
    (`[docker] publish_host` restricts it). In Docker mode execd has no
    server-side auth; `secureAccess` is supported only on Kubernetes.
- **llm-sandbox**:
  - Configured with the same runtime and flags, it is Docker + gVisor with a
    Python API, and measures the same.
  - Its defaults are the weakest measured. It overrides the image's non-root
    user to run as root, with Docker's default capabilities, network on and
    no caps.

**Not run: too big for a 4 GB host, or not self-hostable as open source.**
Each reason comes from the project's own docs, as of 2026-09-29.

- **E2B self-hosted** ("E2B Embed"):
  - It recommends 12 GiB of RAM and reserves 4 GiB of hugepages up front.
  - It runs a privileged orchestrator with host networking.
  - It rewrites modprobe, sysctl and iptables settings on the host every time
    it starts.
- **Daytona OSS**:
  - The public repository has been frozen since June 2026, when development
    moved to a private codebase.
  - The last compose stack is 14 services.
  - Every non-GPU sandbox runs `privileged` inside Docker-in-Docker.
  - Memory limits come in whole GiB, so 512 MB cannot be expressed.
- **CubeSandbox** documents a minimum of 8 GB of RAM and 4 cores.
- **Kubernetes agent-sandbox** needs a cluster. On this host that means k3s,
  which brings a second containerd and its own firewall rules onto a machine
  that already runs Docker, leaving little memory above the floor.

## Method

**Host.** Intel Xeon E3-1220 v2 (4 cores, 2012), 3.8 GiB RAM, Debian 13,
kernel 6.12, Docker 29.8.1, bare metal with KVM.

**Workload.** Every backend runs the same image,
`ghcr.io/blox-eng/openblox-sandbox:0.9.0` (python3, `USER` uid 1000). One
round is:

1. create a sandbox;
2. exec `true`;
3. exec `python3 -c pass`;
4. exec bench.sh's job, which fills 64 MiB and runs a 3M-step loop;
5. delete the sandbox.

**Runs.**
- **Latency:** 10 rounds; we report min, median and max.
- **Concurrency ramp:** 1, 2, 4, 8 and 16 sandboxes run the job three times
  each, at the same time. A level is skipped if it could take the host under
  512 MiB free.

**Limits.** 512 MiB of memory, 2 CPUs, no network, as far as each tool can
express them. Each tool is driven through its own interface:

| backend | driven through | how the limits were set |
|---|---|---|
| openblox | `openbloxd`'s HTTP API | setup.sh's `code-exec` profile: 512 MiB, 2 CPUs, 256 MiB disk, 256 processes, egress `none` |
| docker-runsc, docker-runc | the `docker` CLI | openblox's own hardening flags: memory with swap off, `--cpus`, `--network none`, `--pids-limit 256`, uid 1000, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, two 128 MiB tmpfs |
| docker-kata | the `docker` CLI, `--runtime kata` | the same flags. Kata 4.2.0 runtime-rs with QEMU, registered in `daemon.json` and picked up with `systemctl reload docker`. `default_memory` was lowered from 2048 to 256 MiB; left at 2048, each 512 MiB sandbox would be a 2.5 GiB VM. |
| microsandbox | its Python SDK | `memory=512, cpus=2, network=Network.none(), user="1000:1000", security=RESTRICTED` |
| opensandbox | its Python SDK against its server | `resource={"cpu": "2", "memory": "512Mi"}`, `secure_runtime` gVisor. There is no network-off option under gVisor (see above). Server 1.1.1rc1 was installed from its git tag because the 1.1.0 wheel on PyPI is missing a module and does not start. Execs use the SDK's shell-text form because execd rejected the argv form. |
| llm-sandbox | `SandboxSession` | the docker-runsc flags passed through `runtime_configs`, and `skip_environment_setup=True`; the setup would `pip install` over the network |

**Footprint.**
- *Tool's own processes*: the PSS of its long-running processes (`openbloxd`,
  the OpenSandbox server) while idle.
- *Per idle sandbox*: the PSS added by the per-sandbox host processes (shims,
  runsc, QEMU/virtiofsd, `msb machine`) with three idle sandboxes, divided by
  three.
- PSS splits shared pages between the processes that share them, so this does
  not count a shared library once per sandbox. The MemAvailable column is the
  cruder whole-host view and is noisy at this size.

**Posture.** Each tool's sandbox is probed from inside twice: once as created
with no options, and once with the limits above. For openblox the two are the
same, because a profile is the only way to create one.

The probe reads:
- uid, kernel release, capability sets and `no_new_privs`;
- whether the root filesystem is read-only;
- whether a TCP connection to 1.1.1.1:443 succeeds.

It then tries, each in a fresh sandbox:
- allocating 768 MB;
- forking 300 processes;
- writing 300 MB to `/tmp`.

Two notes on the results:
- "killed (exit 1)" on the microVMs is a `MemoryError` at the VM's size, not a
  cgroup limit.
- Every uid 1000 comes from the image's own `USER`, not from the tool.

**Not measured.** OpenSandbox's concurrency ramp. We stopped after finding its
execd ports published on all interfaces of a host that was about to become
staging.

## Results

### Latency, one sandbox at a time (ms: min / median / max)

| backend | create | exec `true` | python3 startup | job | delete |
| --- | --- | --- | --- | --- | --- |
| openblox | 1117 / **1154** / 1306 | 35 / **39** / 43 | 63 / **67** / 71 | 382 / **388** / 397 | 755 / **806** / 856 |
| docker-runsc | 1056 / **1136** / 1261 | 43 / **44** / 47 | 69 / **70** / 72 | 389 / **398** / 404 | 758 / **800** / 862 |
| docker-runc | 1058 / **1106** / 1186 | 56 / **59** / 70 | 70 / **72** / 90 | 366 / **371** / 389 | 768 / **790** / 857 |
| docker-kata | 7986 / **8040** / 8127 | 54 / **59** / 65 | 174 / **202** / 239 | 477 / **486** / 493 | 1227 / **1284** / 1425 |
| microsandbox | 589 / **636** / 899 | 18 / **20** / 24 | 31 / **34** / 38 | 387 / **390** / 398 | 28 / **61** / 63 |
| opensandbox | 2383 / **2734** / 3008 | 1013 / **1017** / 1019 | 1053 / **1059** / 1063 | 1403 / **1440** / 1459 | 1282 / **1331** / 1477 |
| llm-sandbox | 1195 / **1293** / 1518 | 27 / **35** / 47 | 54 / **65** / 80 | 383 / **393** / 405 | 896 / **948** / 1029 |

### Concurrency ramp (every sandbox runs the job 3 times at once)

| backend | sandboxes | create all (ms) | job p50 (ms) | job max (ms) | jobs/s | CPU % | min free (MiB) | failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openblox | 1 | 1302 | 393 | 401 | 2.53 | 29 | 3144 | 0 |
|  | 2 | 1864 | 415 | 429 | 4.77 | 51 | 3004 | 0 |
|  | 4 | 3486 | 467 | 506 | 8.18 | 90 | 2799 | 0 |
|  | 8 | 6873 | 915 | 1210 | 8.19 | 97 | 2364 | 0 |
|  | 16 | 13566 | 1848 | 2526 | 8.00 | 99 | 1497 | 0 |
| docker-runsc | 1 | 1342 | 396 | 397 | 2.53 | 27 | 3109 | 0 |
|  | 2 | 2062 | 416 | 422 | 4.77 | 48 | 2939 | 0 |
|  | 4 | 3636 | 456 | 490 | 8.61 | 97 | 2784 | 0 |
|  | 8 | 6990 | 894 | 1100 | 8.49 | 92 | 2231 | 0 |
|  | 16 | 14268 | 1798 | 2501 | 8.44 | 97 | 1277 | 0 |
| docker-runc | 1 | 1299 | 372 | 374 | 2.68 | 25 | 3169 | 0 |
|  | 2 | 2109 | 382 | 386 | 5.22 | 49 | 3093 | 0 |
|  | 4 | 3650 | 427 | 454 | 9.14 | 90 | 2916 | 0 |
|  | 8 | 6627 | 831 | 940 | 9.24 | 97 | 2556 | 0 |
|  | 16 | 14065 | 1553 | 2186 | 9.38 | 97 | 1800 | 0 |
| docker-kata | 1 | 8214 | 420 | 614 | 2.08 | 24 | 2981 | 0 |
|  | 2 | 9060 | 461 | 613 | 3.93 | 48 | 2709 | 0 |
|  | 4 | 11352 | 652 | 822 | 5.79 | 86 | 2118 | 0 |
|  | 8 | 15315 | 1554 | 2662 | 4.74 | 94 | 1100 | 0 |
|  | stopped: level 16 would take the host under 512 MiB free (3247 MiB now) |  |  |  |  |  |  |  |
| microsandbox | 1 | 903 | 353 | 407 | 2.71 | 23 | 3101 | 0 |
|  | 2 | 1036 | 361 | 417 | 5.30 | 45 | 2943 | 0 |
|  | 4 | 1395 | 396 | 473 | 9.46 | 86 | 2564 | 0 |
|  | 8 | 2077 | 795 | 954 | 9.55 | 95 | 1957 | 0 |
|  | 16 | 4592 | 1669 | 2247 | 9.00 | 98 | 707 | 0 |
| llm-sandbox | 1 | 1446 | 379 | 398 | 2.60 | 30 | 3039 | 0 |
|  | 2 | 2098 | 393 | 407 | 5.06 | 55 | 2898 | 0 |
|  | 4 | 3564 | 425 | 573 | 8.57 | 94 | 2713 | 0 |
|  | 8 | 6997 | 834 | 1055 | 9.03 | 93 | 2257 | 0 |
|  | 16 | 13554 | 1626 | 2042 | 8.92 | 99 | 1296 | 0 |

### Footprint

| backend | tool's own processes, idle (MiB PSS) | per idle sandbox (MiB PSS) | per idle sandbox (MiB, MemAvailable drop) |
| --- | --- | --- | --- |
| openblox | 23 | 41 | 25 |
| docker-runsc | 0 | 41 | 24 |
| docker-runc | 0 | 10 | -1 |
| docker-kata | 0 | 205 | 169 |
| microsandbox | 0 | 74 | 61 |
| opensandbox | 167 | 47 | 52 |
| llm-sandbox | 0 | 46 | 20 |

### Default posture, probed from inside the sandbox

| backend | config | uid | kernel seen | capability bounding set | no_new_privs | read-only root | reaches the internet | allocate 768 MB | fork 300 | write 300 MB to /tmp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openblox | defaults | 1000 | 4.19.0-gvisor | 0000000000000000 | yes | yes | no | killed (exit 128) | killed (exit 128) | stopped at 127 MB |
|  | configured | 1000 | 4.19.0-gvisor | 0000000000000000 | yes | yes | no | killed (exit 128) | killed (exit 128) | stopped at 127 MB |
| docker-runsc | defaults | 1000 | 4.19.0-gvisor | 00000000a80405fb | no | no | yes | granted | granted | granted |
|  | configured | 1000 | 4.19.0-gvisor | 0000000000000000 | yes | yes | no | killed (exit 128) | killed (exit 128) | stopped at 128 MB |
| docker-runc | defaults | 1000 | 6.12.111+deb13-amd64 | 00000000a80425fb | no | no | yes | granted | granted | granted |
|  | configured | 1000 | 6.12.111+deb13-amd64 | 0000000000000000 | yes | yes | no | killed (exit 137) | stopped at 253 | stopped at 128 MB |
| docker-kata | defaults | 1000 | 6.18.35 | 00000000a80425fb | no | no | yes | killed (exit 1) | granted | granted |
|  | configured | 1000 | 6.18.35 | 0000000000000000 | yes | yes | no | killed (exit 1) | granted | stopped at 128 MB |
| microsandbox | defaults | 1000 | 6.12.109 | 000001ffffffffff | no | no | yes | killed (exit 1) | granted | granted |
|  | configured | 1000 | 6.12.109 | 000001ffffdfffff | yes | no | no | killed (exit 1) | granted | granted |
| opensandbox | defaults | 1000 | 4.19.0-gvisor | 00000000800405fb | yes | no | yes | granted | granted | granted |
|  | configured | 1000 | 4.19.0-gvisor | 00000000800405fb | yes | no | yes | granted | granted | granted |
| llm-sandbox | defaults | 0 | 6.12.111+deb13-amd64 | 00000000a80425fb | no | no | yes | granted | granted | granted |
|  | configured | 1000 | 4.19.0-gvisor | 0000000000000000 | yes | yes | no | killed (exit 128) | killed (exit 128) | stopped at 128 MB |

### Versions

- **openblox**: v0.9.0 / runsc version release-20260921.0
- **docker-runsc**: 29.8.1 / runsc version release-20260921.0
- **docker-runc**: 29.8.1 / runc version 1.5.1
- **docker-kata**: 29.8.1 / kata 4.2.0 runtime-rs, QEMU emulator version 11.0.1 (kata-static)
- **microsandbox**: microsandbox 0.7.4
- **opensandbox**: opensandbox-server 1.1.1rc1, sdk 1.1.0
- **llm-sandbox**: llm-sandbox 0.3.45 / runsc version release-20260921.0

Host: Intel(R) Xeon(R) CPU E3-1220 V2 @ 3.10GHz, 4 CPUs, 3889 MiB RAM, kernel 6.12.111+deb13-amd64.

## Reproduce

On a host with Docker, gVisor and `openbloxd` installed by
[setup.sh](../self-hosting.md), as root:

```sh
python3 compare.py --backend openblox --mode latency      # also: stress, footprint, posture
python3 compare.py --backend docker-runsc --mode latency  # docker-runc, docker-kata likewise
python3 compare.py --backend openblox --mode footprint \
  --tool-procs openbloxd --sandbox-procs 'containerd-shim|runsc'
python3 compare.py --backend docker-kata --mode stress --sandbox-mb 205
python3 report.py > tables.md
```

The microsandbox, opensandbox and llm-sandbox backends import their SDKs, so
run those from a venv that has `microsandbox==0.7.4`, `opensandbox` or
`llm-sandbox[docker]==0.3.45` installed. The opensandbox backend reads
`OPENSANDBOX_API_KEY` for its server. openblox's stress run needs the
profile's `max_sandboxes` raised to 16 for the run; it defaults to 3.
