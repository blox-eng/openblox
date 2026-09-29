#!/usr/bin/env python3
"""Compare openblox with other self-hosted sandboxes on one host.

Every backend gets the same image, the same workload and the same limits
(512 MB memory, 2 CPUs, no network), and is driven through its own API, SDK
or CLI. Run it as root on the host, once per backend and mode:

  sudo python3 compare.py --backend docker-runsc --mode latency
  sudo python3 compare.py --backend docker-runsc --mode stress
  sudo python3 compare.py --backend docker-runsc --mode footprint
  sudo python3 compare.py --backend docker-runsc --mode posture

Each run appends one JSON record to results/<backend>.json; report.py turns
the records into the tables in index.md. The SDK backends (microsandbox,
opensandbox, llm-sandbox) need their package importable, so run those from a
venv that has it installed.

The workload is bench.sh's: exec `true`, `python3 -c pass`, then a job that
fills 64 MiB and runs a 3M-step loop.
"""

import argparse
import base64
import datetime
import http.client
import json
import os
import platform
import re
import shlex
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

IMAGE = "ghcr.io/blox-eng/openblox-sandbox:0.9.0"
MEMORY_MB = 512
CPUS = 2
JOB_MB = 64
CPU_STEPS = 3_000_000
JOB = f"b=b'x'*({JOB_MB}<<20); print(len(b)>>20, sum(i*i for i in range({CPU_STEPS})))"

# Runs inside the sandbox and reports what the tool's defaults allow.
PROBE = r"""
import json, os, socket
r = {"uid": os.getuid(), "kernel": os.uname().release}
for line in open("/proc/self/status"):
    k, _, v = line.partition(":")
    if k == "CapEff": r["cap_eff"] = v.strip()
    if k == "CapBnd": r["cap_bnd"] = v.strip()
    if k == "NoNewPrivs": r["no_new_privs"] = v.strip() == "1"
r["rootfs_readonly"] = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
def cg(name):
    try: return open("/sys/fs/cgroup/" + name).read().strip()
    except OSError: return None
r["pids_max"] = cg("pids.max")
r["memory_max"] = cg("memory.max")
try: r["interfaces"] = sorted(os.listdir("/sys/class/net"))
except OSError: r["interfaces"] = None
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close(); r["egress"] = True
except OSError as e:
    r["egress"] = False; r["egress_error"] = type(e).__name__
print(json.dumps(r))
"""

# Each asks for a bit more than the configured limit allows. Under the tool's
# defaults they show whether anything is capped at all.
LIMIT_PROBES = {
    "alloc_768mb": f"b=b'x'*({MEMORY_MB + 256}<<20); print('granted')",
    "fork_300": """
import os, time
kids = []
try:
    for _ in range(300):
        pid = os.fork()
        if pid == 0:
            time.sleep(2); os._exit(0)
        kids.append(pid)
except OSError:
    pass
for k in kids: os.waitpid(k, 0)
print('granted' if len(kids) == 300 else f'stopped at {len(kids)}')
""",
    "write_300mb_tmp": """
n = 0
try:
    with open('/tmp/fill', 'wb') as f:
        for _ in range(300):
            f.write(b'x' * (1 << 20)); f.flush(); n += 1
except OSError:
    pass
import os
try: os.remove('/tmp/fill')
except OSError: pass
print('granted' if n == 300 else f'stopped at {n} MB')
""",
}

HERE = Path(__file__).resolve().parent


class Docker:
    """Plain `docker run`, with openblox's hardening flags when limited."""

    def __init__(self, runtime):
        self.runtime = runtime
        self.name = f"docker-{runtime}"

    def version(self):
        out = sh(["docker", "version", "--format", "{{.Server.Version}}"])
        rt = {"runc": ["runc", "--version"], "runsc": ["runsc", "--version"]}.get(self.runtime)
        if rt:
            out += " / " + sh(rt).splitlines()[0]
        elif self.runtime == "kata":
            qemu = sh(["/opt/kata/bin/qemu-system-x86_64", "--version"]).splitlines()[0]
            out += f" / kata {Path('/opt/kata/VERSION').read_text().strip()} runtime-rs, {qemu}"
        return out

    def create(self, name, limited=True):
        args = ["docker", "run", "-d", "--name", name]
        if self.runtime != "runc":
            args += ["--runtime", self.runtime]
        if limited:
            args += [
                f"--memory={MEMORY_MB}m", f"--memory-swap={MEMORY_MB}m", f"--cpus={CPUS}",
                "--network=none", "--pids-limit=256", "--user=1000:1000",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
                "--tmpfs=/workspace:rw,nosuid,nodev,noexec,size=128m,mode=0777",
                "--workdir=/workspace",
            ]
        args += ["--entrypoint", "/bin/sh", IMAGE, "-c", "while :; do sleep 3600; done"]
        sh(args)
        return name

    def exec(self, h, argv):
        p = subprocess.run(["docker", "exec", h, *argv], capture_output=True, text=True, timeout=180, check=False)
        return p.returncode, p.stdout

    def delete(self, h):
        try:
            subprocess.run(["docker", "rm", "-f", h], capture_output=True, check=False, timeout=180)
        except subprocess.TimeoutExpired:
            print(f"docker rm -f {h}: no answer after 180s, left behind", file=sys.stderr)


class Openblox:
    """openbloxd's HTTP API on its unix socket, as bench.sh drives it."""

    name = "openblox"

    def __init__(self, socket_path="/run/openbloxd/openbloxd.sock", profile="code-exec"):
        self.socket_path = socket_path
        self.profile = profile

    def _call(self, method, path, body=None):
        conn = _UnixHTTP(self.socket_path)
        conn.request(method, path, json.dumps(body) if body is not None else None,
                     {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if resp.status >= 300:
            raise RuntimeError(f"{method} {path}: {resp.status} {data[:300]!r}")
        return json.loads(data) if data else None

    def version(self):
        return sh(["openbloxd", "--version"]).splitlines()[0] + " / " + sh(["runsc", "--version"]).splitlines()[0]

    def create(self, name, limited=True):
        # The profile is the limit set; setup.sh's code-exec profile is both
        # openblox's default and the 512 MB / 2 CPU / no-network configuration.
        self._call("POST", "/sandboxes", {"name": name, "profile": self.profile})
        return name

    def exec(self, h, argv):
        r = self._call("POST", f"/sandboxes/{h}/exec", {"argv": argv, "timeout": "120s"})
        # stdout is a Go []byte, so JSON carries it base64-encoded.
        return r.get("exit_code", -1), base64.b64decode(r.get("stdout") or "").decode(errors="replace")

    def delete(self, h):
        try:
            self._call("DELETE", f"/sandboxes/{h}")
        except RuntimeError:
            pass


class Microsandbox:
    """microsandbox's Python SDK: one libkrun microVM per sandbox, no daemon.

    The SDK is async only, so calls run on a private event loop in a thread;
    stress mode's threads share it.
    """

    name = "microsandbox"

    def __init__(self):
        import asyncio

        import microsandbox

        self.msb = microsandbox
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.boxes = {}

    def _run(self, fn, *args, **kw):
        # The SDK's native calls need a running loop at call time, not only at
        # await time, so the call itself has to happen on the loop.
        import asyncio

        async def call():
            return await fn(*args, **kw)

        return asyncio.run_coroutine_threadsafe(call(), self.loop).result(timeout=300)

    def version(self):
        from importlib.metadata import version

        return f"microsandbox {version('microsandbox')}"

    def create(self, name, limited=True):
        m = self.msb
        kw = {"image": IMAGE, "replace": True}
        if limited:
            kw |= {"memory": MEMORY_MB, "cpus": CPUS, "network": m.Network.none(), "user": "1000:1000",
                   "security": m.SecurityProfile.RESTRICTED}
        self.boxes[name] = self._run(m.Sandbox.create, name, **kw)
        return name

    def exec(self, h, argv):
        out = self._run(self.boxes[h].exec, argv[0], argv[1:], timeout=120)
        return out.exit_code, out.stdout_text

    def delete(self, h):
        box = self.boxes.pop(h, None)
        if box is not None:
            self._run(box.destroy, force=True)


class OpenSandbox:
    """alibaba/OpenSandbox's Python SDK against its server in Docker mode, on runsc.

    The server reads its API key and address from OPENSANDBOX_API_KEY and
    OPENSANDBOX_DOMAIN (default localhost:8080). There is no network-off
    option to pass: the SDK reaches the in-sandbox execd agent over the
    sandbox's bridge network, and the server rejects egress policies under
    gVisor.
    """

    name = "opensandbox"

    def __init__(self):
        from opensandbox import SandboxSync
        from opensandbox.config import ConnectionConfigSync

        self.Sandbox = SandboxSync
        self.cfg = ConnectionConfigSync(domain=os.environ.get("OPENSANDBOX_DOMAIN", "localhost:8080"),
                                        api_key=os.environ["OPENSANDBOX_API_KEY"])
        self.boxes = {}

    def version(self):
        from importlib.metadata import version

        return f"opensandbox-server {version('opensandbox-server')}, sdk {version('opensandbox')}"

    def create(self, name, limited=True):
        kw = {"connection_config": self.cfg, "timeout": None}
        if limited:
            kw["resource"] = {"cpu": str(CPUS), "memory": f"{MEMORY_MB}Mi"}
        self.boxes[name] = self.Sandbox.create(IMAGE, **kw)
        return name

    def exec(self, h, argv):
        # execd v1.1.0 rejects the SDK's argv-list form ("Command required"),
        # so this uses the shell-text form, which adds a shell to every exec.
        ex = self.boxes[h].commands.run(shlex.join(argv))
        return ex.exit_code, "".join(m.text for m in ex.logs.stdout)

    def delete(self, h):
        box = self.boxes.pop(h, None)
        if box is not None:
            box.destroy()


class LlmSandbox:
    """llm-sandbox's SandboxSession: docker-py underneath, so the limits are
    docker-py's run options, passed through runtime_configs. Configured, it
    gets the same runtime (runsc) and hardening as docker-runsc.
    """

    name = "llm-sandbox"

    def __init__(self):
        from llm_sandbox import SandboxSession

        self.Session = SandboxSession
        self.sessions = {}

    def version(self):
        from importlib.metadata import version

        return f"llm-sandbox {version('llm-sandbox')} / " + sh(["runsc", "--version"]).splitlines()[0]

    def create(self, name, limited=True):
        # keep_template: without it, close() deletes the image it pulled.
        kw = {"backend": "docker", "image": IMAGE, "lang": "python", "keep_template": True}
        if limited:
            kw |= {
                "skip_environment_setup": True,  # it would pip install over the network
                "workdir": "/workspace",
                "runtime_configs": {
                    "name": name, "runtime": "runsc",
                    "mem_limit": f"{MEMORY_MB}m", "memswap_limit": f"{MEMORY_MB}m", "nano_cpus": CPUS * 10**9,
                    "network_mode": "none", "pids_limit": 256, "user": "1000:1000", "read_only": True,
                    "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"],
                    "tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=128m,mode=1777",
                              "/workspace": "rw,nosuid,nodev,noexec,size=128m,mode=0777"},
                },
            }
        session = self.Session(**kw)
        session.open()
        self.sessions[name] = session
        return name

    def exec(self, h, argv):
        # A string is shlex-split and exec'd without a shell.
        out = self.sessions[h].execute_command(shlex.join(argv))
        return out.exit_code, out.stdout

    def delete(self, h):
        session = self.sessions.pop(h, None)
        if session is not None:
            session.close()


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("openbloxd", timeout=180)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


BACKENDS = {
    "docker-runc": lambda: Docker("runc"),
    "docker-runsc": lambda: Docker("runsc"),
    "docker-kata": lambda: Docker("kata"),
    "openblox": Openblox,
    "microsandbox": Microsandbox,
    "opensandbox": OpenSandbox,
    "llm-sandbox": LlmSandbox,
}


def sh(args, timeout=180):
    try:
        p = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"{shlex.join(args)}: no answer after {timeout}s") from e
    if p.returncode != 0:
        raise RuntimeError(f"{shlex.join(args)}: {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout.strip()


def ms_since(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


def meminfo_mb(key):
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(key + ":"):
            return int(line.split()[1]) // 1024
    raise RuntimeError(f"no {key} in /proc/meminfo")


def mem_available_mb():
    return meminfo_mb("MemAvailable")


def cpu_ticks():
    f = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    return f[0] + f[1] + f[2] + f[5] + f[6] + f[7], f[3]  # busy, idle


def pss_mb(pattern):
    """Summed PSS of every process whose command line matches pattern.

    PSS splits shared pages between the processes sharing them, so summing it
    does not count a shared library once per sandbox.
    """
    if not pattern:
        return None
    total = 0
    rx = re.compile(pattern)
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            if pid == str(os.getpid()) or not rx.search(cmd):
                continue
            for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
                if line.startswith("Pss:"):
                    total += int(line.split()[1])
        except OSError:
            continue
    return round(total / 1024)


def summary(xs):
    return {"min": min(xs), "median": round(statistics.median(xs), 1), "max": max(xs), "n": len(xs)}


def must(b, h, argv, what):
    code, out = b.exec(h, argv)
    if code != 0:
        raise RuntimeError(f"{what} exited {code}: {out[:300]}")
    return out


def latency(b, run, rounds):
    samples = {k: [] for k in ("create", "exec_true", "python_startup", "job", "delete")}
    for i in range(rounds):
        name = f"{run}-{i}"
        t = time.perf_counter(); h = b.create(name); samples["create"].append(ms_since(t))
        try:
            t = time.perf_counter(); must(b, h, ["true"], "true"); samples["exec_true"].append(ms_since(t))
            t = time.perf_counter(); must(b, h, ["python3", "-c", "pass"], "python3"); samples["python_startup"].append(ms_since(t))
            t = time.perf_counter(); must(b, h, ["python3", "-c", JOB], "job"); samples["job"].append(ms_since(t))
        finally:
            t = time.perf_counter(); b.delete(h); samples["delete"].append(ms_since(t))
    return {k: summary(v) for k, v in samples.items()}


def stress(b, run, levels, jobs_per_sandbox, floor_mb, sandbox_mb):
    rows, stop = [], None
    for c in levels:
        free = mem_available_mb()
        if free - c * (sandbox_mb + JOB_MB * 14 // 10) < floor_mb:
            stop = f"level {c} would take the host under {floor_mb} MiB free ({free} MiB now)"
            break
        row = _stress_level(b, f"{run}-{c}", c, jobs_per_sandbox, free)
        rows.append(row)
        print(json.dumps(row), file=sys.stderr)
        if row["failed"]:
            stop = f"{row['failed']} jobs or creates failed at {c} sandboxes"
            break
        if row["min_free_mb"] < floor_mb:
            stop = f"host free memory fell under {floor_mb} MiB at {c} sandboxes"
            break
    return {"levels": rows, "stopped": stop}


def _stress_level(b, run, c, jobs_per_sandbox, free):
    """c sandboxes, created at once, each running the job jobs_per_sandbox times at once."""
    handles, errors = [None] * c, []

    def make(j):
        try:
            handles[j] = b.create(f"{run}-{j}")
        except Exception as e:  # noqa: BLE001 - reported, not raised
            errors.append(str(e))

    t = time.perf_counter()
    par([lambda j=j: make(j) for j in range(c)])
    create_ms = ms_since(t)

    mem, done = [], threading.Event()

    def sample():
        while not done.is_set():
            mem.append(mem_available_mb())
            time.sleep(0.2)

    jobs, failures = [], []

    def work(h):
        for _ in range(jobs_per_sandbox):
            s = time.perf_counter()
            try:
                code, _ = b.exec(h, ["python3", "-c", JOB])
            except Exception:  # noqa: BLE001 - a failed job is a data point
                code = -1
            if code == 0:
                jobs.append(ms_since(s))
            else:
                failures.append(code)

    sampler = threading.Thread(target=sample)
    sampler.start()
    busy0, idle0 = cpu_ticks()
    t = time.perf_counter()
    par([lambda h=h: work(h) for h in handles if h])
    wall = time.perf_counter() - t
    busy1, idle1 = cpu_ticks()
    done.set()
    sampler.join()
    par([lambda h=h: b.delete(h) for h in handles if h])

    busy, idle = busy1 - busy0, idle1 - idle0
    jobs.sort()
    return {
        "sandboxes": c, "create_all_ms": create_ms,
        "job_p50_ms": statistics.median(jobs) if jobs else None,
        "job_max_ms": jobs[-1] if jobs else None,
        "jobs_per_s": round(len(jobs) / wall, 2),
        "cpu_pct": round(100 * busy / (busy + idle)) if busy + idle else 0,
        "min_free_mb": min(mem) if mem else free,
        "failed": len(errors) + len(failures), "errors": errors[:3],
    }


def footprint(b, run, n, tool, sandbox):
    """What the tool costs idle, and what each idle sandbox adds.

    tool and sandbox are regexes over process command lines: the tool's own
    long-running processes, and the per-sandbox ones (shims, VMMs, sentries).
    """
    time.sleep(3)
    tool_idle, sb_before, free_before = pss_mb(tool), pss_mb(sandbox), mem_available_mb()
    handles = [b.create(f"{run}-{i}") for i in range(n)]
    try:
        for h in handles:
            must(b, h, ["true"], "true")
        time.sleep(10)
        tool_busy, sb_after, free_after = pss_mb(tool), pss_mb(sandbox), mem_available_mb()
    finally:
        for h in handles:
            b.delete(h)
    return {
        "idle_sandboxes": n,
        "tool_pattern": tool, "sandbox_pattern": sandbox,
        "tool_pss_idle_mb": tool_idle, "tool_pss_with_sandboxes_mb": tool_busy,
        "per_sandbox_pss_mb": round((sb_after - sb_before) / n) if sandbox else None,
        "per_sandbox_memavailable_mb": round((free_before - free_after) / n),
    }


def posture(b, run):
    """Probe the tool's defaults and the configured limits from inside.

    Each limit probe gets a fresh sandbox: under gVisor, going over the memory
    limit kills the whole sandbox, which would fail every probe after it.
    """
    out = {}
    for limited in (False, True):
        key = "configured" if limited else "defaults"
        out[key] = _in_fresh(b, f"{run}-{key}", limited, lambda h: _probe(b, h))
        for probe, src in LIMIT_PROBES.items():
            out[key][probe] = _in_fresh(b, f"{run}-{key}-{probe}", limited, lambda h, src=src: _limit(b, h, src))
    return out


def _in_fresh(b, name, limited, fn):
    try:
        h = b.create(name, limited=limited)
    except Exception as e:  # noqa: BLE001 - a create that fails is the result
        return {"create_error": str(e)[:200]}
    try:
        return fn(h)
    finally:
        b.delete(h)


def _probe(b, h):
    code, stdout = b.exec(h, ["python3", "-c", PROBE])
    return json.loads(stdout.strip().splitlines()[-1]) if code == 0 else {"probe_exit": code, "out": stdout[:300]}


def _limit(b, h, src):
    try:
        code, stdout = b.exec(h, ["python3", "-c", src])
    except Exception as e:  # noqa: BLE001 - a refused exec is the result
        return f"error: {str(e)[:120]}"
    last = stdout.strip().splitlines()[-1] if stdout.strip() else ""
    return last or f"killed (exit {code})"


def par(fns):
    ts = [threading.Thread(target=f) for f in fns]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", required=True, choices=sorted(BACKENDS))
    ap.add_argument("--mode", default="latency", choices=["latency", "stress", "footprint", "posture"])
    ap.add_argument("--rounds", type=int, default=10, help="latency rounds (default 10)")
    ap.add_argument("--jobs", type=int, default=3, help="stress: jobs per sandbox (default 3)")
    ap.add_argument("--levels", default="1 2 4 8 16", help='stress levels (default "1 2 4 8 16")')
    ap.add_argument("--floor-mb", type=int, default=512, help="stress stops before free memory drops under this")
    ap.add_argument("--sandbox-mb", type=int, default=0,
                    help="stress: host memory an idle sandbox costs (footprint mode), so a level is skipped before it can breach the floor")
    ap.add_argument("--idle", type=int, default=3, help="footprint: idle sandboxes to average over")
    ap.add_argument("--tool-procs", default="", help="footprint: regex over the command lines of the tool's own processes")
    ap.add_argument("--sandbox-procs", default="", help="footprint: regex over the command lines of per-sandbox processes")
    ap.add_argument("--note", default="", help="free text stored with the record")
    a = ap.parse_args()

    b = BACKENDS[a.backend]()
    version = b.version()
    run = f"cmp-{os.getpid()}"
    t0 = datetime.datetime.now(datetime.timezone.utc)
    if a.mode == "latency":
        result = latency(b, run, a.rounds)
    elif a.mode == "stress":
        result = stress(b, run, [int(x) for x in a.levels.split()], a.jobs, a.floor_mb, a.sandbox_mb)
    elif a.mode == "footprint":
        result = footprint(b, run, a.idle, a.tool_procs, a.sandbox_procs)
    else:
        result = posture(b, run)

    record = {
        "backend": a.backend, "mode": a.mode, "version": version,
        "started": t0.isoformat(timespec="seconds"),
        "host": {"kernel": platform.release(), "cpus": os.cpu_count(), "cpu": _cpu_model(),
                 "mem_total_mb": meminfo_mb("MemTotal")},
        "limits": {"memory_mb": MEMORY_MB, "cpus": CPUS, "network": "none", "image": IMAGE},
        "note": a.note, "result": result,
    }
    out = HERE / "results" / f"{a.backend}.json"
    out.parent.mkdir(exist_ok=True)
    with out.open("a") as f:
        f.write(json.dumps(record) + "\n")
    print(json.dumps(record, indent=2))


def _cpu_model():
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


if __name__ == "__main__":
    main()
