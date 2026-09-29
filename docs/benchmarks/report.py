#!/usr/bin/env python3
"""Render results/*.json as the Markdown tables in index.md.

Uses the latest record for each backend and mode:

  python3 report.py > tables.md
"""

import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
ORDER = ["openblox", "docker-runsc", "docker-runc", "docker-kata", "microsandbox", "opensandbox", "llm-sandbox"]
OPS = [("create", "create"), ("exec_true", "exec `true`"), ("python_startup", "python3 startup"),
       ("job", "job"), ("delete", "delete")]


def latest():
    out = {}
    for f in RESULTS.glob("*.json"):
        for line in f.read_text().splitlines():
            r = json.loads(line)
            out[(r["backend"], r["mode"])] = r
    return out


def backends(recs, mode):
    names = {b for b, m in recs if m == mode}
    return [b for b in ORDER if b in names] + sorted(names - set(ORDER))


def fmt(v):
    if v is None:
        return "–"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return f"{v:.0f}" if isinstance(v, float) else str(v)


def row(cells):
    return "| " + " | ".join(cells) + " |"


def latency(recs):
    print("### Latency, one sandbox at a time (ms: min / median / max)\n")
    print(row(["backend"] + [label for _, label in OPS]))
    print(row(["---"] * (len(OPS) + 1)))
    for b in backends(recs, "latency"):
        res = recs[(b, "latency")]["result"]
        print(row([b] + [f"{fmt(res[k]['min'])} / **{fmt(res[k]['median'])}** / {fmt(res[k]['max'])}" for k, _ in OPS]))
    print()


def stress(recs):
    print("### Concurrency ramp (every sandbox runs the job 3 times at once)\n")
    print(row(["backend", "sandboxes", "create all (ms)", "job p50 (ms)", "job max (ms)", "jobs/s", "CPU %",
               "min free (MiB)", "failed"]))
    print(row(["---"] * 9))
    for b in backends(recs, "stress"):
        res = recs[(b, "stress")]["result"]
        for i, lv in enumerate(res["levels"]):
            print(row([b if i == 0 else "", str(lv["sandboxes"]), fmt(lv["create_all_ms"]), fmt(lv["job_p50_ms"]),
                       fmt(lv["job_max_ms"]), fmt(lv["jobs_per_s"]) if lv["jobs_per_s"] is None else f"{lv['jobs_per_s']:.2f}",
                       fmt(lv["cpu_pct"]), fmt(lv["min_free_mb"]), fmt(lv["failed"])]))
        if res.get("stopped"):
            print(row(["", f"stopped: {res['stopped']}"] + [""] * 7))
    print()


def footprint(recs):
    print("### Footprint\n")
    print(row(["backend", "tool's own processes, idle (MiB PSS)", "per idle sandbox (MiB PSS)",
               "per idle sandbox (MiB, MemAvailable drop)"]))
    print(row(["---"] * 4))
    for b in backends(recs, "footprint"):
        res = recs[(b, "footprint")]["result"]
        print(row([b, fmt(res["tool_pss_idle_mb"]), fmt(res["per_sandbox_pss_mb"]),
                   fmt(res["per_sandbox_memavailable_mb"])]))
    print()


def posture(recs):
    print("### Default posture, probed from inside the sandbox\n")
    cols = [("uid", "uid"), ("kernel", "kernel seen"), ("cap_bnd", "capability bounding set"),
            ("no_new_privs", "no_new_privs"), ("rootfs_readonly", "read-only root"), ("egress", "reaches the internet"),
            ("alloc_768mb", "allocate 768 MB"), ("fork_300", "fork 300"), ("write_300mb_tmp", "write 300 MB to /tmp")]
    print(row(["backend", "config"] + [label for _, label in cols]))
    print(row(["---"] * (len(cols) + 2)))
    for b in backends(recs, "posture"):
        res = recs[(b, "posture")]["result"]
        for key in ("defaults", "configured"):
            p = res.get(key, {})
            print(row([b if key == "defaults" else "", key] + [fmt(p.get(k)) for k, _ in cols]))
    print()


def versions(recs):
    print("### Versions\n")
    for b in ORDER:
        r = next((recs[k] for k in recs if k[0] == b), None)
        if r:
            print(f"- **{b}**: {r['version']}")
    host = next(iter(recs.values()))["host"]
    print(f"\nHost: {host['cpu']}, {host['cpus']} CPUs, {host['mem_total_mb']} MiB RAM, kernel {host['kernel']}.\n")


def main():
    recs = latest()
    if not recs:
        sys.exit(f"no results in {RESULTS}")
    for part in (latency, stress, footprint, posture, versions):
        part(recs)


if __name__ == "__main__":
    main()
