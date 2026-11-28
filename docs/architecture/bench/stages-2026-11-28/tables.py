"""The --timings tables of run.sh as one presentation table per output mode:
rows = the tool's stages and each method, columns = datasets, values in us
per packet read.

usage: tables.py <dir>
"""
import os
import re
import sys

DATASETS = ["honeypot", "debian12", "macos15", "cic-monday", "mawi2026-5M"]
MODES = ["per-session", "inference-time"]
STAGES = ["capture", "assembly", "dispatch", "output", "summary"]
METHODS = ["f0p", "ja4t", "ja4h", "claimed", "tcpcluster", "fusion"]
TOTALS = ["= infrastructure", "= methods", "= all work", "wait at end", "wall"]
LABEL = {
    "capture": "capture (read + decode)",
    "assembly": "session assembly",
    "dispatch": "dispatch (snapshot + queue)",
    "output": "output (store + live lines)",
    "summary": "end-of-capture summary",
    "= infrastructure": "**Telltale itself (sum)**",
    "= methods": "**methods (sum)**",
    "= all work": "**all work (CPU)**",
    "wait at end": "wait for workers at the end",
    "wall": "**wall time**",
}


def parse(path):
    rows, head = {}, {}
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.search(r"over (\d+) packets: wall (\d+) ms .*?, (\d+) workers", text)
    if m:
        head = {"packets": int(m.group(1)), "workers": int(m.group(3))}
    for line in text.splitlines():
        for name in STAGES + METHODS + TOTALS:
            if line.startswith(name + " ") or line.startswith(name + "\t"):
                rows[name] = float(line.split()[-1])
    return head, rows


def main(d):
    for mode in MODES:
        data = {ds: parse(os.path.join(d, f"{ds}.{mode}.txt")) for ds in DATASETS
                if os.path.exists(os.path.join(d, f"{ds}.{mode}.txt"))}
        data = {ds: v for ds, v in data.items() if v[0]}  # runs stopped before the end have no table
        if not data:
            continue
        cols = list(data)
        print(f"\n### {mode} (µs per packet)\n")
        print("| | " + " | ".join(cols) + " |")
        print("|---|" + "---|" * len(cols))
        print("| packets | " + " | ".join(f"{data[c][0].get('packets', 0):,}" for c in cols) + " |")
        for name in STAGES + ["---"] + METHODS + ["---"] + TOTALS:
            if name == "---":
                continue
            label = LABEL.get(name, name)
            vals = []
            for c in cols:
                v = data[c][1].get(name)
                vals.append("-" if v is None else (f"**{v:.1f}**" if label.startswith("**") else f"{v:.1f}"))
            print(f"| {label} | " + " | ".join(vals) + " |")
        workers = {data[c][0].get("workers") for c in cols}
        print(f"\nworkers: {', '.join(map(str, workers))}")


if __name__ == "__main__":
    main(sys.argv[1])
