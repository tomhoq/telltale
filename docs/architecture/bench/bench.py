"""Wall time + --timings table per (capture, mode, methods on/off)."""
import subprocess, sys, time, json, re
exe, nomethods, out = sys.argv[1], sys.argv[2], sys.argv[3]
caps = [a.split("=", 1) for a in sys.argv[4:]]
res = []
for name, path in caps:
    for mode in ("per-session", "inference-time"):
        for label, d in (("none", nomethods), ("all", "methods/manifests")):
            reps = 3 if name in ("honeypot", "debian12", "macos15") else 1
            walls = []
            for _ in range(reps):
                t = time.perf_counter()
                try:
                    p = subprocess.run([exe, "--output", mode, "--manifest-dir", d, "--timings", "replay", "-p", path],
                                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600)
                except subprocess.TimeoutExpired:
                    walls.append(None); break
                walls.append(time.perf_counter() - t)
            txt = p.stdout[p.stdout.find("=== method timings"):] if walls[-1] else ""
            pk = re.search(r"over (\d+) packets", txt)
            rows = {m.group(1): [float(x) for x in m.groups()[1:]] for m in re.finditer(
                r"^(\S+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)$", txt, re.M)}
            al = re.search(r"^all\s+([\d.]+)\s+([\d.]+)$", txt, re.M)
            r = dict(cap=name, mode=mode, methods=label, wall=min(w for w in walls if w) if walls[-1] else None,
                     packets=int(pk.group(1)) if pk else None, rows=rows,
                     method_ms=float(al.group(1)) if al else None, err=p.stderr[-300:] if walls[-1] and p.returncode else "")
            res.append(r); print(json.dumps(r), flush=True)
json.dump(res, open(out, "w"), indent=1)
