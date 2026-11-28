"""Fusion against the individual methods, per SYN-started TCP connection.

usage: evaluate.py <labeled.jsonl> name=file.tsv[:dataset] ...
  A `:dataset` suffix (cic-ids2017, unsw-daily, unsw-iotraffic, iot-23) joins
  each connection to its label in labeled.jsonl by client and server address;
  without it the capture is scored unlabelled (coverage, agreement, flags).
"""
import json
import re
import sys
from collections import Counter, defaultdict

PREFIX = [("windows", "windows"), ("linux", "linux"), ("android", "linux"), ("wsl", "linux"),
          ("ubuntu", "linux"), ("aws linux", "linux"), ("mac os", "macos"), ("macos", "macos"),
          ("mac osx", "macos"), ("os x", "macos"), ("ios", "macos"), ("iphone", "macos"),
          ("freebsd", "freebsd"), ("openbsd", "openbsd"), ("solaris", "solaris"), ("scanner", "scanner")]
METHODS = ["f0p", "ja4t", "ja4h", "tcpcluster", "fusion"]
FLAGS = ["os-ambiguous", "os-inconsistent", "client-ambiguous", "client-inconsistent"]


def family(label):
    l = label.lower()
    for p, f in PREFIX:
        if l.startswith(p):
            return f
    return "other"


def words(text):
    out = []
    for raw in re.split(r"[^0-9a-z.]+", text.lower()):
        out += [w.strip(".") for w in re.findall(r"[0-9.]+|[a-z]+", raw) if w.strip(".")]
    return out


def sessions(path):
    cur, s = None, None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 7:
                continue
            if p[0] != cur:
                if s:
                    yield s
                cur, s = p[0], {"client": p[1], "server": p[2]}
            if p[3] != "#session":
                s[(p[3], p[4])] = (p[5], p[6])
    if s:
        yield s


def answers(s):
    """method -> family, for the methods that named one."""
    out = {}
    for m in ("f0p", "ja4t", "ja4h"):
        if (m, "os") in s:
            out[m] = family(s[(m, "os")][0])
    if ("tcpcluster", "os") in s:
        v = s[("tcpcluster", "os")][0]
        out["tcpcluster"] = v if v != "scanner" else "scanner"
    if ("fusion", "os") in s:
        v = s[("fusion", "os")][0]
        out["fusion"] = "undecided" if " | " in v else v
    return out


def load_labels(path, datasets):
    labels = {d: {} for d in datasets}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["dataset"] in labels:
                pair = r["conn_id"].split("@")[0]
                client, server = pair.split("->")
                labels[r["dataset"]].setdefault((client, server), r["label"])
    return labels


def pct(a, b):
    return f"{100 * a / b:5.1f}%" if b else "    -"


def report(name, path, labels):
    n = 0
    given, right = Counter(), Counter()
    conf = Counter()
    flags, examples = Counter(), {}
    versions = Counter()
    client = Counter()
    fusion_saves, fusion_loses = 0, 0
    for s in sessions(path):
        truth = None
        if labels is not None:
            truth = labels.get((s["client"], s["server"]))
            if truth is None:
                continue
        n += 1
        a = answers(s)
        tf = truth.split("/")[0] if truth else None
        for m, fam in a.items():
            given[m] += 1
            if tf:
                right[m] += fam == tf
        if ("fusion", "os") in s and a.get("fusion") != "undecided":
            c = s[("fusion", "os")][1]
            conf[(c, (a["fusion"] == tf) if tf else None)] += 1
        for k in FLAGS:
            if ("fusion", k) in s:
                flags[k] += 1
                examples.setdefault(k, (s["client"], s[("fusion", k)][0]))
        if ("fusion", "client") in s:
            client[s[("fusion", "client")][0]] += 1
        if tf and ("fusion", "versions") in s and a.get("fusion") == tf:
            tv = set(words(truth.split("/", 1)[1])) - {"unknown", "unspecified"}
            if tv:
                fv = s[("fusion", "versions")][0]
                cands = [set(words(c)) for c in fv.split(" | ")]
                versions["contains truth" if any(tv <= c or c <= tv for c in cands) else "misses truth"] += 1
                versions["exact" if len(cands) == 1 and (tv <= cands[0] or cands[0] <= tv) else "set or wrong"] += 1
        if tf:
            others = [a[m] for m in ("f0p", "ja4t", "ja4h", "tcpcluster") if m in a]
            if a.get("fusion") == tf and others and Counter(others).most_common(1)[0][0] != tf:
                fusion_saves += 1
            if a.get("fusion") not in (tf, None, "undecided") and tf in others:
                fusion_loses += 1

    print(f"\n## {name}: {n:,} connections" + (" (labelled)" if labels is not None else ""))
    head = "| method | OS given |" + (" family right |" if labels is not None else "")
    print(head)
    print("|" + "---|" * (head.count("|") - 1))
    for m in METHODS:
        cell = f"| {m} | {pct(given[m], n)} |"
        if labels is not None:
            cell += f" {pct(right[m], given[m])} |"
        print(cell)
    print(f"fusion undecided (a | b): {pct(given['fusion'] - sum(conf.values()), n)}")
    print("fusion confidence:", {f"{c}{'' if ok is None else (' right' if ok else ' WRONG')}": v for (c, ok), v in sorted(conf.items(), key=lambda x: -x[1])})
    if labels is not None:
        print(f"fusion right where the methods' majority was wrong: {fusion_saves:,}; "
              f"fusion wrong where some method was right: {fusion_loses:,}")
        if versions:
            vt = versions["contains truth"] + versions["misses truth"]
            print(f"fusion versions (family right, truth has a version): contain truth {pct(versions['contains truth'], vt)}, "
                  f"single and right {pct(versions['exact'], vt)} of {vt:,}")
    print("flags:", {k: f"{v:,} ({pct(v, n).strip()})" for k, v in flags.items()} or "none")
    for k, (c, v) in examples.items():
        print(f"  e.g. {k}: {c} {v}")
    print("fusion.client:", dict(client.most_common(6)))


if __name__ == "__main__":
    labeled, specs = sys.argv[1], sys.argv[2:]
    runs = []
    for spec in specs:
        name, rest = spec.split("=", 1)
        path, _, dataset = rest.partition(":") if not re.match(r"^[a-zA-Z]:[\\/]", rest) else (rest, "", "")
        if re.match(r"^[a-zA-Z]:[\\/]", rest) and rest.count(":") > 1:
            path, dataset = rest.rsplit(":", 1)
        runs.append((name, path, dataset or None))
    datasets = {d for _, _, d in runs if d}
    labels = load_labels(labeled, datasets) if datasets else {}
    for name, path, dataset in runs:
        report(name, path, labels.get(dataset) if dataset else None)
