"""Every method against the labels, per dataset, plus fusion's flags.

usage: compare.py <labeled.jsonl> <dir with os_stats TSVs>

Datasets are found by TSV name prefix (lab-, cic-monday, unsw-daily-,
unsw-iot-, iot23-); each connection is joined to its label in labeled.jsonl
by client and server address. Unlabelled captures (honeypot, cic-friday,
mawi*) get the lie-detector view: how often the User-Agent's OS contradicts
the TCP stack.
"""
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

PREFIX = [("windows", "windows"), ("linux", "linux"), ("android", "linux"), ("chrome os", "linux"),
          ("wsl", "linux"), ("ubuntu", "linux"), ("aws linux", "linux"), ("mac os", "macos"),
          ("macos", "macos"), ("mac osx", "macos"), ("os x", "macos"), ("ios", "macos"),
          ("iphone", "macos"), ("freebsd", "freebsd"), ("openbsd", "openbsd"), ("solaris", "solaris"),
          ("scanner", "scanner")]
DATASETS = [("lab", "lab-"), ("cic-ids2017", "cic-monday"), ("unsw-daily", "unsw-daily-"),
            ("unsw-iotraffic", "unsw-iot-"), ("iot-23", "iot23-")]
UNLABELLED = ["honeypot", "cic-friday", "mawi2017-5M", "mawi2026-5M"]
METHODS = ["f0p", "ja4t", "ja4h", "tcpcluster", "claimed", "fusion"]
NOISE = {"unknown", "unspecified", "or", "x", "kernel", "nt"}


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


def alternatives(label):
    """`a | b`, `x/{a|b}`, `7 or 8`: the alternatives a label names."""
    m = re.match(r"^(.*)\{(.*)\}(.*)$", label)
    if m:
        return [m.group(1) + alt + m.group(3) for alt in m.group(2).split("|")]
    if " | " in label:
        return label.split(" | ")
    return re.split(r"\s+or\s+", label)


def version_words(label, fam):
    drop = NOISE | {fam, "mac", "os", "osx", "macos", "linux", "windows", "server"}
    return [w for w in words(label) if w not in drop]


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


def os_answer(s, m):
    """(family, version label or None) a method gives, or None."""
    if (m, "os") not in s:
        return None
    label = s[(m, "os")][0]
    if m == "fusion":
        if " | " in label:
            return ("undecided", None)
        return (label, s.get(("fusion", "versions"), (None,))[0])
    if m == "tcpcluster":
        if label == "scanner":
            return None
        return (label, s.get(("tcpcluster", "versions"), (None,))[0])
    return (family(label), label)


def load_labels(path):
    labels = defaultdict(dict)
    wanted = {d for d, _ in DATASETS}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["dataset"] in wanted:
                client, server = r["conn_id"].split("@")[0].split("->")
                labels[r["dataset"]].setdefault((client, server), r["label"])
    return labels


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "-"


def score(files, labels):
    n = 0
    c = defaultdict(Counter)
    flags = Counter()
    wrong = defaultdict(Counter)
    for path in files:
        for s in sessions(path):
            truth = labels.get((s["client"], s["server"]))
            if truth is None:
                continue
            n += 1
            tfam, _, tver = truth.partition("/")
            tv = set(version_words(tver, tfam)) if tver else set()
            for m in METHODS:
                a = os_answer(s, m)
                if a is None:
                    continue
                fam, ver = a
                c[m]["given"] += 1
                if fam == "undecided":
                    c[m]["undecided"] += 1
                    continue
                c[m]["decided"] += 1
                if fam != tfam:
                    wrong[m][f"{tfam} as {fam}"] += 1
                    continue
                c[m]["right"] += 1
                if not tv or not ver:
                    continue
                alts = [set(version_words(a, tfam)) for a in alternatives(ver)]
                alts = [a for a in alts if a]
                if not alts:
                    continue
                c[m]["ver given"] += 1
                hit = [a for a in alts if tv <= a or a <= tv]
                c[m]["ver contains"] += bool(hit)
                c[m]["ver single"] += len(alts) == 1 and bool(hit)
            for k in ("os-inconsistent", "os-ambiguous", "client-inconsistent", "client-ambiguous"):
                flags[k] += ("fusion", k) in s
    return n, c, flags, wrong


def table(name, n, c, flags, wrong):
    print(f"\n## {name}: {n:,} labelled connections\n")
    print("| method | OS given | family right | version given (truth has one) | version set has truth | single version, right |")
    print("|---|---|---|---|---|---|")
    for m in METHODS:
        k = c[m]
        given = pct(k["given"], n)
        if k["undecided"]:
            given += f" ({k['undecided']:,} undecided)"
        print(f"| {m} | {given} | {pct(k['right'], k['decided'])} | {k['ver given']:,} | "
              f"{pct(k['ver contains'], k['ver given'])} | {pct(k['ver single'], k['ver given'])} |")
    w = {m: dict(wrong[m].most_common(3)) for m in METHODS if wrong[m]}
    if w:
        print("wrong families:", w)
    print("fusion flags:", {k: f"{v:,} ({pct(v, n)})" for k, v in flags.items() if v} or "none")


def lies(name, path):
    n = 0
    ua = 0
    flags = Counter()
    patterns = Counter()
    examples = []
    for s in sessions(path):
        n += 1
        ua += ("claimed", "os") in s
        if ("fusion", "os-inconsistent") in s:
            flags["os-inconsistent"] += 1
            sides = s[("fusion", "os-inconsistent")][0]
            patterns[re.sub(r"\s*\([^)]*\)", "", sides)] += 1
            if len(examples) < 4:
                claims = "; ".join(f"{key[0]}.{key[1]}={v[0]!r}" for key, v in s.items()
                                   if isinstance(key, tuple) and key[0] != "fusion" and key[1] in ("os", "client"))
                fused = "; ".join(f"{k}={s[('fusion', k)][0]!r}" for k in ("os", "client", "products")
                                  if ("fusion", k) in s)
                examples.append(f"{s['client']} -> {s['server']}: {claims} | fusion {fused or '(no os)'}")
        flags["os-ambiguous"] += ("fusion", "os-ambiguous") in s
    print(f"\n## {name}: {n:,} connections")
    print(f"User-Agent names an OS: {ua:,} ({pct(ua, n)}); os-inconsistent: {flags['os-inconsistent']:,} "
          f"({pct(flags['os-inconsistent'], n)} of all, {pct(flags['os-inconsistent'], ua)} of those with a User-Agent OS); "
          f"os-ambiguous: {flags['os-ambiguous']:,}")
    for p, v in patterns.most_common(6):
        print(f"  {v:>7,}  {p}")
    for e in examples:
        print("    e.g. " + e)


if __name__ == "__main__":
    labeled, d = sys.argv[1], sys.argv[2]
    labels = load_labels(labeled)
    pooled = [0, defaultdict(Counter), Counter(), defaultdict(Counter)]
    for dataset, prefix in DATASETS:
        files = sorted(glob.glob(os.path.join(d, prefix + "*.tsv")))
        n, c, flags, wrong = score(files, labels[dataset])
        table(f"{dataset} ({len(files)} captures)", n, c, flags, wrong)
        pooled[0] += n
        for m in METHODS:
            pooled[1][m].update(c[m])
            pooled[3][m].update(wrong[m])
        pooled[2].update(flags)
    table("all labelled datasets pooled", *pooled)
    for name in UNLABELLED:
        p = os.path.join(d, name + ".tsv")
        if os.path.exists(p):
            lies(name, p)
