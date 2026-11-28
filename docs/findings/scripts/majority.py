"""Where fusion's weighted answer differs from a plain majority vote.

usage: majority.py name=file.tsv ...   (os_stats TSV with fusion keys)

A plain vote gives each method that names an OS family one vote; the family
with most votes wins, a tie has no winner. Fusion weighs the same claims
(method weight x confidence, fusion.yaml) and applies the scanner rule.
Reported per capture: coverage, then each kind of difference with counts
and example connections.
"""
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from evaluate import family, sessions  # noqa: E402

OS_METHODS = ["f0p", "ja4t", "ja4h", "tcpcluster"]


def claims(s):
    """method -> (family, raw label, confidence) for OS claims; tcpcluster's
    `scanner` is a client claim, not an OS."""
    out = {}
    for m in OS_METHODS:
        if (m, "os") in s:
            label, conf = s[(m, "os")]
            fam = label if m == "tcpcluster" else family(label)
            if fam == "scanner":
                continue
            out[m] = (fam, label, conf)
    return out


def plain_vote(c):
    votes = Counter(f for f, _, _ in c.values())
    if not votes:
        return None
    (top, n), *rest = votes.most_common()
    return None if rest and rest[0][1] == n else top


def pct(a, b):
    return f"{100 * a / b:.2f}%" if b else "-"


def show(s, c):
    parts = [f"{m}={label!r} ({conf.lower()})" for m, (_, label, conf) in c.items()]
    for m in ("ja4t", "claimed", "f0p", "ja4h"):
        if (m, "client") in s:
            parts.append(f"{m}.client={s[(m, 'client')][0]!r} ({s[(m, 'client')][1].lower()})")
    if s.get(("tcpcluster", "os"), ("",))[0] == "scanner":
        parts.append("tcpcluster.os='scanner' (strong)")
    fused = [f"{k}={s[('fusion', k)][0]!r} ({s[('fusion', k)][1].lower()})"
             for k in ("os", "versions", "client", "products", "os-ambiguous", "os-inconsistent")
             if ("fusion", k) in s]
    return f"{s['client']} -> {s['server']}\n      claims: {'; '.join(parts)}\n      fusion: {'; '.join(fused) or '(nothing)'}"


def report(name, path):
    n = 0
    given = Counter()
    fusion_conf = Counter()
    multi = 0
    kinds = Counter()
    patterns = defaultdict(Counter)
    examples = defaultdict(list)
    for s in sessions(path):
        n += 1
        c = claims(s)
        for m in c:
            given[m] += 1
        f = s.get(("fusion", "os"), (None, None))
        fos = f[0]
        if fos:
            given["fusion os"] += 1
            if " | " in fos:
                given["fusion os undecided"] += 1
            fusion_conf[f[1]] += 1
        for k in ("versions", "client", "products"):
            given[f"fusion {k}"] += ("fusion", k) in s
        vote = plain_vote(c)
        fams = {fam for fam, _, _ in c.values()}
        if len(c) >= 2:
            multi += 1
        decided = fos if fos and " | " not in fos else None
        pattern = " vs ".join(sorted(f"{fam}({','.join(m for m, v in c.items() if v[0] == fam)})" for fam in fams))
        kind = None
        if c and not fos and s.get(("fusion", "client"), ("",))[0] == "scanner":
            kind = "4 scanner rule: OS withheld"
        elif len(fams) >= 2 and vote is None and decided:
            kind = "1 tie broken by weight"
        elif len(fams) >= 2 and vote and decided and decided != vote:
            kind = "2 minority wins by weight"
        elif vote and fos and " | " in fos:
            kind = "3 majority rejected: undecided"
        elif vote is None and fos and " | " in fos:
            kind = "6 tie left undecided (ambiguous)"
        elif len(fams) >= 2 and vote and decided == vote:
            kind = "5 disagreement, majority = fusion"
        if kind:
            kinds[kind] += 1
            patterns[kind][f"{pattern} -> {fos or '-'}"] += 1
            if len(examples[kind]) < 3:
                examples[kind].append(show(s, c))

    print(f"\n## {name}: {n:,} SYN-started TCP connections\n")
    print("| | gives it | share |")
    print("|---|---|---|")
    for k in OS_METHODS + ["fusion os", "fusion os undecided", "fusion versions", "fusion client", "fusion products"]:
        print(f"| {k} | {given[k]:,} | {pct(given[k], n)} |")
    print(f"fusion os confidence: {dict(fusion_conf.most_common())}")
    print(f"connections with 2+ methods naming an OS: {multi:,}\n")
    for kind in sorted(kinds):
        share = f"{pct(kinds[kind], n)} of all"
        if not kind.startswith("4"):
            share += f", {pct(kinds[kind], multi)} of those with 2+ methods"
        print(f"### {kind[2:]}: {kinds[kind]:,} ({share})")
        for p, v in patterns[kind].most_common(4):
            print(f"  {v:>9,}  {p}")
        for e in examples[kind]:
            print("    e.g. " + e)
        print()


if __name__ == "__main__":
    for spec in sys.argv[1:]:
        name, path = spec.split("=", 1)
        report(name, path)
