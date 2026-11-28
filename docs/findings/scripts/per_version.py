"""Per true label (e.g. windows/7): what each method answers, and how often right.

usage: per_version.py <labeled.jsonl> <dir with os_stats TSVs>

For every label in the labelled datasets, and every method: how often it
answers, how often its version is right as a single version, how often its
set contains the truth, and its most common answers, so the versions that
get mislabelled stand out.
"""
import glob
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare import DATASETS, alternatives, family, load_labels, sessions, version_words  # noqa: E402

METHODS = ["f0p", "ja4t", "tcpcluster", "claimed", "fusion"]


def answer(s, m):
    """The method's answer as one label (family + version as it says it)."""
    if m in ("tcpcluster", "fusion"):
        if (m, "os") not in s:
            return None
        os_ = s[(m, "os")][0]
        if m == "tcpcluster" and os_ == "scanner":
            return None
        ver = s.get((m, "versions"), (None,))[0]
        return f"{os_} / {ver}" if ver else os_
    return s[(m, "os")][0] if (m, "os") in s else None


def judge(label, m, truth):
    tfam, _, tver = truth.partition("/")
    tv = set(version_words(tver, tfam))
    fam_part, _, ver_part = label.partition(" / ")
    fam = fam_part if m in ("tcpcluster", "fusion") else family(label)
    if fam != tfam:
        return "wrong family"
    if not tv:
        return "family right"
    ver = ver_part if m in ("tcpcluster", "fusion") else label
    alts = [set(version_words(a, tfam)) for a in alternatives(ver)] if ver else []
    alts = [a for a in alts if a]
    if not alts:
        return "family only"
    hits = [a for a in alts if tv <= a or a <= tv]
    if not hits:
        return "wrong version"
    return "single right" if len(alts) == 1 else "set has truth"


def main(labeled, d):
    labels = load_labels(labeled)
    per = defaultdict(lambda: defaultdict(Counter))      # truth -> method -> verdict
    said = defaultdict(lambda: defaultdict(Counter))     # truth -> method -> label
    n = Counter()
    for dataset, prefix in DATASETS:
        for path in sorted(glob.glob(os.path.join(d, prefix + "*.tsv"))):
            for s in sessions(path):
                truth = labels[dataset].get((s["client"], s["server"]))
                if not truth:
                    continue
                key = f"{truth} ({dataset})"
                n[key] += 1
                for m in METHODS:
                    a = answer(s, m)
                    if a is None:
                        per[key][m]["no answer"] += 1
                        continue
                    per[key][m][judge(a, m, truth)] += 1
                    said[key][m][a] += 1
    for key, total in sorted(n.items(), key=lambda kv: (-kv[1])):
        print(f"\n### {key}: {total:,} connections\n")
        print("| method | answers | single right | set has truth | family only | wrong version | wrong family | most common answers |")
        print("|---|---|---|---|---|---|---|---|")
        for m in METHODS:
            v = per[key][m]
            given = total - v["no answer"]
            p = lambda k: f"{100 * v[k] / given:.0f}%" if given else "-"  # noqa: E731
            top = "; ".join(f"`{lab}` {100 * c / given:.0f}%" for lab, c in said[key][m].most_common(3)) if given else ""
            fam_only = v["family only"] + v["family right"]
            print(f"| {m} | {100 * given / total:.0f}% | {p('single right')} | {p('set has truth')} | "
                  f"{100 * fam_only / given:.0f}% | {p('wrong version')} | {p('wrong family')} | {top} |"
                  if given else f"| {m} | 0% | | | | | | |")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
