# Scripts behind the findings

The analysis scripts that produced the tables in
[fusion-evaluation-2026-11.md](../fusion-evaluation-2026-11.md) and its per-version
appendix, kept with the docs so the numbers can be regenerated. Their input is the
per-connection TSV that `cli/examples/os_stats.rs` writes: one row per piece of OS
evidence, plus a `#session` row per SYN-started TCP connection.

The batch scripts use absolute paths from the machine they ran on: captures under
`D:\Documents\new-method\data\test`, output under `D:\Documents\telltale-stats`. The TSVs
are 50 MB to 5 GB each, so they stay there, not in git; they can be regenerated from the
captures.

| script | what it does |
|---|---|
| `run-all-captures.sh` | runs `os_stats` on every labelled capture (lab, CIC Monday, UNSW daily and IoT, IoT-23) and on the honeypot, CIC Friday and the two MAWI samples; converts pcapng first |
| `run-first-batch.sh` | the first, smaller batch (CIC, IoT-23, honeypot, MAWI samples) |
| `ng2pcap.py` | pcapng to pcap, with dpkt (`os_stats` reads pcap only) |
| `compare.py` | every method against the labels, per dataset and pooled; the User-Agent lie detector on unlabelled captures |
| `per_version.py` | per true label: what each method answers and how often it's right (the appendix) |
| `evaluate.py` | the first per-dataset evaluation (coverage, family right, flags) |
| `majority.py` | fusion against a plain majority vote on MAWI: ties, scanner rule, undecided |

Usage:

```
python compare.py <labeled.jsonl> <dir with os_stats TSVs>
python per_version.py <labeled.jsonl> <dir with os_stats TSVs>
python majority.py name=file.tsv ...
```

`labeled.jsonl` is the thesis's `data/test/merged/labeled.jsonl`. `majority.py` needs
`evaluate.py` next to it, and `per_version.py` needs `compare.py`.

The scripts behind the earlier [os-coverage-2026-11.md](../os-coverage-2026-11.md)
(`stats.py`, `venn.py`) were kept in a temporary folder and are lost. `evaluate.py` and
`majority.py` compute the same kind of figures: coverage per method, pairwise
agreement, overlap.
