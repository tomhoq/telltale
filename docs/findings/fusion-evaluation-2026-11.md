# Fusion and the methods on every labelled dataset (2026-11-25)

How fusion (specs, Phase 5, "Fusion design") compares with f0p, ja4t, ja4h,
tcpcluster and claimed's User-Agent OS, per connection, on every labelled
capture of the thesis data; how often it flags disagreement; and what the User-Agent
check (`os-inconsistent`) finds. Per-version tables are in
[fusion-evaluation-2026-11-per-version.md](fusion-evaluation-2026-11-per-version.md).

## Setup

- `cli/examples/os_stats.rs` replays each capture, runs every enabled method once on each
  finished TCP session that starts with the client's SYN, and writes the classification
  evidence (OS, versions, client, products, fusion's flags) as TSV. pcapng captures were
  converted to pcap first (dpkt).
- Labels: thesis `data/test/merged/labeled.jsonl`, one label per host, joined per connection
  by client and server address. The true family is the label's first part (`windows/7` ->
  windows).
- Build of 2026-11-25 (commits 74ee187, 940483d): fusion as specced, with two changes made for this evaluation:
  claimed emits the OS its User-Agent names (`os`, from an `os:` list in
  `user-agents.yaml`), and fusion judges `inconsistent` on confidence alone (method weights
  ignored, `min-support` 0.3), so a self-reported claim can be flagged without being
  believed.
- ja4 (TLS) is a stub (no ClientHello parsing) and disabled; it does not appear.

| dataset | captures | labelled connections |
|---|---|---|
| lab (8 VMs) | 8 | 40,349 |
| CIC-IDS2017 Monday | 1 | 131,685 |
| UNSW daily | 20 | 139,999 |
| UNSW IoT traffic | 26 (CanaryCamera read up to a broken pcapng block; none of its connections is labelled) | 787,973 |
| IoT-23 (Echo) | 1 | 345 |
| **all** | **56** | **1,100,351** |

**Caveat:** everything here is in-sample for tcpcluster: its clusters are named from these
labelled connections. Its coverage and accuracy are an upper bound.

## Results, pooled

| method | OS given | family right | version set has truth | single version, right |
|---|---|---|---|---|
| f0p | 100% | 100.0% (40 wrong: Server 2025 as FreeBSD) | 4.1% | 0% |
| ja4t | 2.5% | 100% | 0% | 0% |
| ja4h | 0% | - | - | - |
| tcpcluster | 81.0% | 100% | 99.3% | 30.8% |
| claimed (User-Agent OS) | 53.6% | 99.99% (the 74 lies below) | 100% | 100% |
| **fusion** | **100%** | **100%** | **99.3%** | **29.2%** |

The version columns count connections whose family is right and whose label has a version.

Version sets are short: mean set size 1.5 (lab), 2.7 (CIC), 1.0 (UNSW, IoT-23) for
tcpcluster; 1.95 / 2.5 / 1.0 for fusion. So "set has truth" is not inflated by long lists.

Per dataset, fusion names the right family on every connection it answers, and answers
every connection (f0p always speaks). It never went wrong where one method was right, and
never corrected a wrong majority: on these datasets the methods do not contradict each
other.

## Which versions get mislabelled

From the per-version tables:

- **f0p's versions are wrong almost everywhere.** p0f.fp (2012) has no modern stacks:
  - every modern Linux (Debian 12, Fedora 44, Ubuntu 26.04, Android, Fire OS) is "Linux 2.2.x-3.x";
  - most IoT Linux is "Linux 2.4.x" (91-94%);
  - Ubuntu 12/14/16 are "Linux 3.11 and newer";
  - Windows 8.1, 10 and Vista are "Windows 7 or 8" (right only for Windows 7);
  - Server 2019/2022 are "Windows NT kernel" (family only);
  - Server 2025 is "Windows NT kernel 5.x" (wrong), 1% FreeBSD.
- **ja4t's OS labels are single database examples:** Debian 12 -> "WSL Ubuntu 22.04", Server
  2019/2022 -> "Windows 10", macOS 15/26 -> "Mac OSX/iPhone". Right family, never the
  version (Server 2019 does share Windows 10's 1809 kernel).
- **tcpcluster is almost never wrong on a version; its imprecision is sets of look-alikes:**
  - Ubuntu 12/14/16: always `{ubuntu12|ubuntu14|ubuntu16}`;
  - Windows 7/8.1/10: `{10|7|8.1}` or `{10|8.1}`, the latter missing 7 for 8% of Windows 7;
  - Fedora 44 and Ubuntu 26.04 merged; Server 2019 and 2022 merged (Server 2019 single 86%);
  - macOS 26 mostly `{macos15|macos26}` (single 3%);
  - single and right: Vista, Server 2025, Debian 12, macOS 15 (91%), Android, iOS (100%);
  - Fire OS comes out as `linux/android`: wrong by label, though Fire OS is Android-based.
- **The User-Agent, when present, is right on the version:** Windows 7/8.1/10/Vista from the
  NT version (99-100%), Android versions. Present on 9-32% of CIC Windows connections.
- **Fusion** inherits tcpcluster's sets and narrows them where the User-Agent is single:
  Windows 7 single-right 31%, Windows 10 27%, Vista 90%. Its ja4t inputs widen sets
  (Debian 12 -> `debian 12 | wsl ubuntu 22.04`; Server 2019/2022 gain `10`), so on the lab
  fusion gives a single version less often than tcpcluster alone (20.8% vs 50.4%; pooled
  29.2% vs 30.8%). A lower `version-weights` for ja4t would trade that back.

**Fixed during this evaluation:** fusion dropped tcpcluster's `android` (and any bare
distribution or variant name: `ubuntu`, `ios`). A rule meant for ja4t's `Mac OSX/iPhone`
treated a label made only of its family's keywords as naming no version, and `android` is a
keyword of linux. Now only a family's name and its `family-synonyms` (`os x`, `mac os`,
`osx`, `mac`, `iphone`, `ipad` for macos) say nothing below it. Every other keyword is a
version. Fusion's single-version-right rate went from 15% to 95% on Android (UNSW daily),
0% to 100% on iOS, 21.5% to 29.2% pooled. All numbers above are after the fix.

## Fusion's flags

Across all 1.1M labelled connections:
- `os-inconsistent` fired 74 times, all genuine (below);
- `os-ambiguous`, `client-ambiguous` and `client-inconsistent` never fired.

So there are no false alarms against the labels.

### The User-Agent lie detector

UNSW daily's Samsung Galaxy Tab (`unsw-galaxy-tab`, label `linux/android`) mostly sends
Android 6.0.1 User-Agents. On 65 connections across 13 days it sends instead:

```
Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53
```

f0p and tcpcluster both read its TCP stack as Linux. Fusion answers linux and flags
`os-inconsistent: linux (f0p, tcpcluster) vs macos (claimed)`. UNSW's Android phone 1 does
the same on 9 connections. This is a hard-coded iPhone User-Agent in some app, real
User-Agent spoofing in benign traffic, caught only because the User-Agent's OS is checked
against the stack.

Unlabelled and attack traffic:

| capture | connections | User-Agent names an OS | os-inconsistent |
|---|---|---|---|
| honeypot (1 h) | 679 | 6 | 1 (a Linux stack claiming Windows 10) |
| CIC-IDS2017 Friday (attacks) | 340,668 | 22,195 | 0 |
| MAWI 2017 / 2026, first 5M packets | 103,311 / 750,480 | 0 | 0 |

- **Honeypot:** one hour holds too little HTTP to measure an attacker lie rate.
- **CIC Friday:** its attacks (DDoS, botnet, port scans) run on the lab's real Windows and
  Ubuntu hosts, so User-Agent and stack agree.
- **MAWI:** keeps 96 bytes per packet. No User-Agent survives, so the check is blind on
  backbone traffic.

## Fusion against a plain majority vote (MAWI)

In a plain vote, each method naming an OS has one vote, and a tie has no winner. On MAWI
2017 (2,442,771 connections, full capture; build before the User-Agent change):

| | connections |
|---|---|
| f0p / tcpcluster / fusion give an OS | 27.6% / 7.3% / 26.7% |
| fusion gives a client | 36.8% |
| scanner rule: the vote would say Linux, fusion withholds the OS (the SYN is a scanner's) | 24,468 (1.0%) |
| one-to-one tie broken by weight (e.g. f0p weak Windows vs tcpcluster strong macOS -> macos) | 68 |
| tie left undecided (both strong: f0p FreeBSD 0.6 vs tcpcluster Windows 1.0 = 62.5% < 70%) | 93 |

On the first 5M packets of MAWI 2026 the scanner rule changes 82,246 of 750,480 (11%). Real
conflicts are rare: 161 of 180,045 MAWI 2017 connections where two or more methods name an
OS. The weighting is a safeguard. The scanner rule is where fusion changes many answers.

## Reproducing

The scripts are in [`scripts/`](scripts/) (see its README):
- `run-all-captures.sh`: the os_stats runs.
- `compare.py`: the pooled and per-dataset tables, and the lie detector.
- `per_version.py`: the appendix.
- `majority.py`: the majority-vote comparison.

The per-connection TSVs they read (one per capture, 50 MB to 5 GB) are not in git. They
are in `D:\Documents\telltale-stats\eval-all\` (and `fusion\` for MAWI), and can be
regenerated from the captures with the run script.
