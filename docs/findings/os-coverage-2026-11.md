# OS coverage and agreement across methods (2026-11-20)

An early run of the Phase 6 question: how often does each method name an OS, and
how often does a method add an answer nothing else gives? Measured per TCP
connection that starts with the client's SYN, with every enabled method run once
on the finished session (default direction policy: initiator only).

Tool: `cli/examples/os_stats.rs` (TSV of the `os` / `versions` / `hint` evidence
per connection). It reads packets with `next_raw_packet`, because at the time
Telltale's `PcapFileSource` stopped at the first packet truncated by the
snaplen (since fixed; see "Open issues").

## Datasets

| dataset | connections | notes |
|---|---|---|
| lab | 41,697 | 8 VMs with known OS (debian12, fedora44, ubuntu2604, macos15, macos26, server2019/2022/2025) |
| honeypot | 679 | `hp-20260928-23` |
| MAWI 2017 | 2,442,771 | 128M packets, snaplen 96 |
| MAWI 2026 | 32,109,247 | 215M packets, snaplen 96 (thesis `data/train/mawi`) |

**Caveat:** all four overlap tcpcluster's own data. The lab hosts name its
clusters, the honeypot and MAWI 2017 are in its reference set, and MAWI 2026 is
its training capture. Its coverage and accuracy here are an upper bound. A fair
measure needs a capture it has never seen.

## How often each method names an OS

| | lab | honeypot | MAWI 2017 | MAWI 2026 |
|---|---|---|---|---|
| any method | ~100% | 60.8% | 27.7% | 67.8% |
| f0p OS / version | 99.7 / 44.9% | 60.8 / 58.3% | 27.6 / 18.4% | 67.6 / 63.3% |
| ja4t OS / version | 69.2 / 43.8% | 7.1 / 6.8% | 0.3 / 0.3% | 0.7 / 0.6% |
| ja4h | 0 | 0 | 0 | 0 |
| tcpcluster OS / version set | 99.8 / 99.8% | 22.7 / 22.2% | 8.0 / 7.4% | 9.7 / 9.6% |
| tcpcluster hint (no name) | 0.1% | 21.2% | 13.3% | 43.6% |

Lab accuracy (family): f0p 99.9%, ja4t 100%, tcpcluster 100%. tcpcluster's
version set contains the true version 99.5–100% of the time. f0p's version
labels are often wrong: Debian/Ubuntu get "Linux 2.2.x-3.x", Server 2025 gets
"Windows NT kernel 5.x".

## Agreement on the family

| | lab | honeypot | MAWI 2017 | MAWI 2026 |
|---|---|---|---|---|
| f0p / tcpcluster | 99.9% | 68.2% | 91.4% | 35.2% |
| same, scanner not counted | 99.9% | ~99% | ~99.9% | ~99.9% |
| f0p / ja4t | 100% | 100% | 100% | 100% |
| ja4t / tcpcluster | 100% | 100% | 100% | 100% |
| tcpcluster hint / f0p | 100% | 93.8% | 79.4% | 95.2% |

Nearly every disagreement is tcpcluster saying `scanner` (ZMap-like SYNs) where
f0p says linux: ~2M connections in MAWI 2026, 16k in 2017. Real OS-vs-OS
conflicts are ~850 of 1.08M (2026), mostly freebsd vs windows. Fusion has to
decide whether `scanner` overrides an OS answer.

## Overlap and unique answers

| methods answering | MAWI 2017 | MAWI 2026 | honeypot |
|---|---|---|---|
| none | 72.0% | 32.1% | 39.2% |
| f0p + hint | 12.9% | 43.4% | 20.9% |
| f0p alone | 6.7% | 14.6% | 16.9% |
| f0p + tcpcluster | 7.7% | 8.9% | 15.9% |
| f0p + ja4t + tcpcluster | 0.21% | 0.64% | 6.8% |
| f0p + ja4t + hint | 0.12% | 0.04% | 0.3% |
| tcpcluster alone | 0.05% | 0.17% | 0 |
| hint alone | 0.30% | 0.15% | 0 |

- ja4t never answers alone: every ja4t answer is also an f0p and a tcpcluster answer.
- 98–99% of tcpcluster's named connections are also named by f0p.
- f0p is the only named answer on 19.6% (2017) / 58.0% (2026) of connections.

## Why tcpcluster coverage is low and adds so little

1. **Most MAWI connections are unanswered SYNs, and those are almost never
   named.** The tuple is the SYN plus the client's reply to the SYN-ACK. Split
   by reply state, the method's fingerprint table (reference + labelled
   connections) reads:

   | reply in tuple | share of connections | named |
   |---|---|---|
   | none (unanswered SYN) | 68.4% | 7.7% |
   | ACK (full handshake) | 31.0% | 96.5% |
   | RST / SYN-ACK unanswered | 0.6% | 57–69% |

   Names come from labelled lab connections, which are full handshakes. A tuple
   ending in "no reply" sits away from the named clusters. The busiest unnamed
   tuples are option-less scan SYNs such as `EMPTY|1024|-|15|…|3|-|-|4` (99k
   connections).
2. **Few names exist.** 48 of 258 clusters are named, and 1,269 of 52,078 known
   tuples. Names are attached only where labelled traffic exists.
3. **Its names are the common stacks f0p already knows.** The labelled OSes
   (Linux, Windows, macOS) are exactly the stacks f0p's signatures cover, and f0p
   needs only the SYN, where tcpcluster also needs the reply. So what tcpcluster
   can name is close to a subset of what f0p names by construction.
4. **The encoder generalises only a little.** On a lookup miss it names a tuple only
   within the cluster radius (epsilon 0.055) of a named member. On MAWI 2026,
   3.08M answers came from the table and 41k from the encoder.
5. **The hint is broader but repeats f0p.** It covers common stacks, which f0p
   already names (95% agreement on MAWI 2026, 0.15% hint-only).

Where tcpcluster does add something is precision rather than coverage:
version sets that are right where f0p's version is wrong, and the `scanner`
name.

A way to raise its coverage would be a SYN-only fallback when no reply was seen.
That's a design decision for the method, not something done here.

## Why f0p calls scanner SYNs Linux

Every one of the 16,432 MAWI 2017 connections tcpcluster names `scanner` gets
f0p's `Linux 2.2.x-3.x (barebone)`, as Weak. The SYN is ZMap's: MSS-only
options, window 65535, TTL 255 (bucket 3), no DF, IP ID 54321 (the last SYN bit,
`…00000000001`). The signature it lands on is p0f's generic catch-all:

```
label = g:unix:Linux:2.2.x-3.x (barebone)
sig   = *:64:0:*:*,0:mss:df,id+:0
```

- MSS and window are `*`, and the layout is `mss` alone, so the identifying
  fields all agree.
- The missing `df,id+` is forgiven, because p0f reads a cleared DF as a
  middlebox's doing (`quirks_fit`).
- TTL 255 above the initial 64 only makes the match fuzzy, because the
  signature's TTL isn't a ceiling (`fit_tcp`).

Two forgiven differences give a fuzzy match, so the answer is Weak. p0f's
database has an NMap SYN-scan signature (`*:64-:0:1460:1024,0:mss::0`, a tool
label `!`), but none for ZMap or Masscan, so nothing more specific wins.

## Open issues

- Fixed: `PcapFileSource` used pcap-file's `next_packet`, which rejects packets
  with orig_len > snaplen, so it couldn't replay snaplen-limited captures such
  as MAWI. It now reads with `next_raw_packet`, as `os_stats` does.
- Lab and honeypot captures in pcapng had to be converted to pcap first.
