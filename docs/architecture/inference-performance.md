# Inference-mode performance: measurements and changes (2026-11-22)

How much each method costs per packet, how much Telltale itself costs, and
what changed in the dispatch path to bring inference mode from ~1 ms per packet
to tens of µs. The raw results and the script are in [`bench/`](bench/).

## Where the time goes, per stage (2026-11-28)

One run per dataset and output mode, `telltale-pf --timings --output <mode> replay -p
<capture>`, text output, 12 workers, build `f9fdec1` plus the stage timers. Since that
change, `--timings` times the tool's own stages as well as each method, in the same run:

| stage | thread | what |
|---|---|---|
| capture | main | reading and decoding packets |
| session assembly | main | assigning packets to sessions, timeouts |
| dispatch | main | handing sessions to the workers (in inference mode: a snapshot on every packet) |
| output | consumer | recording evidence into the profile store, and the live lines in inference mode |
| end-of-capture summary | main | rendering and printing the summary |
| each method | workers | time inside its `extract` |

All values are µs per packet read. Stages and methods are CPU work. The main thread, the
consumer and the 12 workers run at the same time, so the work adds up to more than the wall
time.

**Per-session mode** (each session analysed once, when it ends):

| | honeypot | debian12 (lab) | macos15 (lab) | CIC Monday |
|---|---|---|---|---|
| packets | 28,772 | 330,048 | 1,113,093 | 4,989,228 |
| capture (read + decode) | 0.9 | 0.4 | 1.1 | 0.4 |
| session assembly | 0.6 | 1.5 | 0.7 | 4.1 |
| dispatch | 0.1 | 0.1 | 0.1 | 0.2 |
| output | 0.4 | 0.2 | 0.1 | 0.3 |
| end-of-capture summary | 1.1 | 0.2 | 0.0 | 0.2 |
| f0p | 0.5 | 0.2 | 0.1 | 0.4 |
| ja4t | 0.1 | 0.1 | 0.0 | 0.1 |
| ja4h | 0.2 | 0.0 | 0.0 | 0.6 |
| claimed | 0.1 | 0.0 | 0.0 | 0.1 |
| tcpcluster | 3.5 | 0.1 | 0.1 | 0.8 |
| fusion | 0.8 | 0.6 | 0.2 | 0.9 |
| **Telltale itself (sum)** | **3.2** | **2.3** | **2.0** | **5.2** |
| **methods (sum)** | **5.3** | **1.1** | **0.5** | **3.0** |
| **wall time** | **3.1** | **2.3** | **2.1** | **5.1** |

**Inference mode** (every packet re-analyses its session, live output):

| | honeypot | debian12 (lab) | macos15 (lab) |
|---|---|---|---|
| packets | 28,772 | 330,048 | 1,113,093 |
| capture (read + decode) | 1.5 | 0.9 | 0.9 |
| session assembly | 1.2 | 2.6 | 1.1 |
| dispatch (snapshot) | 58.2 | 27.9 | 108.4 |
| output (store + live lines) | 5.6 | 11.8 | 7.7 |
| end-of-capture summary | 0.1 | 0.2 | 0.1 |
| f0p | 18.3 | 56.7 | 50.2 |
| ja4t | 15.5 | 0.3 | 17.3 |
| ja4h | 0.2 | 0.0 | 0.1 |
| claimed | 0.0 | 0.0 | 0.0 |
| tcpcluster | 23.8 | 0.4 | 18.5 |
| fusion | 10.3 | 41.6 | 24.6 |
| **Telltale itself (sum)** | **66.6** | **43.4** | **118.2** |
| **methods (sum)** | **68.2** | **99.0** | **110.7** |
| **wall time** | **64.3** | **32.3** | **110.8** |

What it shows:

- **Per-session mode costs 2-5 µs per packet** in total. Telltale's own stages take about as
  much as all the methods together.
  - The largest method cost is tcpcluster on the honeypot, 3.5 µs, because most honeypot
    tuples miss the fingerprint table and go through the encoder.
  - Session assembly grows with the number of open sessions (CIC 4.1 µs).
- **In inference mode the per-packet snapshot (dispatch) is the bottleneck:** 28-108 µs
  per packet, and the wall time follows it.
  - The methods' 68-111 µs of CPU run on the 12 workers alongside, so they cost little
    wall time.
  - Among the methods, f0p and fusion now cost most. f0p stays `Partial` until the session
    ends, and fusion re-merges on every packet; the rest return `Complete` early.
- **Two scaling limits, measured rather than estimated:**
  - **Long sessions in inference mode:** CIC Monday had not finished after 27 min 47 s and
    was stopped. The snapshot grows with session length.
  - **Many open sessions in either mode:** the first 5M packets of MAWI 2026 had not
    finished per-session after 20 min. `Assembler::expire` scans every open session on every
    packet, and backbone scans keep tens of thousands open for the 30 s timeout. `os_stats`,
    which expires every 4,096 packets, read the same capture in 2 min.
- **Fixes, not implemented:**
  - expire at most once per second of capture time (or keep sessions in a time-ordered
    index), which makes assembly constant per packet;
  - snapshots that cost the same at any session length;
  - f0p returning `Complete` once it has nothing left to wait for.

Raw tables and scripts: [`bench/stages-2026-11-28/`](bench/stages-2026-11-28/).

## The path being measured

```
capture source ──► Assembler ──► (per-session) one job when the session ends
   (pcap replay)   sessions by   (inference)   one job per packet: a snapshot
                   5-tuple,                    of the session so far
                   30 s timeout          │
                                         ▼
                              worker pool (8 threads)
                                         │
                                         ▼
                   Registry::analyze_each: every enabled method, in priority
                   order, whose stage/trigger allows it  ──►  evidence stream
```

- **per-session**: each session is analysed once, when it closes or times out.
- **inference-time**: a snapshot of the session goes to a worker on every
  packet, so the verdict can be refined as data arrives (`cli/src/main.rs`,
  `run`).

Enabled methods: f0p, ja4t, ja4h, claimed, tcpcluster. ja4 and fusion were
disabled in their manifests.

## Setup

- Intel Core i7-8700K (6 cores / 12 threads), 16 GB, Windows 10, rustc 1.96.0,
  `--release`, 12 workers, 30 s session timeout, default direction policy
  (initiator only). 12 is the default without `--config`: one worker per
  logical CPU (`config/pipeline.yaml`'s `workers: 8` applies only when that
  file is passed). An earlier version of this doc said 8, which was wrong.
- `bench/bench.py <exe> <empty-manifest-dir> <out.json> name=capture.pcap ...`
  runs each capture in both modes, with all methods and with none (an empty
  manifest directory, i.e. Telltale alone). Small captures take the fastest of
  3 runs; the others are a single run.
- **Wall time per packet** = the whole run's wall-clock time / packets read.
- **Method time per packet** = the time spent inside that method's `extract`
  (`--timings`) / every packet read, whether or not the method ran on it. This
  is CPU time summed over the 12 workers, so method times do not add up to the
  wall time.

| capture | file (under `D:\Documents\new-method\data\test`) | packets | sessions |
|---|---|---|---|
| honeypot | `honeypot\pcap\http-hp-20260928-23.pcap` | 28,772 | 1,225 |
| debian12 | `lab\raw\debian12-a\capture.pcap` | 330,048 | 6,122 |
| macos15 | `lab\raw\macos15-a\capture.pcap` | 1,113,093 | 9,918 |

Versions measured:

| label | commit | change |
|---|---|---|
| baseline | 9ff3720 | before any change here |
| step 1 | dde10d3 | observations shared between snapshots |
| step 3 | 61b4a3a | a method that returned `Complete` is not invoked again |

Every binary also held the then-uncommitted working tree: the tcpcluster
method, and the `PcapFileSource` snaplen fix that lets the lab captures be read
at all. Those are the same in all three.

## Results: wall time per packet (µs)

| capture | methods | per-session | inference, baseline | inference, step 1 | inference, step 3 |
|---|---|---|---|---|---|
| honeypot | none | 1.6 | 1,248 | 37.4 | 38.0 |
| honeypot | all | 5.4 | 1,394 | 67.9 | 66.2 |
| debian12 | none | 1.6 | 254 | 22.3 | 22.4 |
| debian12 | all | 2.1 | 311 | 34.4 | 33.3 |
| macos15 | none | 0.9 | 1,054 | 76.7 | 77.8 |
| macos15 | all | 1.0 | not measured | 115.5 | 115.8 |

Per-session mode is the same in all three versions (within ±0.1 µs). The
baseline macos15 run with all methods was stopped before it finished.

## Results: method time per packet (µs)

**Per-session mode** (step 3; the same in every version). In brackets: µs per
run, where one run is one session.

| method | honeypot | debian12 | macos15 |
|---|---|---|---|
| f0p | 0.44 (10.4) | 0.18 (9.7) | 0.08 (8.5) |
| ja4t | 0.12 (2.7) | 0.08 (4.3) | 0.03 (3.6) |
| ja4h | 0.09 (2.1) | 0.03 (1.7) | 0.02 (2.3) |
| claimed | 0.06 (1.4) | 0.03 (1.8) | 0.02 (2.4) |
| tcpcluster | 3.52 (82.7) | 0.11 (5.9) | 0.07 (8.4) |

tcpcluster's per-run cost on the honeypot is the encoder: most honeypot tuples
miss the fingerprint table, while lab tuples hit it.

**Inference mode**, baseline → step 1 → step 3:

| method | honeypot | debian12 | macos15 (step 1 → step 3) |
|---|---|---|---|
| f0p | 39.9 → 14.7 → 15.1 | 45.0 → 49.7 → 40.9 | 46.3 → 44.0 |
| ja4t | 30.9 → 13.8 → 13.5 | 3.9 → 5.0 → 0.1 | 25.0 → 18.9 |
| ja4h | 108.6 → 71.7 → 73.5 | 32.9 → 37.8 → 30.4 | 96.3 → 89.2 |
| claimed | 97.9 → 86.5 → 90.1 | 30.5 → 48.3 → 39.0 | 128.0 → 118.0 |
| tcpcluster | 49.7 → 47.6 → 22.0 | 5.2 → 6.9 → 0.4 | 26.6 → 19.1 |

Runs (calls to `extract`), step 1 → step 3:

| method | honeypot | debian12 | macos15 |
|---|---|---|---|
| f0p | 29,997 → 29,997 | 336,170 → 336,170 | 1,123,011 → 1,123,011 |
| ja4t | 29,997 → 21,142 | 336,170 → 10,407 | 1,123,011 → 146,720 |
| ja4h | 27,494 → 27,476 | 304,312 → 304,312 | 1,090,637 → 1,090,637 |
| claimed | 27,494 → 27,456 | 304,312 → 304,273 | 1,090,637 → 1,085,209 |
| tcpcluster | 29,997 → 22,799 | 336,170 → 25,817 | 1,123,011 → 166,554 |

Runs exceed packets slightly because the final pass of each session is a run
too.

## Findings

1. **In inference mode the tool, not the methods, was the cost.** With no
   methods loaded, the baseline took 1,248 µs per packet on the honeypot,
   against 1.6 µs per-session. Each packet cloned the whole session to hand a
   snapshot to a worker, and the clone deep-copied every observation (payload,
   TCP option list, quirk set). A session of n packets was copied n times:
   O(n²) in session length, hence macos15 (long sessions) at 1,054 µs.
2. **Step 1, share instead of copy (dde10d3): 10–30× faster.** Observations
   never change once pushed, so they are held behind an `Arc` and a snapshot
   copies one pointer per observation. Per packet: honeypot 1,394 → 68 µs,
   debian12 311 → 34 µs, macos15 (no methods) 1,054 → 77 µs. Answers
   unchanged.
3. **Step 3, honour `Complete` (61b4a3a): fewer runs, same wall time.**
   `Outcome::Complete` was documented as "do not invoke again", but the
   registry re-ran every method on every packet. Completed methods are now
   skipped, with their evidence still handed to later methods in the pass, so
   fusion sees it. ja4t and tcpcluster runs fell 85–97% on the lab captures.
   Final answers are unchanged, and the evidence stream shrank 43–55%. Wall time
   per packet barely moved, for two reasons:
   - **The per-packet snapshot is now the largest single cost.** It's the
     "none" rows: 22–78 µs, still growing with session length, because a
     snapshot copies one pointer per observation. On macos15 the methods add
     ~38 µs per packet of wall time on top of the tool's 78 µs.
   - **f0p, ja4h and claimed never return `Complete` on most sessions.** f0p
     stays `Partial` until the session ends, in case an HTTP request comes.
     ja4h and claimed return `NoMatch` on every packet of a session that isn't
     HTTP (for example TLS), because they can't tell "not yet" from "never".
4. **Methods are cheap when run once.** In per-session mode all five together
   cost 1–5 µs per packet; f0p ~9 µs and tcpcluster 6–83 µs per session.

## Rejected: fire `stage-reached` methods once

`stage-reached` currently behaves like `every-observation`: once the stage is
reached, the method runs on every later packet. Firing it only once, when the
stage is first reached, would lose answers:

- `Session::push` advances the stage on packets from either side, so a server
  banner (SSH, SMTP) reaches `app-data` before the client has sent anything.
- A request split across two TCP segments gives `NoMatch` on the first.

The method, not the framework, knows when it is done. Honouring `Complete`
(step 3) covers the same ground without that risk.

## Remaining options (not implemented)

- **A fixed-cost snapshot.** Hand the worker a shared pointer to an
  append-only observation list plus a length ("the first n"), so a snapshot
  costs the same at any session length. This targets the 22–78 µs that is now
  the floor.
- **Methods that recognise "never".** For example, ja4h, claimed and f0p's HTTP
  part could return `Complete` once the client's first payload has been seen
  and isn't HTTP. This is a change inside each method, keeping the decision
  with the method.
- **Per-method declared needs instead of a global cap.** Each manifest states
  what it reads (handshake packets only, payload up to the first request,
  payload until SSH KEXINIT for HASSH), and the assembler keeps the union of
  what the enabled methods need. A blanket payload drop would break payload
  methods (HTTP, HASSH).
- **Sessions owned by workers.** Route each packet to the worker that owns its
  session, so the session lives in one place and a packet is moved once. This
  gives constant cost per packet without shared snapshots, but moves session
  assembly and timeouts into the workers: a larger refactor.

## Caveats

- One machine. Large captures were run once, small ones best of 3; no variance
  is reported.
- Method time is CPU time across 12 workers. Inference-mode wall time is bounded
  by the main thread (snapshots), so method speed-ups show up in the method
  columns, not in the wall time.
- The JSON profile is keyed by client IP:port, so two connections from the
  same endpoint race. One honeypot endpoint (`45.33.14.5:52942`) gets f0p
  distance 19 or 20 depending on the run, in every version. Old and new
  binaries are otherwise identical on the honeypot and debian12.
