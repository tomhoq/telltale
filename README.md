# telltale-pf

Passive network fingerprinting framework aimed at **accurate identification of intruder characteristics** (operating system, client software, TLS/transport stack), with automated scanner detection as an additional capability.

Traffic comes in from any source, is correlated into sessions, and is handed to an extensible
set of fingerprinting methods declared in YAML. A fusion method combines multi-layer
observations into a cohesive profile and verdict.

```
source ──▶ Assembler ──▶ classifier ──▶ worker pool ──▶ session results ──▶ output
(live/pcap/  (5-tuple +    (packet ->     (1 job = 1       (append-only;      (batch or
 tcpdump/     timeout)      tcp-syn,       method x 1       result stream)     inference
 honeypot)                  tls-client-    event)                              consumer)
                            hello, ...)
```

Each packet is classified into protocol events; every method whose manifest
lists that event runs once, with that packet. A method is never re-run on
packets it has already seen. When a session ends, `session-end` methods
(fusion) run once everything else has reported, reading the full result list.

## Layout

| Crate       | Package         | Role |
| ----------- | --------------- | ---- |
| `core/`     | `pf-core`       | Shared types, the `Method` trait, manifest schema. No I/O. |
| `capture/`  | `pf-capture`    | Source traits + live, pcap, tcpdump, honeypot-log implementations. |
| `dispatch/` | `pf-dispatch`   | Session correlation (Assembler) and worker pool dispatch engine. |
| `methods/`  | `pf-methods`    | Manifest-driven registry, adapters, and databases. |
| `output/`   | `pf-output`     | Batch and inference mode consumers, dashboard/CLI rendering. |
| `cli/`      | `telltale-pf` bin  | Binary entrypoint, CLI argument parsing, and pipeline wiring. |

Nothing depends on anything but `pf-core`, so a new source or method is an
additive change.

## Extending it

Configuration is YAML on purpose — new methods and different parameter
configurations should not need a recompile.

A new **method**:

1. `methods/manifests/<name>.yaml` — `layer`, `triggers` (the protocol events
   that fire it), `invocation` (in-process adapter, or external command),
   database, `output-schema` (`{field, type, kind}`, kind being one of
   `classification`, `flag`, `score`, `raw-signature`), params;
2. an adapter in `methods/src/adapters/` implementing `pf_core::Method`;
3. one line in `pf_methods::registry::builtin_adapters`.

A method needing an event nobody has used yet also needs it added to
`pf_core::TriggerEvent` and recognised in `pf_dispatch::classifier`.

Re-tuning an existing method is step 1 alone. `cargo test -p pf-methods` checks
every shipped manifest still pairs with an adapter.

A new **source**: implement `pf_capture::Source` under `capture/src/sources/` and
add a CLI subcommand.

## Key rules

- **Methods are pure.** That is what lets many run at once, including several
  off the same packet.
- **Results are append-only.** Nothing merges, replaces or deduplicates at
  storage; reconciling methods is a consumer's job (fusion, inference).
- **Each method owns its database.** No shared signature table.
- **The timeout always wins.** A quiet session ends with whatever results it
  has; nothing waits for traffic that never came.
- **A method failure is logged, not fatal.** One broken (or panicking) method
  must not sink the session.

## Prerequisites

### Windows
Building needs the **Npcap SDK**; live capture at runtime needs **Npcap** itself.

1. Download and extract the [Npcap SDK](https://npcap.com/#download), and point
   `NPCAP_SDK` at it (the directory containing `Lib` and `Include`). The build
   script picks the right `Lib` subdirectory for the target:
   ```powershell
   setx NPCAP_SDK "C:\path\to\npcap-sdk"
   ```
   Adding `<sdk>\Lib\x64` to `LIB` also works.
2. Install [Npcap](https://npcap.com/#download) to run `live`. WinPcap
   API-compatible mode is not needed.

`Packet.dll` is delay-loaded (MSVC toolchain), so the binary starts without
Npcap: `replay`, `honeypot` and `methods` work, and `live` checks for Npcap
first and points at the installer if it is missing. It loads `Packet.dll` from
`System32\Npcap` (or `System32` for WinPcap-compatible installs), never from
the current directory.

**Shipping it:** do the same as Wireshark and Nmap. Link users to the official
installer, or run it as a separate step in your own installer that the user
explicitly agrees to. Never unpack the driver files yourself. Check the
[Npcap license](https://npcap.com/oem/redist) before bundling the
installer: the free edition does not allow redistribution, so bundling it
needs Npcap OEM.

### Linux / macOS
Requires `libpcap` development headers:
```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# Fedora
sudo dnf install libpcap-devel

# macOS
brew install libpcap
```

## Try it

```bash
cargo run -p pf-cli -- --config config/pipeline.yaml methods
cargo run -p pf-cli -- --config config/pipeline.yaml replay -p capture/tests/fixtures/sample_syn_scan.pcap
```

## Output modes

`config/pipeline.yaml`'s `output:` picks the consumer, not the pipeline: both
read the same result stream. `per-session` (batch) prints each session once it
is finalized, with its full result list; `inference-time` prints each result
the moment a method reports it. Still to come for inference: a watcher that
emits a verdict early and revises it when later results contradict it.
