# telltale-pf

Passive network fingerprinting framework aimed at **accurate identification of intruder characteristics** (operating system, client software, TLS/transport stack), with automated scanner detection as an additional capability.

Traffic comes in from any source, is correlated into sessions, and is handed to an extensible
set of fingerprinting methods declared in YAML. A fusion method combines multi-layer
observations into a cohesive profile and verdict.

```
source ──▶ Assembler ──▶ Dispatcher ──▶ Registry ──▶ ProfileStore ──▶ output
(live/pcap/   (5-tuple +   (worker pool,   (methods, by
 tcpdump/      timeout)     1 job =         priority)
 honeypot)                  1 session)
```

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

1. `methods/manifests/<name>.yaml` — required stage, trigger, priority, database,
   output schema, params;
2. an adapter in `methods/src/adapters/` implementing `pf_core::Method`;
3. one line in `pf_methods::registry::builtin_adapters`.

Re-tuning an existing method is step 1 alone. `cargo test -p pf-methods` checks
every shipped manifest still pairs with an adapter.

A new **source**: implement `pf_capture::Source` under `capture/src/sources/` and
add a CLI subcommand.

## Key rules

- **Methods are pure and idempotent** over the session-so-far. That is what lets
  them run in parallel, and what makes both output modes work against the same
  adapters.
- **Each method owns its database.** No shared signature table.
- **The timeout always wins.** A method waiting on a stage that never arrives
  reports partial or no result; it never holds a session open.
- **A method failure is logged, not fatal.** One broken method must not sink the
  session.

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
```

## Still to decide

`config/pipeline.yaml`'s `output:` — `per-session` (batch: assemble, then score)
vs `inference-time` (streaming: guess early, refine). The scaffold supports both;
if batch wins, `Outcome::Partial` and the re-dispatch loop can be deleted.
