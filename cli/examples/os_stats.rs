//! Per-connection method output, for statistics: replays a pcap (a path, or
//! `-` for stdin, so a gzipped capture can be streamed through `gzip -dc`),
//! assembles sessions as the CLI does, runs every enabled method once on each
//! finished TCP session that starts with the client's SYN, and prints one TSV
//! row per piece of evidence:
//!
//! `session  client  server  method  key  value  confidence`
//!
//! plus one `#session` row per analysed session, so connections no method
//! said anything about are counted too.
//!
//! ```text
//! cargo run --release -p pf-cli --example os_stats -- methods/manifests capture.pcap > out.tsv
//! gzip -dc mawi.pcap.gz | cargo run --release -p pf-cli --example os_stats -- methods/manifests - > out.tsv
//! ```
//! A truncated capture (the tail of `head -c`) ends the replay where it breaks.

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::time::{Duration, SystemTime};

use pcap_file::pcap::PcapReader;
use pcap_file::DataLink;
use pf_capture::decode;
use pf_core::{Observation, Session, SessionKey, TcpHeader, Transport};
use pf_dispatch::{Assembler, Emitted};
use pf_methods::Registry;

fn decode_packet(datalink: DataLink, data: &[u8], at: SystemTime) -> Option<Observation> {
    match datalink {
        DataLink::ETHERNET => decode::ethernet_frame(data, at),
        DataLink::IPV4 | DataLink::IPV6 | DataLink::RAW => decode::ip_packet(data, at),
        DataLink::LINUX_SLL => data.get(16..).and_then(|d| decode::ip_packet(d, at)),
        DataLink::LINUX_SLL2 => data.get(20..).and_then(|d| decode::ip_packet(d, at)),
        _ => decode::ethernet_frame(data, at).or_else(|| decode::ip_packet(data, at)),
    }
}

fn starts_with_syn(s: &Session) -> bool {
    s.key.transport == Transport::Tcp
        && s.observations.first().is_some_and(|o| {
            o.tcp
                .as_ref()
                .is_some_and(|t| t.header.has(TcpHeader::SYN) && !t.header.has(TcpHeader::ACK))
        })
}

fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(manifests), Some(path)) = (args.next(), args.next()) else {
        eprintln!("usage: os_stats <manifest-dir> <capture.pcap | ->");
        std::process::exit(2);
    };
    let registry = Registry::load_dir(&manifests)?;
    let input: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin().lock())
    } else {
        Box::new(std::fs::File::open(&path)?)
    };
    let mut reader = PcapReader::new(BufReader::with_capacity(1 << 20, input))?;
    let datalink = reader.header().datalink;
    let mut out = BufWriter::new(io::stdout().lock());
    let mut assembler = Assembler::new(Duration::from_secs(30));
    let mut packets = 0u64;
    let sessions = std::cell::Cell::new(0u64);

    // Only the OS answers are written, and a session is kept to its first
    // packets: the methods read the handshake and the first request, and a
    // long flow's every packet would otherwise sit in memory until it ends.
    const KEYS: [&str; 10] = [
        "os",
        "versions",
        "hint",
        "stack",
        "client",
        "products",
        "os-ambiguous",
        "os-inconsistent",
        "client-ambiguous",
        "client-inconsistent",
    ];
    const MAX_PACKETS: u32 = 64;
    let mut seen: std::collections::HashMap<SessionKey, u32> = Default::default();

    let analyse = |s: Session, out: &mut dyn Write| -> io::Result<()> {
        if !starts_with_syn(&s) {
            return Ok(());
        }
        sessions.set(sessions.get() + 1);
        let sessions = sessions.get();
        let (c, d) = (s.initiator, if s.key.low == s.initiator { s.key.high } else { s.key.low });
        let (c, d) = (format!("{}:{}", c.addr, c.port), format!("{}:{}", d.addr, d.port));
        writeln!(out, "{sessions}\t{c}\t{d}\t#session\t\t\t")?;
        for e in registry.analyze(&s, true, false).into_iter().filter(|e| KEYS.contains(&e.key.as_str())) {
            writeln!(
                out,
                "{sessions}\t{c}\t{d}\t{}\t{}\t{}\t{:?}",
                e.method,
                e.key,
                clean(&e.value),
                e.confidence
            )?;
        }
        Ok(())
    };

    // Raw packets: pcap-file's `next_packet` rejects any packet longer on the
    // wire than the snaplen, i.e. every truncated packet of a snaplen-limited
    // capture (MAWI's 96 bytes).
    let nanos = reader.header().ts_resolution == pcap_file::TsResolution::NanoSecond;
    loop {
        let packet = match reader.next_raw_packet() {
            None => break,
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                eprintln!("stopping at packet {packets}: {e}");
                break;
            }
        };
        packets += 1;
        let frac = if nanos { packet.ts_frac } else { packet.ts_frac.saturating_mul(1000) };
        let at = SystemTime::UNIX_EPOCH + Duration::new(packet.ts_sec.into(), frac.min(999_999_999));
        let Some(obs) = decode_packet(datalink, &packet.data, at) else { continue };
        let n = seen.entry(SessionKey::new(obs.source, obs.destination, obs.transport)).or_default();
        *n += 1;
        if *n > MAX_PACKETS {
            continue;
        }
        if let Emitted::Finished(s) = assembler.ingest(obs) {
            seen.remove(&s.key);
            analyse(s, &mut out)?;
        }
        if packets % 4096 == 0 {
            for s in assembler.expire(at) {
                seen.remove(&s.key);
                analyse(s, &mut out)?;
            }
        }
        if packets % 10_000_000 == 0 {
            eprintln!("{packets} packets, {} sessions", sessions.get());
        }
    }
    for s in assembler.drain() {
        analyse(s, &mut out)?;
    }
    out.flush()?;
    eprintln!("done: {packets} packets, {} SYN-started TCP sessions", sessions.get());
    Ok(())
}
