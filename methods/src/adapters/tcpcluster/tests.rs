use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::SystemTime;

use pf_core::{Endpoint, Observation, Session, Stage};
use serde::Deserialize;

use super::*;

fn shipped() -> TcpCluster {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
    let manifest = MethodManifest::from_yaml(&std::fs::read_to_string(dir.join("tcpcluster.yaml")).unwrap()).unwrap();
    let spec = manifest.database.clone().unwrap();
    TcpCluster {
        model: Model::load(&dir.join(spec.path)).expect("the shipped export should load"),
        params: Params::from(&manifest),
        manifest,
    }
}

#[derive(Deserialize)]
struct Vector {
    #[serde(flatten)]
    record: Record,
    raw_key: String,
    known: bool,
    opt_ids: Vec<usize>,
    opt_len: usize,
    cats: Vec<usize>,
    nums: Vec<f32>,
    embedding: Vec<f32>,
    cluster: i32,
    anchor: i32,
    family: String,
    versions: String,
}

/// The 400 cases `export_telltale.py` wrote (half known tuples, half
/// augmented unseen ones): raw key exact, model inputs and embedding to
/// float tolerance, and the same cluster, anchor and name from the search.
#[test]
fn matches_the_exported_test_vectors() {
    let method = shipped();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("db/tcpcluster/test_vectors.jsonl");
    let text = std::fs::read_to_string(path).unwrap();
    let (mut n, mut worst_emb, mut table_differs) = (0, 0f32, 0);
    for (i, line) in text.lines().enumerate() {
        let v: Vector = serde_json::from_str(line).unwrap_or_else(|e| panic!("vector {i}: {e}"));
        n += 1;

        assert_eq!(raw_key(&v.record), v.raw_key, "vector {i}: raw key");
        assert_eq!(method.model().fingerprints.contains_key(&v.raw_key), v.known, "vector {i}: known");

        let f = featurize(&v.record);
        assert_eq!(f.opt_ids.to_vec(), v.opt_ids, "vector {i}: opt_ids");
        assert_eq!(f.opt_len, v.opt_len, "vector {i}: opt_len");
        assert_eq!(f.cats.to_vec(), v.cats, "vector {i}: cats");
        for (j, (a, b)) in f.nums.iter().zip(&v.nums).enumerate() {
            assert!((a - b).abs() <= 1e-6, "vector {i}: nums[{j}] {a} vs {b}");
        }

        let e = method.model().encoder.embed(&f);
        let d = e.iter().zip(&v.embedding).map(|(a, b)| (a - b).abs()).fold(0f32, f32::max);
        worst_emb = worst_emb.max(d);
        assert!(d <= 1e-5, "vector {i}: embedding off by {d}");

        let found = method.model().classify(&e);
        let (cluster, anchor) = match found.map(|(h, _)| h) {
            Some(Hit::Cluster(c)) => (c, -1),
            Some(Hit::Anchor(a)) => (-1, a),
            None => (-1, -1),
        };
        assert_eq!((cluster, anchor), (v.cluster, v.anchor), "vector {i}: cluster, anchor");
        let name = found.map(|(_, n)| n);
        assert_eq!(name.map_or("-", |n| n.family.as_str()), v.family, "vector {i}: family");
        let versions = name.map(|n| n.versions.as_deref().unwrap_or("unnamed"));
        assert_eq!(versions.unwrap_or("-"), v.versions, "vector {i}: versions");

        // A known tuple is answered from the table, which the export filled
        // from the full assignment rather than this search; count, not fail.
        let a = method.answer(&v.record);
        if v.known && a.name.as_ref().map(|n| n.family.as_str()).unwrap_or("-") != v.family {
            table_differs += 1;
        }

    }
    assert_eq!(n, 400);
    assert_eq!(table_differs, 0);
}

// ---------------------------------------------------------------- from a session

const CLIENT: Endpoint = Endpoint {
    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
    port: 50000,
};
const SERVER: Endpoint = Endpoint {
    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
    port: 80,
};

fn segment(from_client: bool, flags: u8, seq: u32, ack: u32, window: u16, options: Vec<TcpOptionKind>) -> Observation {
    let (source, destination) = if from_client { (CLIENT, SERVER) } else { (SERVER, CLIENT) };
    let syn = flags & TcpHeader::SYN != 0;
    Observation {
        at: SystemTime::UNIX_EPOCH,
        source,
        destination,
        transport: Transport::Tcp,
        payload: Vec::new(),
        stage_hint: Some(if syn && flags & TcpHeader::ACK == 0 { Stage::Connect } else { Stage::Established }),
        tcp: Some(TcpFeatures {
            ttl: if from_client { 54 } else { 64 },
            ip_option_len: 0,
            quirks: [TcpQuirk::Df, TcpQuirk::NonZeroId].into(),
            window,
            mss: options.contains(&TcpOptionKind::Mss).then_some(1390),
            window_scale: options.contains(&TcpOptionKind::WindowScale).then_some(2),
            sack_permitted: options.contains(&TcpOptionKind::SackPermitted),
            timestamp: false,
            option_order: options,
            eol_padding: None,
            options_truncated: false,
            header: TcpHeader {
                flags,
                reserved: 0,
                seq,
                ack,
                ip_id: Some(if from_client { 15687 + (seq != 1000) as u16 } else { 0 }),
                timestamps: None,
            },
        }),
    }
}

fn windows_syn() -> Vec<TcpOptionKind> {
    use TcpOptionKind::*;
    vec![Mss, Nop, WindowScale, Nop, Nop, SackPermitted]
}

/// The first test vector's SYN (`MSS,NOP,WS,NOP,NOP,SOK|8192|1390|2|...`),
/// built as observations, followed by a SYN-ACK and the client's ACK.
fn handshake() -> Session {
    use TcpOptionKind::*;
    let mut s = Session::open(segment(true, TcpHeader::SYN, 1000, 0, 8192, windows_syn()));
    s.push(segment(false, TcpHeader::SYN | TcpHeader::ACK, 77, 1001, 65535, vec![Mss, WindowScale]));
    s.push(segment(true, TcpHeader::ACK, 1001, 78, 16425, vec![]));
    s
}

fn record(session: &Session, both_directions: bool, is_final: bool) -> Option<Record> {
    connection(&Context::new(session, &[], is_final, both_directions), true)
}

const WINDOWS_SYN_KEY: &str = "MSS,NOP,WS,NOP,NOP,SOK|8192|1390|2|10000000000|0|1";

#[test]
fn waits_for_the_reply_to_the_syn_ack() {
    let s = Session::open(segment(true, TcpHeader::SYN, 1000, 0, 8192, windows_syn()));
    assert!(record(&s, false, false).is_none());
    // Never answered: no handshake info, as the extractor.
    assert_eq!(raw_key(&record(&s, false, true).unwrap()), format!("{WINDOWS_SYN_KEY}|3|-|-|4"));
}

/// The client's ACK is read without the SYN-ACK: window 16425 << 2 (the
/// client offered scaling), same TTL, IP ID + 1.
#[test]
fn reads_the_reply_without_the_syn_ack() {
    let expected = format!("{WINDOWS_SYN_KEY}|0|65700|0|1");
    assert_eq!(raw_key(&record(&handshake(), false, false).unwrap()), expected);
    assert_eq!(raw_key(&record(&handshake(), true, false).unwrap()), expected);
}

/// In view, the SYN-ACK decides scaling: a server that sent no WS leaves
/// the ACK's window as it is.
#[test]
fn a_syn_ack_in_view_decides_window_scaling() {
    use TcpOptionKind::*;
    let mut s = Session::open(segment(true, TcpHeader::SYN, 1000, 0, 8192, windows_syn()));
    s.push(segment(false, TcpHeader::SYN | TcpHeader::ACK, 77, 1001, 65535, vec![Mss]));
    s.push(segment(true, TcpHeader::ACK, 1001, 78, 16425, vec![]));
    assert_eq!(raw_key(&record(&s, true, false).unwrap()), format!("{WINDOWS_SYN_KEY}|0|16425|0|1"));
    assert_eq!(raw_key(&record(&s, false, false).unwrap()), format!("{WINDOWS_SYN_KEY}|0|65700|0|1"));

    // Answered, then the client went silent: NONE only if the SYN-ACK was seen.
    let mut s = Session::open(segment(true, TcpHeader::SYN, 1000, 0, 8192, windows_syn()));
    s.push(segment(false, TcpHeader::SYN | TcpHeader::ACK, 77, 1001, 65535, vec![Mss]));
    assert_eq!(raw_key(&record(&s, true, true).unwrap()), format!("{WINDOWS_SYN_KEY}|2|-|-|4"));
    assert_eq!(raw_key(&record(&s, false, true).unwrap()), format!("{WINDOWS_SYN_KEY}|3|-|-|4"));
}

#[test]
fn emits_only_os_keys() {
    let method = shipped();
    let out = method.extract(&Context::new(&handshake(), &[], false, false)).unwrap();
    for e in out.evidence() {
        assert!(["os", "versions", "hint", "hint-distance"].contains(&e.key.as_str()), "{e:?}");
        assert!(method.manifest().output.declares(&e.key));
    }
}

/// The extractor tokenizes an unreadable option as OTHER and drops EOL.
#[test]
fn option_tokens_follow_the_extractor() {
    use TcpOptionKind::*;
    let mut t = segment(true, TcpHeader::SYN, 1, 0, 1, vec![Mss, Other(34), Other(30), Timestamp, Eol]).tcp.unwrap();
    assert_eq!(option_tokens(&t), ["MSS", "TFO", "MPTCP", "TS"]);
    t.option_order = vec![Mss, Sack];
    t.options_truncated = true;
    assert_eq!(option_tokens(&t), ["MSS", "OTHER"]);
}
