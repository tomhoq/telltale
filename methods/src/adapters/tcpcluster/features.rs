//! The connection record and its features, ported from the thesis code
//! (`scripts/train_encoder.py`: `featurize`, `ttl_bucket`, `ipid_change`;
//! `scripts/export_telltale.py`: `raw_key`). Anything changed here must change
//! there too: the test vectors in `db/tcpcluster/test_vectors.jsonl` pin both.
//!
//! [`Record`] mirrors the extractor's JSON record (`extract_connections.py`)
//! field for field, `None` where the JSON has `null`, so the test vectors
//! deserialize straight into it.

use serde::Deserialize;

pub const OPT_VOCAB: [&str; 12] = [
    "PAD", "EMPTY", "MSS", "NOP", "WS", "SOK", "TS", "EOL", "SACK", "TFO", "MPTCP", "OTHER",
];
pub const MAX_OPTS: usize = 12;
const TTL_BUCKETS: [i64; 4] = [32, 64, 128, 255];
const HS_OUTCOMES: [&str; 3] = ["ACK", "RST", "NONE"];
const SHIFT_ABSENT: i64 = 15;
const TTL_MISSING: usize = 4;
const HS_MISSING: usize = 3;
const IPID_MISSING: usize = 4;
pub const N_NUM: usize = 22;
pub const N_CAT: usize = 4;

/// The client's SYN, as the extractor records it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Syn {
    /// Option tokens in wire order, EOL excluded (`NOP`, `MSS`, ..., `OTHER`).
    pub options: Option<Vec<String>>,
    pub window: Option<u64>,
    pub mss: Option<u64>,
    /// The shift as sent, unclipped.
    pub wscale: Option<i64>,
    pub df: Option<bool>,
    pub ipid: Option<i64>,
    pub ece: Option<bool>,
    pub cwr: Option<bool>,
    pub ts_val: Option<u64>,
    pub ts_ecr: Option<u64>,
    pub urg_ptr_no_flag: Option<bool>,
    pub ack_nonzero: Option<bool>,
    pub reserved_bits: Option<bool>,
    pub payload_len: Option<u64>,
    pub eol_pad: Option<u64>,
    pub isn_eq_dst: Option<bool>,
    pub ttl: Option<i64>,
}

/// The client's reply to the SYN-ACK. `None` on the record when the server
/// never sent one (closed port, or a capture that missed it).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Handshake {
    /// `ACK`, `RST` or `NONE` (the server answered, the client never did).
    pub outcome: Option<String>,
    /// The ACK's window in bytes: shifted by the client's scale only when
    /// both sides sent the option.
    pub ack_window_bytes: Option<u64>,
    pub ack_ttl: Option<i64>,
    pub ack_ipid: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Record {
    pub syn: Syn,
    #[serde(default)]
    pub hs: Option<Handshake>,
}

/// What the encoder takes.
#[derive(Debug, Clone, PartialEq)]
pub struct Features {
    pub opt_ids: [usize; MAX_OPTS],
    pub opt_len: usize,
    pub cats: [usize; N_CAT],
    pub nums: [f32; N_NUM],
}

fn flag(b: Option<bool>) -> bool {
    b.unwrap_or(false)
}

/// Python's truthiness of an optional integer (`if mss:`): absent and zero
/// are both false.
fn present(x: Option<u64>) -> Option<u64> {
    x.filter(|&v| v != 0)
}

pub fn ttl_bucket(ttl: Option<i64>) -> usize {
    let Some(ttl) = ttl else {
        return TTL_MISSING;
    };
    TTL_BUCKETS
        .iter()
        .position(|&b| ttl <= b)
        .unwrap_or(TTL_BUCKETS.len() - 1)
}

pub fn ipid_change(syn_ipid: Option<i64>, ack_ipid: Option<i64>) -> usize {
    let (Some(s), Some(a)) = (syn_ipid, ack_ipid) else {
        return IPID_MISSING;
    };
    match (a - s).rem_euclid(65536) {
        0 => 0,
        1 => 1,
        d if d <= 1024 => 2,
        _ => 3,
    }
}

/// Featurizer tokens: anything outside the vocabulary (or `PAD`/`EMPTY` sent
/// as a token) is `OTHER`, at most [`MAX_OPTS`], `EMPTY` when there are none.
fn tokens(syn: &Syn) -> Vec<&str> {
    let mut toks: Vec<&str> = syn
        .options
        .iter()
        .flatten()
        .map(|t| match t.as_str() {
            "PAD" | "EMPTY" => "OTHER",
            t if OPT_VOCAB.contains(&t) => t,
            _ => "OTHER",
        })
        .take(MAX_OPTS)
        .collect();
    if toks.is_empty() {
        toks.push("EMPTY");
    }
    toks
}

fn wscale_cat(ws: Option<i64>) -> i64 {
    ws.map_or(SHIFT_ABSENT, |w| w.clamp(0, 14))
}

fn hs_outcome(hs: &Handshake) -> usize {
    hs.outcome
        .as_deref()
        .and_then(|o| HS_OUTCOMES.iter().position(|&h| h == o))
        .unwrap_or(HS_MISSING)
}

fn syn_bits(syn: &Syn) -> [bool; 11] {
    [
        flag(syn.df),
        syn.ipid == Some(0),
        flag(syn.ece) && flag(syn.cwr),
        syn.ts_val == Some(0),
        syn.ts_ecr.is_some_and(|v| v != 0),
        flag(syn.urg_ptr_no_flag),
        flag(syn.ack_nonzero),
        flag(syn.reserved_bits),
        syn.payload_len.unwrap_or(0) > 0,
        flag(syn.isn_eq_dst),
        syn.ipid == Some(54321),
    ]
}

/// The integer inputs of the features, before any maths, `|`-separated; `-`
/// is absent. Exact, so it is the fingerprint-set key:
/// `options | window | mss | wscale | 11 SYN bits | eol_pad | ttl bucket |
/// hs outcome | ack window bytes | ttl change | ipid change`.
pub fn raw_key(rec: &Record) -> String {
    let syn = &rec.syn;
    let mut f: Vec<String> = vec![
        tokens(syn).join(","),
        syn.window.unwrap_or(0).to_string(),
        present(syn.mss).map_or("-".into(), |m| m.to_string()),
        wscale_cat(syn.wscale).to_string(),
        syn_bits(syn).iter().map(|&b| if b { '1' } else { '0' }).collect(),
        syn.eol_pad.unwrap_or(0).min(8).to_string(),
        ttl_bucket(syn.ttl).to_string(),
    ];
    match &rec.hs {
        Some(hs) => {
            let outcome = hs_outcome(hs);
            f.push(outcome.to_string());
            f.push(match hs.ack_window_bytes {
                Some(ab) if hs.outcome.as_deref() == Some("ACK") => ab.to_string(),
                _ => "-".into(),
            });
            f.push(match (hs.ack_ttl, syn.ttl) {
                (Some(at), Some(st)) => (at - st).clamp(-8, 8).to_string(),
                _ => "-".into(),
            });
            f.push(ipid_change(syn.ipid, hs.ack_ipid).to_string());
        }
        None => {
            f.push(HS_MISSING.to_string());
            f.push("-".into());
            f.push("-".into());
            f.push(IPID_MISSING.to_string());
        }
    }
    f.join("|")
}

/// `featurize(rec, use_a2=True, use_b=True)`. Computed in f64 as Python does,
/// then narrowed to the f32 the model runs in.
pub fn featurize(rec: &Record) -> Features {
    let syn = &rec.syn;
    let toks = tokens(syn);
    let mut opt_ids = [0usize; MAX_OPTS];
    for (slot, t) in opt_ids.iter_mut().zip(&toks) {
        *slot = OPT_VOCAB.iter().position(|v| v == t).expect("tokens are in the vocabulary");
    }

    let mut nums = [0f64; N_NUM];
    let mut cats = [0usize; N_CAT];

    // A1
    let win = syn.window.unwrap_or(0) as f64;
    nums[0] = win / 65535.0;
    match present(syn.mss) {
        Some(mss) => {
            let mss = mss as f64;
            nums[1] = (1.0 + win / mss).log2() / 7.0;
            nums[2] = mss.ln() / 65535f64.ln();
        }
        None => nums[3] = 1.0,
    }
    cats[0] = wscale_cat(syn.wscale) as usize;

    // A2: df .. ipid_54321 are nums[4..16], with eol_pad scaled in the middle.
    let bits = syn_bits(syn);
    let b = |i: usize| bits[i] as u8 as f64;
    nums[4] = b(0); // df
    nums[5] = b(1); // ipid_zero
    nums[6] = b(2); // ecn_setup
    nums[7] = b(3); // ts_val_zero
    nums[8] = b(4); // ts_ecr_nonzero
    nums[9] = b(5); // urg_ptr_no_flag
    nums[10] = b(6); // ack_nonzero
    nums[11] = b(7); // reserved_bits
    nums[12] = b(8); // payload_in_syn
    nums[13] = syn.eol_pad.unwrap_or(0).min(8) as f64 / 8.0;
    nums[14] = b(9); // isn_eq_dst
    nums[15] = b(10); // ipid_54321
    nums[20] = 1.0; // present_a2
    cats[1] = ttl_bucket(syn.ttl);

    // B
    match &rec.hs {
        Some(hs) => {
            cats[2] = hs_outcome(hs);
            match hs.ack_window_bytes {
                Some(ab) if hs.outcome.as_deref() == Some("ACK") => {
                    nums[16] = (1.0 + ab as f64).log2() / 30.0;
                    if win > 0.0 {
                        let r = (ab.max(1) as f64 / win).log2();
                        nums[17] = r.clamp(-4.0, 8.0) / 8.0;
                    }
                }
                _ => nums[19] = 1.0, // ack_win_absent
            }
            if let (Some(at), Some(st)) = (hs.ack_ttl, syn.ttl) {
                nums[18] = (at - st).clamp(-8, 8) as f64 / 8.0;
            }
            cats[3] = ipid_change(syn.ipid, hs.ack_ipid);
            nums[21] = 1.0; // present_b
        }
        None => {
            cats[2] = HS_MISSING;
            cats[3] = IPID_MISSING;
        }
    }

    Features {
        opt_ids,
        opt_len: toks.len(),
        cats,
        nums: nums.map(|x| x as f32),
    }
}
