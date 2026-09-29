//! JA4T: FoxIO's TCP client fingerprint, from the SYN —
//! `window_options_mss_wscale`, e.g. `64240_2-1-3-1-1-4_1460_8`.
//!
//! - `window`: the raw window field, unscaled.
//! - `options`: option kinds in wire order, `-`-joined; every byte of
//!   padding after an EOL is another `0` (a Mac's `…-4-0-0` is `eol+1`).
//!   No options at all is `00`.
//! - `mss`, `wscale`: the option values, `00` when absent (a scale of 0 is
//!   `00` too).
//!
//! A strict subset of what `f0p` looks at — no TTL, no quirks, window kept as
//! a plain number — so it is steadier across hops but blinder to crafted
//! packets. Its value is a stable, shareable key, and the database's
//! scanner entries (masscan, ZMap, Nmap) are exactly the SYNs a honeypot
//! sees most.
//!
//! JA4TScan adds a fifth section, retransmission timings, which only an
//! active probe can measure; the lookup compares the first four (see
//! [`Ja4t::sections`]).
//!
//! JA4T licensing: FoxIO License 1.1 (see `methods/db/ja4.LICENSE`).

use std::path::Path;

use pf_core::{
    Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result, Stage, TcpFeatures,
    TcpOptionKind,
};

use super::ja4_common::{label_evidence, match_sections, Ja4tDb};
use crate::db;

fn option_kind(option: TcpOptionKind) -> u8 {
    match option {
        TcpOptionKind::Eol => 0,
        TcpOptionKind::Nop => 1,
        TcpOptionKind::Mss => 2,
        TcpOptionKind::WindowScale => 3,
        TcpOptionKind::SackPermitted => 4,
        TcpOptionKind::Sack => 5,
        TcpOptionKind::Timestamp => 8,
        TcpOptionKind::Other(kind) => kind,
    }
}

fn fingerprint(syn: &TcpFeatures) -> String {
    let mut kinds: Vec<String> = syn
        .option_order
        .iter()
        .map(|&option| option_kind(option).to_string())
        .collect();
    kinds.extend((0..syn.eol_padding.unwrap_or(0)).map(|_| "0".to_string()));
    let options = if kinds.is_empty() {
        "00".to_string()
    } else {
        kinds.join("-")
    };
    let mss = syn.mss.unwrap_or(0);
    let scale = match syn.window_scale.unwrap_or(0) {
        0 => "00".to_string(),
        scale => scale.to_string(),
    };
    format!("{}_{options}_{mss:02}_{scale}", syn.window)
}

pub struct Ja4t {
    manifest: MethodManifest,
    db: Ja4tDb,
    /// Sections the database lookup compares: the four of JA4T. A JA4TScan
    /// entry's fifth (retransmission timings) is never compared.
    sections: usize,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<Ja4tDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();
    let sections = match_sections(&manifest, 4);
    Ok(Box::new(Ja4t { manifest, db, sections }))
}

impl Method for Ja4t {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        // Only the SYN, as in `f0p`: a session first seen mid-stream has none
        // and gets no fingerprint rather than one taken from an ACK.
        let Some(syn) = ctx
            .observations()
            .filter(|o| o.stage_hint == Some(Stage::Connect))
            .find_map(|o| o.tcp.as_ref())
        else {
            return Ok(Outcome::NotApplicable);
        };
        let ja4t = fingerprint(syn);

        let subject = ctx.session.initiator;
        let matches = self.db.0.lookup(&ja4t, self.sections);
        let mut evidence = label_evidence(self.name(), subject, &matches);
        evidence.push(Evidence::new(self.name(), subject, "ja4t", ja4t, Confidence::Weak));
        Ok(Outcome::Complete(evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::ja4_common::{FingerprintDb, LabelKind};
    use TcpOptionKind::*;

    fn syn(window: u16, options: Vec<TcpOptionKind>, mss: Option<u16>, scale: Option<u8>) -> TcpFeatures {
        TcpFeatures {
            ttl: 64,
            ip_option_len: 0,
            quirks: Default::default(),
            window,
            mss,
            window_scale: scale,
            sack_permitted: options.contains(&SackPermitted),
            timestamp: options.contains(&Timestamp),
            option_order: options,
            eol_padding: None,
        }
    }

    fn shipped_db() -> FingerprintDb {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("db/ja4t_fingerprint.csv");
        FingerprintDb::parse(&std::fs::read_to_string(path).unwrap(), "ja4t_fingerprint").unwrap()
    }

    /// FoxIO's own format tests (`rust/ja4/src/tcp.rs`).
    #[test]
    fn matches_foxios_format() {
        assert_eq!(fingerprint(&syn(8192, vec![], None, None)), "8192_00_00_00");
        assert_eq!(
            fingerprint(&syn(5744, vec![Mss, SackPermitted, Timestamp, Nop, WindowScale], Some(1436), Some(0))),
            "5744_2-4-8-1-3_1436_00"
        );
        assert_eq!(fingerprint(&syn(8192, vec![Mss], Some(9), None)), "8192_2_09_00");
    }

    #[test]
    fn eol_padding_bytes_are_zeros() {
        let mut iphone = syn(
            65535,
            vec![Mss, Nop, WindowScale, Nop, Nop, Timestamp, SackPermitted, Eol],
            Some(1460),
            Some(6),
        );
        iphone.eol_padding = Some(1);
        assert_eq!(fingerprint(&iphone), "65535_2-1-3-1-1-8-4-0-0_1460_6");
        let found = shipped_db().lookup(&fingerprint(&iphone), 4);
        assert_eq!(found[0].kind, LabelKind::Os);
        assert_eq!(found[0].label(), "Mac OSX/iPhone");
    }

    #[test]
    fn masscan_and_nmap_are_labelled_from_the_shipped_database() {
        let db = shipped_db();
        assert_eq!(db.lookup(&fingerprint(&syn(1024, vec![], None, None)), 4)[0].label(), "masscan");
        assert_eq!(
            db.lookup(&fingerprint(&syn(1024, vec![Mss], Some(1460), None)), 4)[0].label(),
            "Nmap"
        );
    }

    #[test]
    fn a_ja4tscan_entry_matches_on_its_first_four_sections() {
        let db = FingerprintDb::parse(
            "application,library,device,os,ja4t_fingerprint\nSomeScanner,,,,1024_2_1460_00_1-2-4-8-R6\n",
            "ja4t_fingerprint",
        )
        .unwrap();
        assert_eq!(db.lookup("1024_2_1460_00", 4)[0].label(), "SomeScanner");
    }
}
