use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use pf_core::{Endpoint, Observation, Session, Transport};

use super::*;

const CLIENT: Endpoint = Endpoint {
    addr: IpAddr::V4(Ipv4Addr::new(154, 18, 197, 29)),
    port: 59358,
};

fn shipped() -> Fusion {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
    let manifest = MethodManifest::from_yaml(&std::fs::read_to_string(dir.join("fusion.yaml")).unwrap()).unwrap();
    Fusion::new(manifest, &dir)
}

fn session() -> Session {
    let server = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
        port: 80,
    };
    Session::open(Observation {
        at: SystemTime::UNIX_EPOCH,
        source: CLIENT,
        destination: server,
        transport: Transport::Tcp,
        payload: Vec::new(),
        stage_hint: Some(Stage::Connect),
        tcp: None,
    })
}

fn claim(method: &str, key: &str, value: &str, confidence: Confidence) -> Evidence {
    Evidence::new(method, CLIENT, key, value, confidence)
}

/// Fusion's evidence as `key -> (value, confidence)`.
fn fuse(evidence: &[Evidence]) -> HashMap<String, (String, Confidence)> {
    let session = session();
    let out = shipped().extract(&Context::new(&session, evidence, true, false)).unwrap();
    out.evidence()
        .iter()
        .map(|e| (e.key.clone(), (e.value.clone(), e.confidence)))
        .collect()
}

fn value<'a>(fused: &'a HashMap<String, (String, Confidence)>, key: &str) -> Option<&'a str> {
    fused.get(key).map(|(v, _)| v.as_str())
}

use Confidence::{Likely, Strong, Weak};

/// The worked example in specs (Phase 5, "Fusion design"): three methods
/// agree on linux, two of them strongly; below it ja4t's Ubuntu and
/// tcpcluster's Debian split evenly (f0p's version counts 0), so both are
/// listed, as Weak.
#[test]
fn the_worked_example() {
    let fused = fuse(&[
        claim("ja4t", "os", "WSL Ubuntu 22.04", Strong),
        claim("tcpcluster", "os", "linux", Strong),
        claim("tcpcluster", "versions", "linux/debian12", Strong),
        claim("f0p", "os", "Linux 2.2.x-3.x", Likely),
    ]);
    assert_eq!(fused["os"], ("linux".into(), Strong));
    assert_eq!(fused["versions"], ("debian 12 | wsl ubuntu 22.04".into(), Weak));
    assert!(!fused.keys().any(|k| k.ends_with("ambiguous") || k.ends_with("inconsistent")), "{fused:?}");
    assert!(!fused.contains_key("verdict"), "no verdict until its scoring exists");
}

/// Mid-session (a live run) the answer is given at once, as Partial: more
/// traffic can still change it. At the session's end it is Complete.
#[test]
fn answers_mid_session_as_partial() {
    let session = session();
    let evidence = [claim("tcpcluster", "os", "linux", Strong)];
    let fusion = shipped();
    let live = fusion.extract(&Context::new(&session, &evidence, false, false)).unwrap();
    assert!(matches!(&live, Outcome::Partial(e) if e.iter().any(|e| e.key == "os")), "{live:?}");
    let end = fusion.extract(&Context::new(&session, &evidence, true, false)).unwrap();
    assert!(matches!(end, Outcome::Complete(_)));
    assert_eq!(fusion.manifest().invocation.trigger, pf_core::Trigger::EveryObservation);
}

/// A Windows User-Agent against a Linux TCP stack: claimed's weight is low,
/// so the answer stays linux, but the lie is flagged — inconsistency is
/// judged on confidence, not on how far fusion trusts the User-Agent.
#[test]
fn a_user_agent_lying_about_the_os_is_flagged_not_believed() {
    let fused = fuse(&[
        claim("ja4t", "os", "WSL Ubuntu 22.04", Strong),
        claim("tcpcluster", "os", "linux", Strong),
        claim("claimed", "os", "Windows 10", Weak),
    ]);
    assert_eq!(value(&fused, "os"), Some("linux"));
    assert_eq!(value(&fused, "os-inconsistent"), Some("linux (ja4t, tcpcluster) vs windows (claimed)"));
}

/// The User-Agent agreeing with the stack is not flagged.
#[test]
fn a_user_agent_agreeing_with_the_stack_is_not_flagged() {
    let fused = fuse(&[
        claim("tcpcluster", "os", "macos", Strong),
        claim("claimed", "os", "iOS 18.7", Weak),
    ]);
    assert_eq!(value(&fused, "os"), Some("macos"));
    assert!(!fused.keys().any(|k| k.starts_with("os-")), "{fused:?}");
}

/// A scanner sending a browser's User-Agent: no OS (both the SYN and the
/// User-Agent are the tool's), but the lie is still flagged.
#[test]
fn a_scanner_faking_a_browser_has_no_os_but_is_flagged() {
    let fused = fuse(&[
        claim("ja4t", "client", "masscan", Strong),
        claim("f0p", "os", "Linux 2.2.x-3.x (barebone)", Weak),
        claim("claimed", "os", "Windows 10", Weak),
    ]);
    assert_eq!(value(&fused, "client"), Some("scanner"));
    assert!(!fused.contains_key("os"), "{fused:?}");
    assert_eq!(value(&fused, "os-inconsistent"), Some("linux (f0p) vs windows (claimed)"));
}

/// A well-supported application-layer claim of another family: the
/// majority still answers, and the split between layers is flagged.
#[test]
fn transport_against_application_is_inconsistent() {
    let fused = fuse(&[
        claim("ja4t", "os", "WSL Ubuntu 22.04", Strong),
        claim("tcpcluster", "os", "linux", Strong),
        claim("f0p", "os", "Linux 2.2.x-3.x", Likely),
        claim("ja4h", "os", "Windows 10", Strong),
    ]);
    assert_eq!(value(&fused, "os"), Some("linux"));
    assert_eq!(
        value(&fused, "os-inconsistent"),
        Some("linux (ja4t, tcpcluster, f0p) vs windows (ja4h)")
    );
}

/// Two methods reading the same SYN disagree evenly: no answer, both
/// listed, flagged ambiguous, not inconsistent (same layer).
#[test]
fn an_even_split_within_a_layer_is_ambiguous() {
    let fused = fuse(&[
        claim("f0p", "os", "FreeBSD 9.x", Strong),
        claim("tcpcluster", "os", "windows", Likely),
    ]);
    assert_eq!(fused["os"], ("freebsd | windows".into(), Weak));
    assert_eq!(value(&fused, "os-ambiguous"), Some("freebsd (f0p) vs windows (tcpcluster)"));
    assert!(!fused.contains_key("os-inconsistent"));
}

/// ZMap: ja4t names it, tcpcluster's `os: scanner` is a client claim, and
/// the client being a scanner drops f0p's "Linux" (the tool's SYN).
#[test]
fn a_scanner_discounts_the_transport_os() {
    let fused = fuse(&[
        claim("ja4t", "client", "Modified ZMap", Strong),
        claim("tcpcluster", "os", "scanner", Strong),
        claim("tcpcluster", "versions", "scanner/zmap", Strong),
        claim("f0p", "os", "Linux 2.2.x-3.x (barebone)", Weak),
    ]);
    assert_eq!(fused["client"], ("scanner".into(), Strong));
    assert_eq!(fused["products"], ("modified zmap".into(), Strong));
    assert!(!fused.contains_key("os"), "the SYN is the tool's: {fused:?}");
}

/// tcpcluster's version set agrees with ja4t's single version on the
/// version they share.
#[test]
fn a_version_set_agrees_on_its_overlap() {
    let fused = fuse(&[
        claim("tcpcluster", "os", "windows", Strong),
        claim("tcpcluster", "versions", "windows/{10|8.1}", Strong),
        claim("ja4t", "os", "Windows 10", Strong),
    ]);
    assert_eq!(fused["os"], ("windows".into(), Strong));
    assert_eq!(fused["versions"], ("10".into(), Strong));
}

/// A set no one narrows is reported as the set.
#[test]
fn a_lone_version_set_stays_a_set() {
    let fused = fuse(&[
        claim("tcpcluster", "os", "windows", Strong),
        claim("tcpcluster", "versions", "windows/{10|8.1}", Strong),
    ]);
    assert_eq!(fused["versions"], ("10 | 8.1".into(), Likely));
}

/// A label made only of the family's name and synonyms names no version.
#[test]
fn a_label_of_only_family_synonyms_has_no_version() {
    let fused = fuse(&[
        claim("ja4t", "os", "Mac OSX/iPhone", Strong),
        claim("tcpcluster", "os", "macos", Strong),
        claim("tcpcluster", "versions", "macos/macos15", Strong),
    ]);
    assert_eq!(fused["os"], ("macos".into(), Strong));
    assert_eq!(fused["versions"], ("15".into(), Likely));
}

/// A keyword that tells the family can still be the version: tcpcluster's
/// `linux/android` is Android, its `macos/ios` iOS (they were dropped when
/// every family keyword counted as naming nothing).
#[test]
fn distribution_and_variant_names_are_versions() {
    let android = fuse(&[
        claim("f0p", "os", "Linux 2.2.x-3.x", Likely),
        claim("tcpcluster", "os", "linux", Strong),
        claim("tcpcluster", "versions", "linux/android", Strong),
    ]);
    assert_eq!(android["os"].0, "linux");
    assert_eq!(android["versions"], ("android".into(), Likely));

    let ios = fuse(&[
        claim("tcpcluster", "os", "macos", Strong),
        claim("tcpcluster", "versions", "macos/ios", Strong),
    ]);
    assert_eq!(value(&ios, "versions"), Some("ios"));

    // The User-Agent's `Android 6.0.1` agrees with, and refines, `android`.
    let refined = fuse(&[
        claim("tcpcluster", "os", "linux", Strong),
        claim("tcpcluster", "versions", "linux/android", Strong),
        claim("claimed", "os", "Android 6.0.1", Weak),
    ]);
    assert_eq!(value(&refined, "versions"), Some("android 6.0.1"));
}

/// Labels the tables do not know are kept, not dropped.
#[test]
fn an_unknown_label_is_kept() {
    let fused = fuse(&[claim("ja4t", "client", "Some New Tool", Strong)]);
    assert_eq!(value(&fused, "client"), Some("other:some new tool"));
}

/// Raw signatures, scores and flags are not claims.
#[test]
fn only_classifications_are_merged() {
    let mut raw = claim("ja4t", "os", "Windows 10", Strong);
    raw.kind = FieldKind::RawSignature;
    assert!(fuse(&[raw, claim("f0p", "distance", "25", Weak)]).is_empty());
}

#[test]
fn layers_come_from_the_manifests() {
    let fusion = shipped();
    for (method, layer) in [
        ("f0p", Layer::Transport),
        ("ja4t", Layer::Transport),
        ("tcpcluster", Layer::Transport),
        ("ja4h", Layer::Application),
        ("claimed", Layer::Application),
        ("ja4", Layer::Application),
    ] {
        assert_eq!(fusion.layers.get(method), Some(&layer), "{method}");
    }
}

#[test]
fn words_split_letters_from_digits() {
    assert_eq!(words("linux/debian12"), ["linux", "debian", "12"]);
    assert_eq!(words("Linux 2.2.x-3.x (barebone)"), ["linux", "2.2", "x", "3", "x", "barebone"]);
    assert_eq!(words("WSL Ubuntu 22.04"), ["wsl", "ubuntu", "22.04"]);
    assert_eq!(alternatives("windows/{10|8.1}"), ["windows/10", "windows/8.1"]);
}
