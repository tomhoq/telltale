use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use pf_core::{
    Context, Error, Evidence, Method, MethodManifest, Outcome, Result, Session, Trigger,
};

use crate::adapters;

/// Builds a method from its manifest. Adapters get their parameters and database
/// path from the manifest and nothing else, which is what keeps YAML the single
/// place configuration lives.
pub type AdapterFactory = fn(MethodManifest, &Path) -> Result<Box<dyn Method>>;

/// Every adapter compiled into the binary, keyed by manifest `name`.
pub fn builtin_adapters() -> HashMap<&'static str, AdapterFactory> {
    HashMap::from([
        ("f0p", adapters::f0p::build as AdapterFactory),
        ("ja4", adapters::ja4::build as AdapterFactory),
        ("banner", adapters::banner::build as AdapterFactory),
        ("fusion", adapters::fusion::build as AdapterFactory),
    ])
}

/// The set of methods a run will apply, ordered by descending priority so that
/// fusion (low priority) sees the evidence it combines.
pub struct Registry {
    methods: Vec<Box<dyn Method>>,
}

impl Registry {
    /// Load every `*.yaml` in a manifest directory and pair it with its adapter.
    ///
    /// A manifest with no adapter is a hard error: silently skipping it would
    /// mean a config change quietly does nothing.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let adapters = builtin_adapters();
        let mut methods = Vec::new();

        let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
            .collect();
        paths.sort();

        for path in paths {
            let text = fs::read_to_string(&path)?;
            let manifest = MethodManifest::from_yaml(&text).map_err(|source| Error::Manifest {
                path: path.display().to_string(),
                reason: source.to_string(),
            })?;

            if !manifest.enabled {
                tracing::debug!(method = %manifest.name, "disabled by manifest");
                continue;
            }

            let build = adapters
                .get(manifest.name.as_str())
                .copied()
                .ok_or_else(|| Error::UnknownMethod(manifest.name.clone()))?;

            methods.push(build(manifest, dir)?);
        }

        methods.sort_by_key(|m| -m.manifest().invocation.priority);
        Ok(Self { methods })
    }

    pub fn new(methods: Vec<Box<dyn Method>>) -> Self {
        Self { methods }
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.methods.iter().map(|m| m.name())
    }

    pub fn len(&self) -> usize {
        self.methods.len()
    }

    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
    /// Run every method whose stage requirement and trigger are satisfied.
    ///
    /// `final_pass` is true when the session is closed or timed out; that is when
    /// `SessionEnd` methods run, and when methods still waiting on a stage the
    /// session never reached get their last chance to report a partial result
    /// instead of holding the session open.
    ///
    /// Evidence accumulates as we go, in priority order, so a fusion method
    /// reads what the methods before it produced.
    ///
    /// `both_directions` is the run's direction policy: false (the default)
    /// hands every method only the traffic the session's initiator sent — on a
    /// honeypot that is the attacker, i.e. incoming traffic. true also exposes
    /// the responder's side via [`Context::observations`].
    pub fn analyze(&self, session: &Session, final_pass: bool, both_directions: bool) -> Vec<Evidence> {
        let mut all = Vec::new();
        self.analyze_each(session, final_pass, both_directions, |produced| {
            all.extend_from_slice(produced)
        });
        all
    }

    /// [`Registry::analyze`], but handing each method's evidence to `emit` the
    /// moment that method returns, rather than once every method has run — so
    /// a fast method's result is not held back by a slow one after it. `emit`
    /// is called once per method that produced something, never with an empty
    /// slice.
    pub fn analyze_each(
        &self,
        session: &Session,
        final_pass: bool,
        both_directions: bool,
        mut emit: impl FnMut(&[Evidence]),
    ) {
        let mut evidence: Vec<Evidence> = Vec::new();

        for method in &self.methods {
            let manifest = method.manifest();

            let should_run = match manifest.invocation.trigger {
                Trigger::SessionEnd => final_pass,
                Trigger::StageReached | Trigger::EveryObservation => {
                    session.reached(manifest.required_stage)
                }
            };
            if !should_run {
                if final_pass {
                    tracing::debug!(
                        method = %manifest.name,
                        required = ?manifest.required_stage,
                        reached = ?session.stage,
                        "required stage never reached; no result for this session"
                    );
                }
                continue;
            }

            // TODO: enforce invocation.budget_ms here — a runaway method must not
            // stall its worker.
            let outcome = {
                let ctx = Context::new(session, &evidence, final_pass, both_directions);
                match method.extract(&ctx) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // One broken method must not sink the whole session.
                        tracing::warn!(method = %manifest.name, %error, "method failed");
                        continue;
                    }
                }
            };

            let provisional = !final_pass && matches!(outcome, Outcome::Partial(_));
            let first_new = evidence.len();
            for mut item in outcome.evidence().to_vec() {
                if !manifest.output.declares(&item.key) {
                    // The manifest and its adapter have drifted apart. Loud,
                    // because it means the declared output schema is a lie.
                    tracing::warn!(
                        method = %manifest.name,
                        key = %item.key,
                        "evidence key is not declared in the manifest output schema"
                    );
                    continue;
                }
                item.provisional = provisional;
                evidence.push(item);
            }
            if evidence.len() > first_new {
                emit(&evidence[first_new..]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the contract between YAML and Rust: every shipped manifest parses,
    /// names an adapter that exists, and its adapter builds. A typo in a manifest
    /// fails here rather than at startup on a live capture.
    #[test]
    fn shipped_manifests_all_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        let registry = Registry::load_dir(&dir).expect("shipped manifests should load");
        assert!(!registry.is_empty(), "no methods loaded from {dir:?}");
    }

    /// A SYN then a curl request: `f0p` and `banner` both have something to
    /// say, and each says it in its own emit, in priority order, rather than
    /// the two arriving together at the end of the pass.
    #[test]
    fn each_method_reports_in_its_own_emit() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::SystemTime;

        use pf_core::{Endpoint, Observation, Stage, TcpFeatures, TcpOptionKind, Transport};

        let client = Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            port: 47236,
        };
        let server = Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
            port: 5173,
        };
        let segment = |stage: Stage, payload: &[u8], tcp: Option<TcpFeatures>| Observation {
            at: SystemTime::UNIX_EPOCH,
            source: client,
            destination: server,
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            stage_hint: Some(stage),
            tcp,
        };
        let syn = TcpFeatures {
            ttl: 64,
            df: true,
            window: 64240,
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamp: true,
            option_order: vec![
                TcpOptionKind::Mss,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
            ],
            eol_padding: None,
        };

        let mut session = Session::open(segment(Stage::Connect, b"", Some(syn)));
        session.push(segment(
            Stage::Established,
            b"GET / HTTP/1.1\r\nHost: 10.0.0.8:5173\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
            None,
        ));
        session.advance(Stage::AppData);

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        let registry = Registry::load_dir(&dir).expect("shipped manifests should load");

        let mut emits: Vec<Vec<String>> = Vec::new();
        registry.analyze_each(&session, false, false, |produced| {
            emits.push(produced.iter().map(|e| e.method.clone()).collect());
        });

        let methods: Vec<&str> = emits.iter().map(|emit| emit[0].as_str()).collect();
        assert_eq!(methods, ["f0p", "banner"]);
        for emit in &emits {
            assert!(emit.iter().all(|m| m == &emit[0]), "one emit mixed methods: {emit:?}");
        }
    }

    /// Fusion must come last so the evidence it combines already exists.
    #[test]
    fn fusion_runs_last() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        let registry = Registry::load_dir(&dir).expect("shipped manifests should load");
        let order: Vec<&str> = registry.names().collect();
        assert_eq!(order.last(), Some(&"fusion"), "order was {order:?}");
    }
}
