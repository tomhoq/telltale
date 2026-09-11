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
        ("tcp-syn", adapters::tcp_syn::build as AdapterFactory),
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

    /// Whether any method wants a pass on every observation, not only when a
    /// session reaches a new stage. Streaming mode submits far more work if so.
    pub fn wants_every_observation(&self) -> bool {
        self.methods
            .iter()
            .any(|m| m.manifest().invocation.trigger == Trigger::EveryObservation)
    }
    /// One pass over a session: the session's whole answer as of now.
    ///
    /// A method runs when its gate is open — `SessionEnd` on the final pass,
    /// the others once `required_stage` is reached — and it has not already
    /// settled. Settled means its last run returned anything but `Partial`:
    /// `Complete`, `NoMatch` and `NotApplicable` are all verdicts on packets
    /// already seen, so a later packet opening some *other* method's gate does
    /// not make it run again; its result is taken from `memo`. `Partial`
    /// asks for more data and is re-run next pass, as is anything triggered
    /// `every-observation`.
    ///
    /// `final_pass` is true when the session is closed or timed out. The
    /// session is then at `Closed`, past every stage, so methods that were
    /// waiting on a stage it never reached get their last chance to report.
    ///
    /// Evidence accumulates in priority order — fresh and remembered alike —
    /// so a fusion method reads what every method before it has concluded.
    pub fn analyze(
        &self,
        session: &Session,
        final_pass: bool,
        memo: &mut SessionMemo,
    ) -> Vec<Evidence> {
        let mut evidence: Vec<Evidence> = Vec::new();

        for (index, method) in self.methods.iter().enumerate() {
            let manifest = method.manifest();

            let gate_open = match manifest.invocation.trigger {
                Trigger::SessionEnd => final_pass,
                Trigger::StageReached | Trigger::EveryObservation => {
                    session.reached(manifest.required_stage)
                }
            };
            if !gate_open {
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

            let run = match memo.results.get(&index) {
                None => true,
                Some(previous) => {
                    !previous.settled || manifest.invocation.trigger == Trigger::EveryObservation
                }
            };
            if run {
                // A failed run leaves the previous result, if any, in place and
                // is tried again next pass.
                if let Some(result) = self.run(method.as_ref(), session, &evidence, final_pass) {
                    memo.results.insert(index, result);
                }
            }

            if let Some(result) = memo.results.get(&index) {
                evidence.extend(result.evidence.iter().cloned());
            }
        }

        evidence
    }

    /// Invoke one method and keep only the evidence its manifest declares.
    /// `None` if it failed.
    fn run(
        &self,
        method: &dyn Method,
        session: &Session,
        evidence: &[Evidence],
        final_pass: bool,
    ) -> Option<MethodResult> {
        let manifest = method.manifest();

        // TODO: enforce invocation.budget_ms here — a runaway method must not
        // stall its worker.
        let outcome = match method.extract(&Context::new(session, evidence, final_pass)) {
            Ok(outcome) => outcome,
            Err(error) => {
                // One broken method must not sink the whole session.
                tracing::warn!(method = %manifest.name, %error, "method failed");
                return None;
            }
        };

        let partial = matches!(outcome, Outcome::Partial(_));
        let provisional = partial && !final_pass;
        let evidence = outcome
            .evidence()
            .iter()
            .filter(|item| {
                let declared = manifest.output.declares(&item.key);
                if !declared {
                    // The manifest and its adapter have drifted apart. Loud,
                    // because it means the declared output schema is a lie.
                    tracing::warn!(
                        method = %manifest.name,
                        key = %item.key,
                        "evidence key is not declared in the manifest output schema"
                    );
                }
                declared
            })
            .cloned()
            .map(|mut item| {
                item.provisional = provisional;
                item
            })
            .collect();

        Some(MethodResult {
            evidence,
            settled: !partial,
        })
    }
}

/// What earlier passes over one session concluded, per method.
///
/// Belongs to one session and lives on the worker that owns it (see
/// `pf_dispatch::Dispatcher`), created empty on the session's first pass and
/// dropped after its final one.
#[derive(Debug, Default)]
pub struct SessionMemo {
    /// Latest result per method, keyed by its index in the registry, which is
    /// fixed once the registry is loaded.
    results: HashMap<usize, MethodResult>,
}

#[derive(Debug)]
struct MethodResult {
    evidence: Vec<Evidence>,
    /// The method's last run returned something other than `Partial`, so it
    /// has nothing more to say about this session.
    settled: bool,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use pf_core::{Confidence, Endpoint, Observation, Stage, Transport};

    use super::*;

    /// A method that counts its invocations and answers with a fixed outcome.
    struct Counting {
        manifest: MethodManifest,
        calls: Arc<AtomicUsize>,
        answer: fn(&Context<'_>) -> Outcome,
    }

    impl Method for Counting {
        fn manifest(&self) -> &MethodManifest {
            &self.manifest
        }

        fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok((self.answer)(ctx))
        }
    }

    fn counting(
        name: &str,
        stage: &str,
        trigger: &str,
        priority: i32,
        answer: fn(&Context<'_>) -> Outcome,
    ) -> (Box<dyn Method>, Arc<AtomicUsize>) {
        let manifest = MethodManifest::from_yaml(&format!(
            "name: {name}\nrequired-stage: {stage}\ninvocation:\n  trigger: {trigger}\n  \
             priority: {priority}\noutput:\n  fields:\n    - name: {name}\n"
        ))
        .expect("test manifest should parse");
        let calls = Arc::new(AtomicUsize::new(0));
        let method = Counting {
            manifest,
            calls: Arc::clone(&calls),
            answer,
        };
        (Box::new(method), calls)
    }

    fn claim(ctx: &Context<'_>, name: &str) -> Evidence {
        Evidence::new(name, ctx.session.initiator, name, "yes", Confidence::Strong)
    }

    fn syn_session() -> Session {
        let endpoint = |port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            port,
        };
        Session::open(Observation {
            at: SystemTime::UNIX_EPOCH,
            source: endpoint(40000),
            destination: endpoint(443),
            transport: Transport::Tcp,
            payload: Vec::new(),
            stage_hint: Some(Stage::Connect),
        })
    }

    fn keys(evidence: &[Evidence]) -> Vec<&str> {
        evidence.iter().map(|e| e.key.as_str()).collect()
    }

    /// The case the memo exists for: tcp-syn settles on the SYN, and a TLS
    /// packet later opening ja4's gate must not make it run again.
    #[test]
    fn a_settled_method_is_not_rerun_when_another_gate_opens() {
        let (syn, syn_calls) = counting("syn", "connect", "stage-reached", 100, |ctx| {
            Outcome::Complete(vec![claim(ctx, "syn")])
        });
        let (tls, tls_calls) = counting("tls", "tls-client-hello", "stage-reached", 90, |ctx| {
            Outcome::Complete(vec![claim(ctx, "tls")])
        });
        let registry = Registry::new(vec![syn, tls]);
        let mut memo = SessionMemo::default();
        let mut session = syn_session();

        let first = registry.analyze(&session, false, &mut memo);
        assert_eq!(keys(&first), ["syn"]);

        session.advance(Stage::TlsClientHello);
        let second = registry.analyze(&session, false, &mut memo);
        session.advance(Stage::Closed);
        let last = registry.analyze(&session, true, &mut memo);

        assert_eq!(syn_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tls_calls.load(Ordering::SeqCst), 1);
        // Remembered results still belong to every later answer.
        assert_eq!(keys(&second), ["syn", "tls"]);
        assert_eq!(keys(&last), ["syn", "tls"]);
    }

    #[test]
    fn a_partial_result_is_rerun_and_final_only_at_the_end() {
        let (grow, calls) = counting("grow", "connect", "stage-reached", 0, |ctx| {
            Outcome::Partial(vec![claim(ctx, "grow")])
        });
        let registry = Registry::new(vec![grow]);
        let mut memo = SessionMemo::default();
        let mut session = syn_session();

        let first = registry.analyze(&session, false, &mut memo);
        session.advance(Stage::Established);
        registry.analyze(&session, false, &mut memo);
        session.advance(Stage::Closed);
        let last = registry.analyze(&session, true, &mut memo);

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(first[0].provisional);
        assert!(!last[0].provisional);
    }

    #[test]
    fn fusion_sees_evidence_remembered_from_earlier_passes() {
        let (syn, _) = counting("syn", "connect", "stage-reached", 100, |ctx| {
            Outcome::Complete(vec![claim(ctx, "syn")])
        });
        let (fusion, _) = counting("fusion", "connect", "session-end", -100, |ctx| {
            if ctx.method_produced("syn") {
                Outcome::Complete(vec![claim(ctx, "fusion")])
            } else {
                Outcome::NoMatch
            }
        });
        let registry = Registry::new(vec![syn, fusion]);
        let mut memo = SessionMemo::default();
        let mut session = syn_session();

        registry.analyze(&session, false, &mut memo);
        session.advance(Stage::Closed);
        let last = registry.analyze(&session, true, &mut memo);

        assert_eq!(keys(&last), ["syn", "fusion"]);
    }

    /// Guards the contract between YAML and Rust: every shipped manifest parses,
    /// names an adapter that exists, and its adapter builds. A typo in a manifest
    /// fails here rather than at startup on a live capture.
    #[test]
    fn shipped_manifests_all_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        let registry = Registry::load_dir(&dir).expect("shipped manifests should load");
        assert!(!registry.is_empty(), "no methods loaded from {dir:?}");
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
