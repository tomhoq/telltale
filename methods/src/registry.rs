use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
        ("ja4h", adapters::ja4h::build as AdapterFactory),
        ("ja4t", adapters::ja4t::build as AdapterFactory),
        ("claimed", adapters::claimed::build as AdapterFactory),
        ("tcpcluster", adapters::tcpcluster::build as AdapterFactory),
        ("fusion", adapters::fusion::build as AdapterFactory),
    ])
}

/// The set of methods a run will apply, ordered by descending priority so that
/// fusion (low priority) sees the evidence it combines.
pub struct Registry {
    methods: Vec<Box<dyn Method>>,
    /// One per method, same order. Atomics because workers run sessions on
    /// several threads at once.
    timings: Vec<Timing>,
}

#[derive(Default)]
struct Timing {
    runs: AtomicU64,
    nanos: AtomicU64,
}

/// Time spent inside one method's `extract`, over the whole run.
#[derive(Debug, Clone)]
pub struct MethodTiming {
    pub name: String,
    /// How many times `extract` was called (it is skipped while the
    /// session has not reached the method's stage).
    pub runs: u64,
    pub total: Duration,
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
        Ok(Self::new(methods))
    }

    pub fn new(methods: Vec<Box<dyn Method>>) -> Self {
        let timings = methods.iter().map(|_| Timing::default()).collect();
        Self { methods, timings }
    }

    /// Per-method time spent in `extract` so far, in run order.
    pub fn timings(&self) -> Vec<MethodTiming> {
        self.methods
            .iter()
            .zip(&self.timings)
            .map(|(method, timing)| MethodTiming {
                name: method.name().to_string(),
                runs: timing.runs.load(Ordering::Relaxed),
                total: Duration::from_nanos(timing.nanos.load(Ordering::Relaxed)),
            })
            .collect()
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

        for (method, timing) in self.methods.iter().zip(&self.timings) {
            let manifest = method.manifest();

            // `Complete` on an earlier snapshot of this session: the method
            // said it is done, so it is not invoked again. Its evidence was
            // emitted then; it is only added to this pass's evidence, for the
            // methods after it (fusion).
            if let Some(done) = session.completed.get(&manifest.name) {
                evidence.extend_from_slice(&done);
                continue;
            }

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
                let started = Instant::now();
                let result = method.extract(&ctx);
                timing.runs.fetch_add(1, Ordering::Relaxed);
                timing
                    .nanos
                    .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
                match result {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // One broken method must not sink the whole session.
                        tracing::warn!(method = %manifest.name, %error, "method failed");
                        continue;
                    }
                }
            };

            let provisional = !final_pass && matches!(outcome, Outcome::Partial(_));
            let complete = matches!(outcome, Outcome::Complete(_));
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
                item.kind = manifest.output.kind_of(&item.key);
                item.provisional = provisional;
                evidence.push(item);
            }
            if evidence.len() > first_new {
                emit(&evidence[first_new..]);
            }
            // A final pass is the session's last, so there is nothing to skip.
            if complete && !final_pass {
                session.completed.record(&manifest.name, &evidence[first_new..]);
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

    /// A SYN then a curl request: `f0p`, `ja4t`, `ja4h` and `claimed` all have something to
    /// say, and each says it in its own emit, in priority order, rather than
    /// the two arriving together at the end of the pass.
    #[test]
    fn each_method_reports_in_its_own_emit() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::SystemTime;

        use pf_core::{Endpoint, Observation, Stage, TcpFeatures, TcpOptionKind, TcpQuirk, Transport};

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
            ip_option_len: 0,
            quirks: [TcpQuirk::Df, TcpQuirk::NonZeroId].into(),
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
            options_truncated: false,
            header: Default::default(),
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
        assert_eq!(methods, ["f0p", "ja4t", "ja4h", "claimed"]);
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

    // ------------------------------------------------ completed methods are not re-run

    /// One entry per `extract` call: how much evidence from earlier methods
    /// it was handed.
    type Calls = std::sync::Arc<std::sync::Mutex<Vec<usize>>>;

    /// Says the same thing every call, `Complete` or `Partial`.
    struct Stub {
        manifest: MethodManifest,
        complete: bool,
        calls: Calls,
    }

    impl Method for Stub {
        fn manifest(&self) -> &MethodManifest {
            &self.manifest
        }

        fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
            self.calls.lock().unwrap().push(ctx.evidence.len());
            let evidence = vec![Evidence::new(
                self.name(),
                ctx.session.initiator,
                "os",
                "linux",
                pf_core::Confidence::Weak,
            )];
            Ok(if self.complete {
                Outcome::Complete(evidence)
            } else {
                Outcome::Partial(evidence)
            })
        }
    }

    fn stub(name: &str, priority: i32, complete: bool) -> (Box<dyn Method>, Calls) {
        let manifest = MethodManifest::from_yaml(&format!(
            "name: {name}
required-stage: connect
invocation: {{trigger: every-observation, priority: {priority}, budget-ms: 50}}
output: {{fields: [{{name: os}}]}}"
        ))
        .unwrap();
        let calls = Calls::default();
        let method = Stub {
            manifest,
            complete,
            calls: Calls::clone(&calls),
        };
        (Box::new(method), calls)
    }

    fn one_packet_session() -> Session {
        use std::net::{IpAddr, Ipv4Addr};
        use pf_core::{Endpoint, Observation, Stage, Transport};
        let endpoint = |last, port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        };
        Session::open(Observation {
            at: std::time::SystemTime::UNIX_EPOCH,
            source: endpoint(10, 50000),
            destination: endpoint(8, 80),
            transport: Transport::Tcp,
            payload: Vec::new(),
            stage_hint: Some(Stage::Connect),
            tcp: None,
        })
    }

    /// Inference mode hands a fresh snapshot (a clone) of the session to the
    /// registry on every packet. A method that returned `Complete` is not
    /// invoked on later snapshots, nor on the final pass, and its evidence is
    /// not emitted again; one that returned `Partial` runs every time.
    #[test]
    fn a_completed_method_is_not_invoked_again() {
        let (done, done_calls) = stub("done", 90, true);
        let (growing, growing_calls) = stub("growing", 80, false);
        let registry = Registry::new(vec![done, growing]);
        let session = one_packet_session();

        let mut emitted = Vec::new();
        let passes = [(session.clone(), false), (session.clone(), false), (session, true)];
        for (snapshot, is_final) in passes {
            registry.analyze_each(&snapshot, is_final, false, |produced| {
                emitted.extend(produced.iter().map(|e| e.method.clone()))
            });
        }

        assert_eq!(done_calls.lock().unwrap().len(), 1);
        assert_eq!(growing_calls.lock().unwrap().len(), 3);
        assert_eq!(emitted, ["done", "growing", "growing", "growing"]);
        let runs: Vec<u64> = registry.timings().iter().map(|t| t.runs).collect();
        assert_eq!(runs, [1, 3], "a skipped method is not counted as a run");
    }

    /// A completed method is skipped, but the methods after it in a pass still
    /// see its evidence, as they did when it ran: fusion reads the others'.
    #[test]
    fn a_completed_method_s_evidence_still_reaches_later_methods() {
        let (done, _) = stub("done", 90, true);
        let (reader, seen) = stub("reader", 10, false);
        let registry = Registry::new(vec![done, reader]);
        let session = one_packet_session();

        registry.analyze(&session.clone(), false, false);
        registry.analyze(&session.clone(), false, false);
        registry.analyze(&session, true, false);

        assert_eq!(*seen.lock().unwrap(), [1, 1, 1]);
    }

    /// The record lives in the session, not the registry: a different
    /// session (say the next connection on the same ports) starts afresh.
    #[test]
    fn completion_is_per_session() {
        let (done, calls) = stub("done", 90, true);
        let registry = Registry::new(vec![done]);
        registry.analyze(&one_packet_session(), false, false);
        registry.analyze(&one_packet_session(), false, false);
        assert_eq!(calls.lock().unwrap().len(), 2);
    }
}
