use crate::evidence::Evidence;
use crate::manifest::MethodManifest;
use crate::session::Session;

/// What a method is given to work with.
///
/// It carries the evidence already produced during this pass as well as the
/// session, because fusion methods combine other methods' output. Priority
/// ordering in the registry is what guarantees the evidence a fusion method
/// needs is already there.
pub struct Context<'a> {
    pub session: &'a Session,
    /// Evidence from higher-priority methods: what they concluded this pass,
    /// or in an earlier pass if they had already settled.
    pub evidence: &'a [Evidence],
    /// True when the session is closed or timed out and will not grow again.
    pub is_final: bool,
}

impl<'a> Context<'a> {
    pub fn new(session: &'a Session, evidence: &'a [Evidence], is_final: bool) -> Self {
        Self {
            session,
            evidence,
            is_final,
        }
    }

    /// Every value a given method claimed for a key.
    pub fn claims<'b>(&'b self, method: &'b str, key: &'b str) -> impl Iterator<Item = &'b str> {
        self.evidence
            .iter()
            .filter(move |e| e.method == method && e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Whether a method produced anything at all — "this scanner spoke no TLS"
    /// is itself evidence.
    pub fn method_produced(&self, method: &str) -> bool {
        self.evidence.iter().any(|e| e.method == method)
    }
}

/// What one invocation of a method produced.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The method is done with this session; do not invoke it again.
    Complete(Vec<Evidence>),
    /// Everything the method can say so far. Emitted when the required stage was
    /// reached but the session is still growing, and when a timeout cut the
    /// session short of what the method wanted.
    Partial(Vec<Evidence>),
    /// The method does not apply to this session at all.
    NotApplicable,
    /// It applied, but produced nothing — an unknown signature, say. Kept
    /// distinct from `NotApplicable` because "no match" is itself a signal.
    NoMatch,
}

impl Outcome {
    pub fn evidence(&self) -> &[Evidence] {
        match self {
            Outcome::Complete(e) | Outcome::Partial(e) => e,
            Outcome::NotApplicable | Outcome::NoMatch => &[],
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(self, Outcome::Complete(_) | Outcome::NotApplicable)
    }
}

/// A fingerprinting technique.
///
/// Adapters live in `pf-methods` and pair with a YAML manifest. Contract:
///
/// - `extract()` is **pure** — no I/O, no shared mutable state — so the
///   dispatcher can run methods across sessions in parallel.
/// - `extract()` is **idempotent over the session-so-far**: calling it again on a
///   longer session must be safe. That is what allows streaming output; a
///   batch-only method just returns `Complete` the first time.
/// - The registry guarantees the session has reached `manifest().required_stage`
///   before calling, so adapters need not re-check it.
pub trait Method: Send + Sync {
    fn manifest(&self) -> &MethodManifest;

    fn name(&self) -> &str {
        &self.manifest().name
    }

    fn extract(&self, ctx: &Context<'_>) -> crate::Result<Outcome>;
}
