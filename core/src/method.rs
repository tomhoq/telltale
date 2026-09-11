use crate::manifest::MethodManifest;
use crate::observation::Observation;
use crate::result::Fields;
use crate::session::Session;
use crate::trigger::TriggerEvent;

/// What a method is given for one trigger.
pub struct Context<'a> {
    /// The event that fired this call — one of the method's `triggers`. A
    /// method listening for several (p0f on both SYN and HTTP) branches on it.
    pub trigger: TriggerEvent,
    /// The packet that raised the event. `None` for session events.
    pub packet: Option<&'a Observation>,
    /// Read-only: every packet seen so far in this flow, and every result
    /// already appended. Single-packet methods ignore it; sequence methods
    /// and fusion read it.
    pub session: &'a Session,
}

/// A fingerprinting technique.
///
/// Adapters live in `pf-methods` and pair with a YAML manifest. Contract:
///
/// - `extract()` is **pure** — no I/O, no shared mutable state — so the
///   dispatcher can run many calls at once, including several methods off the
///   same packet.
/// - It is called once per trigger event, and only for events the manifest
///   lists.
/// - It returns what it found: each [`Fields`] becomes one result entry, and
///   an empty `Vec` means nothing to report. Every field must be declared in
///   the manifest's `output-schema` with the matching type; anything else is
///   dropped with a warning.
pub trait Method: Send + Sync {
    fn manifest(&self) -> &MethodManifest;

    fn name(&self) -> &str {
        &self.manifest().name
    }

    fn triggers(&self) -> &[TriggerEvent] {
        &self.manifest().triggers
    }

    fn extract(&self, ctx: &Context<'_>) -> crate::Result<Vec<Fields>>;
}
