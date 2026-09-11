use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use pf_core::{
    Context, Error, Fields, InvocationTarget, Method, MethodManifest, Result, ResultEntry,
    TriggerEvent,
};

use crate::adapters;

/// Builds a method from its manifest. Adapters get their parameters and database
/// path from the manifest and nothing else, which is what keeps YAML the single
/// place configuration lives.
pub type AdapterFactory = fn(MethodManifest, &Path) -> Result<Box<dyn Method>>;

/// Every adapter compiled into the binary, keyed by the name a manifest's
/// `invocation.adapter` refers to.
pub fn builtin_adapters() -> HashMap<&'static str, AdapterFactory> {
    HashMap::from([
        ("tcp-syn", adapters::tcp_syn::build as AdapterFactory),
        ("ja4", adapters::ja4::build as AdapterFactory),
        ("banner", adapters::banner::build as AdapterFactory),
        ("fusion", adapters::fusion::build as AdapterFactory),
    ])
}

/// Identifies a loaded method; stable for the life of the registry.
pub type MethodId = usize;

/// The loaded methods, indexed by the events that fire them.
pub struct Registry {
    methods: Vec<Box<dyn Method>>,
    by_trigger: HashMap<TriggerEvent, Vec<MethodId>>,
}

impl Registry {
    /// Load every `*.yaml` in a manifest directory and pair it with its adapter.
    ///
    /// A manifest naming an adapter that does not exist is a hard error:
    /// silently skipping it would mean a config change quietly does nothing.
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
            let invalid = |reason: String| Error::Manifest {
                path: path.display().to_string(),
                reason,
            };

            let text = fs::read_to_string(&path)?;
            let manifest =
                MethodManifest::from_yaml(&text).map_err(|source| invalid(source.to_string()))?;

            if !manifest.enabled {
                tracing::debug!(method = %manifest.name, "disabled by manifest");
                continue;
            }

            let build = match &manifest.invocation.target {
                InvocationTarget::InProcess { adapter } => adapters
                    .get(adapter.as_str())
                    .copied()
                    .ok_or_else(|| Error::UnknownMethod(adapter.clone()))?,
                // TODO: the subprocess adapter — run the command per call with
                // `invocation.timeout-ms` enforced.
                InvocationTarget::External { command, .. } => {
                    return Err(invalid(format!(
                        "external invocation (`{command}`) is not supported yet"
                    )));
                }
            };

            methods.push(build(manifest, dir)?);
        }

        Self::new(methods)
    }

    /// Build from already-constructed methods. Names must be unique, since
    /// results are attributed by name.
    pub fn new(methods: Vec<Box<dyn Method>>) -> Result<Self> {
        let mut by_trigger: HashMap<TriggerEvent, Vec<MethodId>> = HashMap::new();
        for (id, method) in methods.iter().enumerate() {
            if methods[..id].iter().any(|other| other.name() == method.name()) {
                return Err(Error::Manifest {
                    path: method.name().to_string(),
                    reason: "another loaded manifest has the same name".into(),
                });
            }
            for trigger in method.triggers() {
                let ids = by_trigger.entry(*trigger).or_default();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        Ok(Self {
            methods,
            by_trigger,
        })
    }

    /// The methods an event fires. Empty for an event nothing listens to.
    pub fn methods_for(&self, trigger: TriggerEvent) -> &[MethodId] {
        self.by_trigger.get(&trigger).map_or(&[], Vec::as_slice)
    }

    pub fn method(&self, id: MethodId) -> &dyn Method {
        self.methods[id].as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Method> {
        self.methods.iter().map(|m| m.as_ref())
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

    /// Run one method for one trigger and turn what it found into result
    /// entries, stamped with the method, the trigger and the packet's time.
    ///
    /// Everything is checked against the manifest's `output-schema`: a field
    /// it does not declare, or a value of the wrong type, is dropped with a
    /// warning — the manifest and adapter have drifted apart, and the declared
    /// schema is what output trusts. A method that fails is logged and
    /// reports nothing; it must not sink the session.
    pub fn run(&self, id: MethodId, ctx: &Context<'_>) -> Vec<ResultEntry> {
        let method = self.method(id);
        let manifest = method.manifest();

        let found = match method.extract(ctx) {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(method = %manifest.name, %error, "method failed");
                return Vec::new();
            }
        };

        let timestamp = ctx.packet.map_or(ctx.session.last_seen_at, |packet| packet.at);
        found
            .into_iter()
            .map(|fields| conforming(manifest, fields))
            .filter(|fields| !fields.is_empty())
            .map(|fields| ResultEntry {
                method: manifest.name.clone(),
                trigger: ctx.trigger,
                timestamp,
                fields,
            })
            .collect()
    }
}

/// The fields that match the manifest's schema.
fn conforming(manifest: &MethodManifest, fields: Fields) -> Fields {
    fields
        .into_iter()
        .filter(|(name, value)| match manifest.field(name) {
            Some(spec) if spec.ty == value.field_type() => true,
            Some(spec) => {
                tracing::warn!(
                    method = %manifest.name,
                    field = %name,
                    declared = ?spec.ty,
                    actual = ?value.field_type(),
                    "field value does not match its declared type"
                );
                false
            }
            None => {
                tracing::warn!(
                    method = %manifest.name,
                    field = %name,
                    "field is not declared in the manifest's output-schema"
                );
                false
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    use pf_core::{Endpoint, FieldValue, Observation, Session, Transport};

    use super::*;

    fn manifests_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests")
    }

    /// Guards the contract between YAML and Rust: every shipped manifest parses,
    /// names an adapter that exists, and its adapter builds. A typo in a manifest
    /// fails here rather than at startup on a live capture.
    #[test]
    fn shipped_manifests_all_load() {
        let registry = Registry::load_dir(manifests_dir()).expect("shipped manifests should load");
        assert!(!registry.is_empty(), "no methods loaded");
    }

    #[test]
    fn methods_are_indexed_by_their_triggers() {
        let registry = Registry::load_dir(manifests_dir()).expect("shipped manifests should load");
        let names = |trigger| -> Vec<&str> {
            registry
                .methods_for(trigger)
                .iter()
                .map(|id| registry.method(*id).name())
                .collect()
        };

        assert_eq!(names(TriggerEvent::TcpSyn), ["tcp-syn"]);
        assert_eq!(names(TriggerEvent::TlsClientHello), ["ja4"]);
        assert_eq!(names(TriggerEvent::SessionEnd), ["fusion"]);
        assert!(names(TriggerEvent::TlsServerHello).is_empty());
    }

    /// A method whose output does not match its declared schema.
    struct Sloppy(MethodManifest);

    impl Method for Sloppy {
        fn manifest(&self) -> &MethodManifest {
            &self.0
        }

        fn extract(&self, _: &Context<'_>) -> Result<Vec<Fields>> {
            Ok(vec![Fields::from([
                ("os".to_string(), FieldValue::from("linux")),
                ("hops".to_string(), FieldValue::from("three")), // declared integer
                ("undeclared".to_string(), FieldValue::from(true)),
            ])])
        }
    }

    #[test]
    fn run_keeps_only_fields_that_match_the_schema_and_stamps_the_entry() {
        let manifest = MethodManifest::from_yaml(
            r#"
name: sloppy
layer: L1
triggers: [tcp-syn]
invocation: { type: in-process, adapter: sloppy }
output-schema:
  - { field: os, type: string, kind: classification }
  - { field: hops, type: integer, kind: score }
"#,
        )
        .unwrap();
        let registry = Registry::new(vec![Box::new(Sloppy(manifest))]).unwrap();

        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(7);
        let endpoint = |port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let packet = Observation {
            at,
            source: endpoint(40000),
            destination: endpoint(22),
            transport: Transport::Tcp,
            ttl: Some(64),
            tcp: None,
            payload: Vec::new(),
        };
        let session = Session::open(packet.clone());
        let ctx = Context {
            trigger: TriggerEvent::TcpSyn,
            packet: Some(&packet),
            session: &session,
        };

        let entries = registry.run(0, &ctx);

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.method, "sloppy");
        assert_eq!(entry.trigger, TriggerEvent::TcpSyn);
        assert_eq!(entry.timestamp, at);
        assert_eq!(entry.fields.keys().collect::<Vec<_>>(), ["os"]);
    }
}
