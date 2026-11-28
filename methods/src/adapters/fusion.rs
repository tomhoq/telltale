//! Merges what the other methods say about an endpoint into one answer per
//! topic (its OS, its client), and flags where they disagree. The design is
//! `specs`, Phase 5, "Fusion design".
//!
//! 1. *Claims.* Every `classification` the methods before it produced, by
//!    key name: `os` and `versions` are about the OS, `client` about the
//!    client. A label that names a client category where an OS was expected
//!    (tcpcluster's `os: scanner`) counts as a client claim.
//! 2. *Normalise.* Two keyword tables from the manifest give each label its
//!    family (OS) or category (client). Below that, a label stays free text,
//!    compared as lowercase words.
//! 3. *Weigh.* A claim scores `method weight x confidence value`;
//!    `version-weights` overrides the weight below the family.
//! 4. *Decide, level by level.* A family is taken when it holds at least
//!    `accept` of the score; then, within it, the version (or product) the
//!    same way.
//! 5. *Disagreement.* `inconsistent` when another family is backed only by
//!    methods of the other layer (TCP stack against the HTTP side), each side
//!    with at least `min-support` of confidence, method weights ignored;
//!    `ambiguous` when no family has a majority otherwise.
//! 6. *Scanners.* A client category of `scanner` discounts every OS claim
//!    (the tool's crafted SYN, the User-Agent it chose) before the OS is
//!    decided; the flag is decided before that discount.
//!
//! A method's layer comes from its manifest's `required-stage`, read from the
//! manifest directory: `connect` and `established` are transport,
//! `tls-client-hello` and `app-data` application.
//!
//! The scanner verdict (`verdict`) is still a placeholder: its scoring is a
//! TODO, and it is emitted only once it reaches the threshold.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use pf_core::{
    Confidence, Context, Evidence, FieldKind, Method, MethodManifest, Outcome, Result, Stage, Verdict,
};
use serde::Deserialize;

/// Which side of the connection a method reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    /// The TCP/IP stack: the SYN and the handshake.
    Transport,
    /// What the client sends once connected: TLS hello, HTTP request.
    Application,
    /// A method whose manifest was not found.
    Unknown,
}

impl Layer {
    fn of(stage: Stage) -> Self {
        match stage {
            Stage::Connect | Stage::Established => Layer::Transport,
            Stage::TlsClientHello | Stage::AppData => Layer::Application,
            Stage::Closed => Layer::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topic {
    Os,
    Client,
}

impl Topic {
    fn name(self) -> &'static str {
        match self {
            Topic::Os => "os",
            Topic::Client => "client",
        }
    }
}

/// `families` or `categories`: names in manifest order, each with its
/// keywords, every keyword split into words, and the words that are only
/// other names for the entry.
#[derive(Debug, Default)]
struct Table {
    entries: Vec<(String, Vec<Vec<String>>)>,
    /// Per entry, from `family-synonyms` (`mac`, `osx` for macos). Dropped
    /// with the entry's name from what is compared below it; every other
    /// keyword (`ubuntu`, `android`, `ios`) is a version.
    synonyms: Vec<BTreeSet<String>>,
}

impl Table {
    fn from_param(manifest: &MethodManifest, key: &str, synonyms_key: Option<&str>) -> Self {
        let mapping: serde_yaml::Mapping = manifest.param(key, serde_yaml::Mapping::new());
        let synonyms: HashMap<String, Vec<String>> = synonyms_key
            .map(|k| manifest.param(k, HashMap::new()))
            .unwrap_or_default();
        let entries: Vec<(String, Vec<Vec<String>>)> = mapping
            .into_iter()
            .filter_map(|(name, keywords)| {
                let name = name.as_str()?.to_lowercase();
                let keywords: Vec<String> = serde_yaml::from_value(keywords).ok()?;
                Some((name, keywords.iter().map(|k| words(k)).collect()))
            })
            .collect();
        let synonyms = entries
            .iter()
            .map(|(name, _)| synonyms.get(name).into_iter().flatten().flat_map(|s| words(s)).collect())
            .collect();
        Table { entries, synonyms }
    }

    /// The entry whose keyword appears earliest in `label`; on a tie, the
    /// one listed first.
    fn classify(&self, label: &[String]) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, (_, keywords))| {
                keywords.iter().filter_map(|k| position(label, k)).min().map(|at| (at, i))
            })
            .min()
            .map(|(_, i)| i)
    }

    /// Words that only repeat the entry's own name, dropped from what is
    /// compared below it: the name itself and its synonyms.
    fn name_words(&self, entry: usize) -> BTreeSet<String> {
        words(&self.entries[entry].0)
            .into_iter()
            .chain(self.synonyms[entry].iter().cloned())
            .collect()
    }
}

/// Where `phrase` starts as a run of whole words in `label`.
fn position(label: &[String], phrase: &[String]) -> Option<usize> {
    if phrase.is_empty() || phrase.len() > label.len() {
        return None;
    }
    (0..=label.len() - phrase.len()).find(|&i| label[i..i + phrase.len()] == *phrase)
}

/// Lowercase words, split on anything but letters, digits and dots, and
/// again where letters meet digits: `debian12` is `debian 12`, `2.2.x-3.x`
/// is `2.2 x 3 x`.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |w: &mut String| {
        let trimmed = w.trim_matches('.');
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
        w.clear();
    };
    for raw in text.to_lowercase().split(|c: char| !(c.is_alphanumeric() || c == '.')) {
        let mut word = String::new();
        let mut numeric = None;
        for c in raw.chars() {
            let is_numeric = c.is_ascii_digit() || c == '.';
            if numeric.is_some_and(|n| n != is_numeric) {
                push(&mut word);
            }
            word.push(c);
            numeric = Some(is_numeric);
        }
        push(&mut word);
    }
    out
}

/// `windows/{10|8.1}` -> `windows/10`, `windows/8.1`: tcpcluster's version
/// sets, one alternative each. Anything else is its own only alternative.
fn alternatives(label: &str) -> Vec<String> {
    match (label.find('{'), label.rfind('}')) {
        (Some(open), Some(close)) if open < close => {
            let (before, after) = (&label[..open], &label[close + 1..]);
            label[open + 1..close]
                .split('|')
                .map(|alt| format!("{before}{alt}{after}"))
                .collect()
        }
        _ => vec![label.to_string()],
    }
}

/// One method's claim about one topic.
#[derive(Debug, Clone)]
struct Claim {
    method: String,
    layer: Layer,
    topic: Topic,
    /// Family or category; `other:<label>` when no keyword matched.
    top: String,
    confidence: Confidence,
    /// Weight for the family / category level.
    score: f64,
    /// Weight below it.
    version_score: f64,
    /// What it says below the family: one word list per alternative, none
    /// when it names only the family.
    below: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ConfidenceValues {
    strong: f64,
    likely: f64,
    weak: f64,
}

impl Default for ConfidenceValues {
    fn default() -> Self {
        ConfidenceValues {
            strong: 1.0,
            likely: 0.6,
            weak: 0.3,
        }
    }
}

impl ConfidenceValues {
    fn of(&self, confidence: Confidence) -> f64 {
        match confidence {
            Confidence::Strong => self.strong,
            Confidence::Likely => self.likely,
            Confidence::Weak => self.weak,
        }
    }
}

/// One topic's answer: the family (or the candidates, when undecided), what
/// is below it, and a disagreement flag.
#[derive(Debug, Default, PartialEq)]
struct Answer {
    top: Option<(String, Confidence)>,
    below: Option<(String, Confidence)>,
    /// `ambiguous` or `inconsistent`, and the sides.
    flag: Option<(&'static str, String)>,
}

pub struct Fusion {
    manifest: MethodManifest,
    /// Score at or above which the endpoint is called a scanner. Lives in the
    /// manifest so the threshold can be swept without recompiling.
    threshold: f64,
    families: Table,
    categories: Table,
    method_weights: HashMap<String, f64>,
    version_weights: HashMap<String, f64>,
    confidence: ConfidenceValues,
    accept: f64,
    min_support: f64,
    scanner_category: String,
    scanner_discount: f64,
    /// Each method's layer, from the manifests next to this one.
    layers: HashMap<String, Layer>,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    Ok(Box::new(Fusion::new(manifest, manifest_dir)))
}

impl Fusion {
    fn new(manifest: MethodManifest, manifest_dir: &Path) -> Self {
        let layers = std::fs::read_dir(manifest_dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
            .filter_map(|p| MethodManifest::from_yaml(&std::fs::read_to_string(p).ok()?).ok())
            .map(|m| (m.name, Layer::of(m.required_stage)))
            .collect();
        Fusion {
            threshold: manifest.param("threshold", 0.7),
            families: Table::from_param(&manifest, "families", Some("family-synonyms")),
            categories: Table::from_param(&manifest, "categories", None),
            method_weights: manifest.param("method-weights", HashMap::new()),
            version_weights: manifest.param("version-weights", HashMap::new()),
            confidence: manifest.param("confidence", ConfidenceValues::default()),
            accept: manifest.param("accept", 0.7),
            min_support: manifest.param("min-support", 0.6),
            scanner_category: manifest.param("scanner-category", "scanner".to_string()),
            scanner_discount: manifest.param("scanner-discount", 0.0),
            layers,
            manifest,
        }
    }

    /// The claims in this pass's evidence, OS and client.
    fn claims(&self, evidence: &[Evidence]) -> Vec<Claim> {
        let mut claims = Vec::new();
        for e in evidence {
            if e.method == self.name() || e.kind != FieldKind::Classification {
                continue;
            }
            let asked = match e.key.as_str() {
                "os" | "versions" => Topic::Os,
                "client" => Topic::Client,
                _ => continue,
            };
            let label = words(&e.value);
            // An OS slot naming a client category (tcpcluster's `scanner`)
            // is a claim about the client.
            let (topic, table, entry) = match asked {
                Topic::Os => match self.families.classify(&label) {
                    Some(i) => (Topic::Os, &self.families, Some(i)),
                    None => match self.categories.classify(&label) {
                        Some(i) => (Topic::Client, &self.categories, Some(i)),
                        None => (Topic::Os, &self.families, None),
                    },
                },
                Topic::Client => (Topic::Client, &self.categories, self.categories.classify(&label)),
            };
            let (top, below) = match entry {
                Some(i) => {
                    // The entry's name and synonyms say nothing below it
                    // (ja4t's "Mac OSX/iPhone" names no version); any other
                    // word is the version: `android`, `ubuntu 22.04`, `ios`.
                    let drop = table.name_words(i);
                    let below = alternatives(&e.value)
                        .iter()
                        .map(|alt| words(alt).into_iter().filter(|w| !drop.contains(w)).collect::<Vec<_>>())
                        .filter(|alt| !alt.is_empty())
                        .collect();
                    (table.entries[i].0.clone(), below)
                }
                // Unknown to the tables: kept whole, never dropped.
                None => (format!("other:{}", e.value.to_lowercase()), Vec::new()),
            };
            let weight = self.method_weights.get(&e.method).copied().unwrap_or(1.0);
            let version_weight = self.version_weights.get(&e.method).copied().unwrap_or(weight);
            let value = self.confidence.of(e.confidence);
            claims.push(Claim {
                method: e.method.clone(),
                layer: self.layers.get(&e.method).copied().unwrap_or(Layer::Unknown),
                topic,
                top,
                confidence: e.confidence,
                score: weight * value,
                version_score: version_weight * value,
                below,
            });
        }
        claims
    }

    /// Strong when at least two methods back it with Strong claims, Likely
    /// when its score is at least 1.0, Weak otherwise.
    fn fused_confidence(supporters: &[(&str, Confidence, f64)], score: f64) -> Confidence {
        let strong: BTreeSet<&str> = supporters
            .iter()
            .filter(|(_, c, _)| *c == Confidence::Strong)
            .map(|(m, _, _)| *m)
            .collect();
        if strong.len() >= 2 {
            Confidence::Strong
        } else if score >= 1.0 {
            Confidence::Likely
        } else {
            Confidence::Weak
        }
    }

    /// One topic, decided level by level.
    fn decide(&self, claims: &[&Claim]) -> Answer {
        // Family level: each method counted once per family, at its best.
        let mut tops: Vec<(String, Vec<(&str, Confidence, f64)>, BTreeSet<Layer>)> = Vec::new();
        for c in claims.iter().filter(|c| c.score > 0.0) {
            let at = match tops.iter().position(|(t, _, _)| *t == c.top) {
                Some(at) => at,
                None => {
                    tops.push((c.top.clone(), Vec::new(), BTreeSet::new()));
                    tops.len() - 1
                }
            };
            let (_, supporters, layers) = &mut tops[at];
            layers.insert(c.layer);
            match supporters.iter_mut().find(|(m, _, _)| *m == c.method) {
                Some(s) if s.2 >= c.score => {}
                Some(s) => *s = (&c.method, c.confidence, c.score),
                None => supporters.push((&c.method, c.confidence, c.score)),
            }
        }
        if tops.is_empty() {
            return Answer::default();
        }
        let score = |s: &[(&str, Confidence, f64)]| s.iter().map(|x| x.2).sum::<f64>();
        tops.sort_by(|a, b| score(&b.1).total_cmp(&score(&a.1)).then(a.0.cmp(&b.0)));
        let total: f64 = tops.iter().map(|t| score(&t.1)).sum();
        let (first, first_support, first_layers) = &tops[0];
        let first_score = score(first_support);
        let decided = first_score / total >= self.accept;

        let sides = |(name, support, _): &(String, Vec<(&str, Confidence, f64)>, BTreeSet<Layer>)| {
            let methods: Vec<&str> = support.iter().map(|s| s.0).collect();
            format!("{name} ({})", methods.join(", "))
        };
        // Whether the layers contradict each other is judged on what the
        // claims say, not on how far fusion trusts them: confidence alone,
        // method weights ignored. Weights pick the answer; they must not hide
        // that a client claimed what its stack contradicts.
        let support = |s: &[(&str, Confidence, f64)]| s.iter().map(|x| self.confidence.of(x.1)).sum::<f64>();
        let inconsistent = tops[1..].iter().find(|other| {
            support(first_support) >= self.min_support
                && support(&other.1) >= self.min_support
                && other.2.is_disjoint(first_layers)
        });
        let flag = match inconsistent {
            Some(other) => Some(("inconsistent", format!("{} vs {}", sides(&tops[0]), sides(other)))),
            None if !decided => Some(("ambiguous", format!("{} vs {}", sides(&tops[0]), sides(&tops[1])))),
            None => None,
        };

        if !decided {
            let names: Vec<&str> = tops.iter().map(|t| t.0.as_str()).collect();
            return Answer {
                top: Some((names.join(" | "), Confidence::Weak)),
                below: None,
                flag,
            };
        }
        let top = Some((first.clone(), Self::fused_confidence(first_support, first_score)));
        let below = self.decide_below(claims.iter().filter(|c| c.top == *first));
        Answer { top, below, flag }
    }

    /// Within a decided family: the version (or product) the claims agree
    /// on, or the candidates. Two word lists agree when one contains the
    /// other (`ubuntu` and `ubuntu 22.04`); a claim with a set of
    /// alternatives backs every candidate any of them agrees with.
    fn decide_below<'c>(&self, claims: impl Iterator<Item = &'c &'c Claim>) -> Option<(String, Confidence)> {
        // Per method: every alternative it gives, at its best score.
        let mut methods: Vec<(&str, Confidence, f64, Vec<&Vec<String>>)> = Vec::new();
        for c in claims.filter(|c| c.version_score > 0.0 && !c.below.is_empty()) {
            match methods.iter_mut().find(|m| m.0 == c.method) {
                Some(m) => {
                    if c.version_score > m.2 {
                        (m.1, m.2) = (c.confidence, c.version_score);
                    }
                    m.3.extend(c.below.iter());
                }
                None => methods.push((&c.method, c.confidence, c.version_score, c.below.iter().collect())),
            }
        }
        if methods.is_empty() {
            return None;
        }
        let set = |w: &Vec<String>| w.iter().cloned().collect::<BTreeSet<String>>();
        let agree = |a: &Vec<String>, b: &Vec<String>| {
            let (a, b) = (set(a), set(b));
            a.is_subset(&b) || b.is_subset(&a)
        };
        let mut candidates: Vec<&Vec<String>> = Vec::new();
        for alt in methods.iter().flat_map(|m| m.3.iter().copied()) {
            if !candidates.iter().any(|c| set(c) == set(alt)) {
                candidates.push(alt);
            }
        }
        let backers = |cand: &Vec<String>| -> Vec<(&str, Confidence, f64)> {
            methods
                .iter()
                .filter(|m| m.3.iter().any(|alt| agree(alt, cand)))
                .map(|m| (m.0, m.1, m.2))
                .collect()
        };
        let total: f64 = methods.iter().map(|m| m.2).sum();
        let support = |cand: &Vec<String>| backers(cand).iter().map(|b| b.2).sum::<f64>();
        let shown = |w: &Vec<String>| w.join(" ");
        candidates.sort_by(|a, b| support(b).total_cmp(&support(a)).then(shown(a).cmp(&shown(b))));
        let best = support(candidates[0]);
        if best / total < self.accept {
            let all: Vec<String> = candidates.iter().map(|c| shown(c)).collect();
            return Some((all.join(" | "), Confidence::Weak));
        }
        let winners: Vec<&Vec<String>> =
            candidates.iter().copied().filter(|c| (support(c) - best).abs() < 1e-9).collect();
        let confidence = Self::fused_confidence(&backers(winners[0]), best);
        let all_agree = winners.iter().all(|a| winners.iter().all(|b| agree(a, b)));
        let value = if all_agree {
            // The most specific of mutually agreeing candidates.
            shown(winners.iter().max_by_key(|w| w.len()).unwrap())
        } else {
            // One claim's own set (`10 | 8.1`), backed as a whole.
            winners.iter().map(|w| shown(w)).collect::<Vec<_>>().join(" | ")
        };
        Some((value, confidence))
    }

    /// The fused evidence for this pass: per topic, the answer and its flag.
    fn fuse(&self, ctx: &Context<'_>) -> Vec<Evidence> {
        let mut claims = self.claims(ctx.evidence);
        let subject = ctx.session.initiator;
        let mut evidence = Vec::new();
        let mut emit = |topic: Topic, answer: &Answer, below_key: &str| {
            if let Some((value, confidence)) = &answer.top {
                evidence.push(Evidence::new(self.name(), subject, topic.name(), value.clone(), *confidence));
            }
            if let Some((value, confidence)) = &answer.below {
                evidence.push(Evidence::new(self.name(), subject, below_key, value.clone(), *confidence));
            }
            if let Some((kind, sides)) = &answer.flag {
                let key = format!("{}-{kind}", topic.name());
                evidence.push(Evidence::new(self.name(), subject, key, sides.clone(), Confidence::Weak));
            }
        };

        let client = self.decide(&claims.iter().filter(|c| c.topic == Topic::Client).collect::<Vec<_>>());
        emit(Topic::Client, &client, "products");
        let mut os = self.decide(&claims.iter().filter(|c| c.topic == Topic::Os).collect::<Vec<_>>());
        // A scanner's connection is the tool's: its SYN is crafted and its
        // User-Agent chosen, so no OS claim describes a host. The OS is
        // decided without them; the flag stays as decided with them, so a
        // scanner faking a browser's User-Agent is still `os-inconsistent`.
        if client.top.as_ref().is_some_and(|(top, _)| *top == self.scanner_category) {
            for c in claims.iter_mut().filter(|c| c.topic == Topic::Os) {
                c.score *= self.scanner_discount;
                c.version_score *= self.scanner_discount;
            }
            let discounted = self.decide(&claims.iter().filter(|c| c.topic == Topic::Os).collect::<Vec<_>>());
            os = Answer { flag: os.flag, ..discounted };
        }
        emit(Topic::Os, &os, "versions");
        evidence
    }
}

impl Method for Fusion {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        if ctx.evidence.is_empty() {
            return Ok(Outcome::NoMatch);
        }
        let mut evidence = self.fuse(ctx);

        // TODO: the scanner verdict's scoring. Signals worth weighing, roughly
        // in order of how much they distinguish a scanner from a browser:
        //   - a ja4 hash on the known-scanner list
        //   - a User-Agent claiming to be a scanning tool
        //   - an OS/stack fingerprint inconsistent with the claimed client
        //     (`os-inconsistent` above)
        //   - session shape: connect-then-abandon, no app data, very short life
        //   - across sessions: many destinations from one source (needs state
        //     the ProfileStore holds, not this session — decide where that lives)
        // Until then the score is 0 and no verdict is emitted: "unknown" on
        // every endpoint would say nothing.
        let score = 0.0_f64;
        if score >= self.threshold {
            evidence.push(Evidence::new(
                self.name(),
                ctx.session.initiator,
                "verdict",
                format!("{:?}", Verdict::Scanner).to_lowercase(),
                Confidence::Weak,
            ));
        }

        if evidence.is_empty() {
            return Ok(Outcome::NoMatch);
        }
        // Not final until the session is: more traffic can change the answer.
        Ok(if ctx.is_final {
            Outcome::Complete(evidence)
        } else {
            Outcome::Partial(evidence)
        })
    }
}

#[cfg(test)]
mod tests;
