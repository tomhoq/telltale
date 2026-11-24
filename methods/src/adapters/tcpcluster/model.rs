//! The exported model: fingerprint set, encoder, cluster search table and
//! anchors (`export_telltale.py`, thesis SPEC 9.4.8). Loaded once; every file
//! is checked against the sha256 `meta.json` records for it, so a stale or
//! hand-edited copy fails at startup rather than giving quietly wrong answers.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::features::{Features, MAX_OPTS, N_CAT, N_NUM, OPT_VOCAB};

pub const EMB: usize = 32;
const GRU_IN: usize = 16;
const GRU_H: usize = 32;
const CAT_DIMS: [(usize, usize); N_CAT] = [(16, 4), (5, 4), (4, 3), (5, 3)];
const TRUNK_IN: usize = GRU_H + 4 + 4 + 3 + 3 + N_NUM;
const HIDDEN: usize = 128;

/// Family and version set of a named cluster or anchor. `versions` is a set
/// written as the export writes it (`windows/{10|8.1}`), `None` when the
/// cluster names a family but no version set ("unnamed").
#[derive(Debug, Clone, PartialEq)]
pub struct Name {
    pub family: String,
    pub versions: Option<String>,
}

impl Name {
    fn parse(family: &str, versions: &str) -> Option<Self> {
        let given = |s: &str| !matches!(s, "-" | "unnamed" | "mixed" | "");
        given(family).then(|| Name {
            family: family.to_string(),
            versions: given(versions).then(|| versions.to_string()),
        })
    }
}

/// One row of the fingerprint set.
#[derive(Debug, Clone)]
pub struct Known {
    pub cluster: i32,
    pub anchor: i32,
    pub name: Option<Name>,
}

/// Where an encoder answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Cluster(i32),
    Anchor(i32),
}

pub struct Model {
    pub fingerprints: HashMap<String, Known>,
    pub encoder: Encoder,
    /// Search members: cluster (-1 unnamed), threshold, embedding.
    search: Vec<(i32, f32, [f32; EMB])>,
    clusters: HashMap<i32, Name>,
    anchors: Vec<(Name, f32, [f32; EMB])>,
}

#[derive(Deserialize)]
struct Meta {
    feature_version: u32,
    opt_vocab: Vec<String>,
    files: HashMap<String, FileMeta>,
}

#[derive(Deserialize)]
struct FileMeta {
    sha256: String,
}

fn err(reason: impl Into<String>) -> String {
    reason.into()
}

impl Model {
    /// `meta` is the bundle's `meta.json`; the other files sit beside it.
    pub fn load(meta_path: &Path) -> Result<Self, String> {
        let dir = meta_path.parent().unwrap_or(Path::new("."));
        let read = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|e| err(format!("{}: {e}", dir.join(name).display())))
        };
        let meta: Meta = serde_json::from_slice(&read(
            meta_path.file_name().and_then(|n| n.to_str()).unwrap_or("meta.json"),
        )?)
        .map_err(|e| err(format!("meta.json: {e}")))?;
        if meta.feature_version != 3 || meta.opt_vocab != OPT_VOCAB {
            return Err(err(format!(
                "feature version {} / option vocabulary {:?} is not the one this adapter implements (3, {OPT_VOCAB:?})",
                meta.feature_version, meta.opt_vocab
            )));
        }

        let mut files: HashMap<&str, Vec<u8>> = HashMap::new();
        for name in ["fingerprints.tsv", "search.tsv", "anchors.tsv", "clusters.tsv", "encoder.bin", "encoder.yaml"] {
            let bytes = read(name)?;
            let expected = meta
                .files
                .get(name)
                .ok_or_else(|| err(format!("meta.json lists no sha256 for {name}")))?;
            let actual: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
            if actual != expected.sha256 {
                return Err(err(format!("{name}: sha256 {actual}, meta.json says {}", expected.sha256)));
            }
            files.insert(name, bytes);
        }
        let text = |name: &str| String::from_utf8_lossy(&files[name]).into_owned();

        let fingerprints = parse_fingerprints(&text("fingerprints.tsv"))?;
        let clusters = rows(&text("clusters.tsv"))
            .map(|(line, f)| {
                let c = int(f.first().copied(), line)?;
                let name = Name::parse(f.get(1).copied().unwrap_or("-"), f.get(2).copied().unwrap_or("-"))
                    .ok_or_else(|| err(format!("clusters.tsv:{line}: a cluster listed without a family")))?;
                Ok((c, name))
            })
            .collect::<Result<_, String>>()?;
        let search = rows(&text("search.tsv"))
            .map(|(line, f)| {
                Ok((int(f.first().copied(), line)?, float(f.get(1).copied(), line)?, embedding(&f[2..], line)?))
            })
            .collect::<Result<_, String>>()?;
        let anchors = rows(&text("anchors.tsv"))
            .map(|(line, f)| {
                let name = Name::parse(f.get(1).copied().unwrap_or("-"), f.get(2).copied().unwrap_or("-"))
                    .ok_or_else(|| err(format!("anchors.tsv:{line}: an anchor without a family")))?;
                Ok((name, float(f.get(3).copied(), line)?, embedding(&f[4..], line)?))
            })
            .collect::<Result<_, String>>()?;
        let encoder = Encoder::load(&files["encoder.bin"], &text("encoder.yaml"))?;

        Ok(Self {
            fingerprints,
            encoder,
            search,
            clusters,
            anchors,
        })
    }

    /// The thesis's "closest known OS" hint (`evaluate.py`, `closest_known`):
    /// for a tuple nothing named, the family of the nearest member of a named
    /// cluster — `skip` families (reference-only names such as `scanner`)
    /// left out — if it is within `max` (`hint_thresholds.json`).
    pub fn hint(&self, e: &[f32; EMB], max: f32, skip: &[String]) -> Option<(&str, f32)> {
        let mut best: Option<(f32, &str)> = None;
        for (c, _, m) in &self.search {
            let Some(name) = self.clusters.get(c) else { continue };
            if skip.contains(&name.family) {
                continue;
            }
            let d2: f32 = e.iter().zip(m).map(|(a, b)| (a - b) * (a - b)).sum();
            if best.map_or(true, |(bd, _)| d2 < bd) {
                best = Some((d2, &name.family));
            }
        }
        best.map(|(d2, f)| (f, d2.sqrt())).filter(|&(_, d)| d <= max)
    }

    /// Nearest search member; its cluster if within that member's threshold
    /// and named. Otherwise the nearest anchor within its threshold.
    pub fn classify(&self, e: &[f32; EMB]) -> Option<(Hit, &Name)> {
        let cluster = nearest(self.search.iter().map(|(c, t, m)| (*c, *t, m)), e)
            .filter(|&c| c >= 0)
            .and_then(|c| self.clusters.get(&c).map(|n| (Hit::Cluster(c), n)));
        cluster.or_else(|| {
            nearest(self.anchors.iter().enumerate().map(|(i, (_, t, m))| (i as i32, *t, m)), e)
                .map(|i| (Hit::Anchor(i), &self.anchors[i as usize].0))
        })
    }
}

/// Label of the nearest member, if the query is within that member's
/// threshold.
fn nearest<'a>(members: impl Iterator<Item = (i32, f32, &'a [f32; EMB])>, q: &[f32; EMB]) -> Option<i32> {
    let mut best: Option<(f32, i32, f32)> = None;
    for (label, thr, m) in members {
        let d2: f32 = q.iter().zip(m).map(|(a, b)| (a - b) * (a - b)).sum();
        if best.map_or(true, |(bd, _, _)| d2 < bd) {
            best = Some((d2, label, thr));
        }
    }
    best.and_then(|(d2, label, thr)| (d2.sqrt() <= thr).then_some(label))
}

fn rows(text: &str) -> impl Iterator<Item = (usize, Vec<&str>)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#') && !l.trim().is_empty())
        .map(|(i, l)| (i + 1, l.split('\t').collect()))
}

fn int(field: Option<&str>, line: usize) -> Result<i32, String> {
    field
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err(format!("line {line}: expected an integer")))
}

fn float(field: Option<&str>, line: usize) -> Result<f32, String> {
    field
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err(format!("line {line}: expected a number")))
}

fn embedding(fields: &[&str], line: usize) -> Result<[f32; EMB], String> {
    if fields.len() != EMB {
        return Err(err(format!("line {line}: {} embedding values, expected {EMB}", fields.len())));
    }
    let mut e = [0f32; EMB];
    for (slot, f) in e.iter_mut().zip(fields) {
        *slot = float(Some(f), line)?;
    }
    Ok(e)
}

fn parse_fingerprints(text: &str) -> Result<HashMap<String, Known>, String> {
    rows(text)
        .map(|(line, f)| {
            if f.len() < 5 {
                return Err(err(format!("fingerprints.tsv:{line}: {} fields, expected 7", f.len())));
            }
            let known = Known {
                cluster: int(Some(f[1]), line)?,
                anchor: int(Some(f[2]), line)?,
                name: Name::parse(f[3], f[4]),
            };
            Ok((f[0].to_string(), known))
        })
        .collect()
}

// ---------------------------------------------------------------- encoder

#[derive(Deserialize)]
struct Layout {
    floats: usize,
    tensors: Vec<TensorMeta>,
}

#[derive(Deserialize)]
struct TensorMeta {
    name: String,
    shape: Vec<usize>,
    offset: usize,
}

/// Row-major `[out, in]` weight and its bias: `y = x W^T + b`.
struct Linear {
    w: Vec<f32>,
    b: Vec<f32>,
    out: usize,
    inp: usize,
}

impl Linear {
    fn apply(&self, x: &[f32], y: &mut [f32]) {
        debug_assert_eq!((x.len(), y.len()), (self.inp, self.out));
        for (o, y) in y.iter_mut().enumerate() {
            let row = &self.w[o * self.inp..(o + 1) * self.inp];
            *y = self.b[o] + row.iter().zip(x).map(|(w, x)| w * x).sum::<f32>();
        }
    }
}

/// The contrastive encoder (`train_encoder.py`, `Encoder`): option embeddings
/// through a one-layer GRU, its state after the last real option joined with
/// the categorical embeddings and the numbers, then a 68-128-128-32 ReLU
/// trunk, L2-normalised.
pub struct Encoder {
    opt_emb: Vec<f32>,
    /// `[3H, in]` and `[3H, H]`, gates in PyTorch's order r, z, n.
    w_ih: Linear,
    w_hh: Linear,
    cat_embs: [Vec<f32>; N_CAT],
    trunk: [Linear; 3],
}

impl Encoder {
    fn load(bin: &[u8], yaml: &str) -> Result<Self, String> {
        let layout: Layout = serde_yaml::from_str(yaml).map_err(|e| err(format!("encoder.yaml: {e}")))?;
        if bin.len() != layout.floats * 4 {
            return Err(err(format!("encoder.bin is {} bytes, encoder.yaml says {} floats", bin.len(), layout.floats)));
        }
        let floats: Vec<f32> = bin
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let tensor = |name: &str, shape: &[usize]| -> Result<Vec<f32>, String> {
            let t = layout
                .tensors
                .iter()
                .find(|t| t.name == name)
                .ok_or_else(|| err(format!("encoder.yaml has no tensor {name}")))?;
            if t.shape != shape {
                return Err(err(format!("{name}: shape {:?}, expected {shape:?}", t.shape)));
            }
            let n: usize = shape.iter().product();
            floats
                .get(t.offset..t.offset + n)
                .map(<[f32]>::to_vec)
                .ok_or_else(|| err(format!("{name} runs past the end of encoder.bin")))
        };
        let linear = |w: &str, b: &str, out: usize, inp: usize| -> Result<Linear, String> {
            Ok(Linear {
                w: tensor(w, &[out, inp])?,
                b: tensor(b, &[out])?,
                out,
                inp,
            })
        };
        let cat = |i: usize| tensor(&format!("cat_embs.{i}.weight"), &[CAT_DIMS[i].0, CAT_DIMS[i].1]);
        Ok(Self {
            opt_emb: tensor("opt_emb.weight", &[OPT_VOCAB.len(), GRU_IN])?,
            w_ih: linear("gru.weight_ih_l0", "gru.bias_ih_l0", 3 * GRU_H, GRU_IN)?,
            w_hh: linear("gru.weight_hh_l0", "gru.bias_hh_l0", 3 * GRU_H, GRU_H)?,
            cat_embs: [cat(0)?, cat(1)?, cat(2)?, cat(3)?],
            trunk: [
                linear("trunk.0.weight", "trunk.0.bias", HIDDEN, TRUNK_IN)?,
                linear("trunk.2.weight", "trunk.2.bias", HIDDEN, HIDDEN)?,
                linear("trunk.4.weight", "trunk.4.bias", EMB, HIDDEN)?,
            ],
        })
    }

    pub fn embed(&self, f: &Features) -> [f32; EMB] {
        // GRU over the real options only: the model reads its state after
        // the last of them, so the padding steps never matter.
        let sigmoid = |x: f32| 1.0 / (1.0 + (-x).exp());
        let mut h = [0f32; GRU_H];
        let (mut gi, mut gh) = ([0f32; 3 * GRU_H], [0f32; 3 * GRU_H]);
        for &tok in &f.opt_ids[..f.opt_len.clamp(1, MAX_OPTS)] {
            self.w_ih.apply(&self.opt_emb[tok * GRU_IN..(tok + 1) * GRU_IN], &mut gi);
            self.w_hh.apply(&h, &mut gh);
            for j in 0..GRU_H {
                let r = sigmoid(gi[j] + gh[j]);
                let z = sigmoid(gi[GRU_H + j] + gh[GRU_H + j]);
                let n = (gi[2 * GRU_H + j] + r * gh[2 * GRU_H + j]).tanh();
                h[j] = (1.0 - z) * n + z * h[j];
            }
        }

        let mut x = Vec::with_capacity(TRUNK_IN);
        x.extend_from_slice(&h);
        for (i, emb) in self.cat_embs.iter().enumerate() {
            let (rows, dim) = CAT_DIMS[i];
            let c = f.cats[i].min(rows - 1);
            x.extend_from_slice(&emb[c * dim..(c + 1) * dim]);
        }
        x.extend_from_slice(&f.nums);

        let mut a = [0f32; HIDDEN];
        let mut b = [0f32; HIDDEN];
        self.trunk[0].apply(&x, &mut a);
        a.iter_mut().for_each(|v| *v = v.max(0.0));
        self.trunk[1].apply(&a, &mut b);
        b.iter_mut().for_each(|v| *v = v.max(0.0));
        let mut e = [0f32; EMB];
        self.trunk[2].apply(&b, &mut e);

        // F.normalize: x / max(||x||, 1e-12)
        let norm = e.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-12);
        e.map(|v| v / norm)
    }
}
