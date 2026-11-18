//! Operator adapter packs (GR-OPR-002/006, Design Doc 0033).
//!
//! An adapter pack is a Tier-0 declarative CUE mapping that **supplies an
//! operator** (pinned install manifests for stage 02) and **synthesizes its
//! CR family** (stage 03) from the AmiSpec component model. Evaluation is a
//! pure function of (pack files, model): the pinned `cue` CLI exports `out`.
//!
//! Pack layout (catalog/adapters/<publisher>/<id>/rev<N>/):
//!   adapter.meta.yaml  — identity, CRD family, operator supply/requires
//!   *.cue              — model/map/names/status/defaults/reverse/roundtrip
//!   install/*.yaml     — vendored operator manifests (sha256-pinned in meta)
//!   fixtures/          — golden fixtures (see catalog/scripts/conformance.sh)

use crate::CompileError;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `adapter.meta.yaml` — identity + compatibility + operator supply.
#[derive(Debug, Clone, Deserialize)]
pub struct AdapterMeta {
    pub metadata: AdapterMetaIdentity,
    pub crd: AdapterCrd,
    #[serde(default)]
    pub operator: Option<AdapterOperator>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdapterMetaIdentity {
    #[serde(rename = "adapterRev")]
    pub adapter_rev: Option<u32>,
}

impl AdapterMetaIdentity {
    pub fn rev(&self) -> u32 {
        self.adapter_rev.unwrap_or(1)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdapterCrd {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AdapterOperator {
    #[serde(default)]
    pub supplies: Option<OperatorSupply>,
    #[serde(default)]
    pub requires: Vec<OperatorRequirement>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorSupply {
    pub name: String,
    pub install: InstallSpec,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorRequirement {
    pub name: String,
    pub install: InstallSpec,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallSpec {
    pub form: String,
    #[serde(default)]
    pub files: Vec<InstallFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallFile {
    pub path: String,
    pub sha256: String,
}

/// One adapter pack on disk.
#[derive(Debug, Clone)]
pub struct AdapterPack {
    /// `<publisher>/<id>`
    pub id: String,
    /// `rev<N>`
    pub rev: String,
    pub dir: PathBuf,
    pub meta: AdapterMeta,
    /// CUE package name declared by map.cue.
    pub package: String,
}

/// Evaluated output of one adapter pack for one component instance.
#[derive(Debug, Clone, Default)]
pub struct AdapterOutput {
    /// CR family docs (cluster + companions), deterministic order.
    pub docs: Vec<Value>,
    /// Service/secret names for bindings (`out.names`).
    pub names: BTreeMap<String, String>,
}

/// Index of adapter packs under `catalog/adapters/`.
#[derive(Debug, Default, Clone)]
pub struct AdapterIndex {
    packs: Vec<AdapterPack>,
}

impl AdapterIndex {
    /// Load every `<publisher>/<id>/rev<N>/` pack under `root`.
    pub fn load(root: &Path) -> Result<Self, CompileError> {
        let mut packs = Vec::new();
        if !root.exists() {
            return Ok(Self { packs });
        }
        for pub_dir in sorted_dirs(root) {
            let publisher = dir_name(&pub_dir);
            for id_dir in sorted_dirs(&pub_dir) {
                let id = dir_name(&id_dir);
                for rev_dir in sorted_dirs(&id_dir) {
                    let rev = dir_name(&rev_dir);
                    if !rev.starts_with("rev") {
                        continue;
                    }
                    let meta_path = rev_dir.join("adapter.meta.yaml");
                    let raw = fs::read_to_string(&meta_path).map_err(|e| {
                        CompileError::Generic(format!("adapter meta {}: {e}", meta_path.display()))
                    })?;
                    let meta: AdapterMeta = serde_yaml::from_str(&raw)
                        .map_err(|e| CompileError::Generic(format!("adapter meta: {e}")))?;
                    let package = package_of(&rev_dir)?;
                    packs.push(AdapterPack {
                        id: format!("{publisher}/{id}"),
                        rev: rev.clone(),
                        dir: rev_dir.clone(),
                        meta,
                        package,
                    });
                }
            }
        }
        Ok(Self { packs })
    }

    /// Resolve a `<publisher>/<id>@rev<N>` pin.
    pub fn resolve(&self, pin: &str) -> Option<&AdapterPack> {
        let (id, rev) = pin.split_once('@')?;
        self.packs.iter().find(|p| p.id == id && p.rev == rev)
    }
}

/// Parse the `package <name>` clause of map.cue.
fn package_of(dir: &Path) -> Result<String, CompileError> {
    let map = fs::read_to_string(dir.join("map.cue"))
        .map_err(|e| CompileError::Generic(format!("map.cue: {e}")))?;
    for line in map.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("package ") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(CompileError::Generic("map.cue: package clause not found".into()))
}

fn sorted_dirs(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(root)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && !dir_name(p).starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn dir_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
}

/// Locate the `cue` CLI (env `CUE_BIN`, PATH, or ~/.local/bin — same policy as
/// the CUE↔Rust contract tests).
fn cue_bin() -> String {
    if let Ok(b) = std::env::var("CUE_BIN") {
        return b;
    }
    for cand in ["cue", "/root/.local/bin/cue"] {
        if Command::new(cand).arg("version").output().map(|o| o.status.success()).unwrap_or(false) {
            return cand.to_string();
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let cand = format!("{home}/.local/bin/cue");
        if Path::new(&cand).exists() {
            return cand;
        }
    }
    "cue".to_string()
}

/// Evaluate one pack for one component model (pure function of pack + model).
pub fn evaluate(
    pack: &AdapterPack,
    model: &Value,
    work_dir: &Path,
) -> Result<AdapterOutput, CompileError> {
    fs::create_dir_all(work_dir)
        .map_err(|e| CompileError::Generic(format!("adapter workdir: {e}")))?;
    let model_cue = work_dir.join(format!("model-{}.cue", dir_name(&pack.dir)));
    let body = format!(
        "package {}\n\nmodel: {}\n",
        pack.package,
        to_cue_literal(model)
    );
    fs::write(&model_cue, &body)
        .map_err(|e| CompileError::Generic(format!("model.cue: {e}")))?;

    let mut files: Vec<PathBuf> = fs::read_dir(&pack.dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "cue").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files.push(model_cue.clone());

    let mut cmd = Command::new(cue_bin());
    cmd.arg("export");
    for f in &files {
        cmd.arg(f);
    }
    cmd.args(["-e", "out", "--out", "json"]);
    let out = cmd.output().map_err(|e| {
        CompileError::Generic(format!("cue export (adapter {}): {e}", pack.id))
    })?;
    let _ = fs::remove_file(&model_cue);
    if !out.status.success() {
        return Err(CompileError::Generic(format!(
            "cue export (adapter {}): {}",
            pack.id,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| CompileError::Generic(format!("adapter output json: {e}")))?;

    let mut docs = Vec::new();
    let obj = v.as_object().cloned().unwrap_or_default();
    for key in ["cluster", "pooler"] {
        if let Some(d) = obj.get(key) {
            if !d.is_null() {
                docs.push(d.clone());
            }
        }
    }
    if let Some(backup) = obj.get("backup").and_then(|b| b.as_object()) {
        for key in ["objectStore", "scheduledBackup"] {
            if let Some(d) = backup.get(key) {
                if !d.is_null() {
                    docs.push(d.clone());
                }
            }
        }
    }
    let names = obj
        .get("names")
        .and_then(|n| n.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(AdapterOutput { docs, names })
}

/// JSON → CUE literal (JSON object syntax is valid CUE for our value domain).
fn to_cue_literal(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "{}".into())
}

/// Operator install artifacts of a pack, ordered requirements-first, with
/// sha256 integrity verification (GR-OPR-006 supply chain).
pub fn operator_installs(pack: &AdapterPack) -> Result<Vec<(String, String)>, CompileError> {
    let mut out = Vec::new();
    let op = pack.meta.operator.as_ref();
    let mut specs: Vec<(String, &InstallSpec)> = Vec::new();
    if let Some(op) = op {
        for r in &op.requires {
            specs.push((r.name.clone(), &r.install));
        }
        if let Some(s) = &op.supplies {
            specs.push((s.name.clone(), &s.install));
        }
    }
    for (name, spec) in specs {
        for f in &spec.files {
            let path = pack.dir.join(&f.path);
            let bytes = fs::read(&path).map_err(|e| {
                CompileError::Generic(format!("operator install {} ({}): {e}", f.path, pack.id))
            })?;
            let mut h = Sha256::new();
            h.update(&bytes);
            let digest = format!("sha256:{:x}", h.finalize());
            if digest != format!("sha256:{}", f.sha256) {
                return Err(CompileError::Generic(format!(
                    "operator install {} ({}): digest mismatch (expected sha256:{})",
                    f.path, pack.id, f.sha256
                )));
            }
            out.push((
                name.clone(),
                String::from_utf8(bytes).map_err(|_| {
                    CompileError::Generic(format!("operator install {}: not UTF-8", f.path))
                })?,
            ));
        }
    }
    Ok(out)
}

/// JSON map helper: insert into a serde_json object.
pub fn json_set(map: &mut Map<String, Value>, key: &str, v: Value) {
    map.insert(key.to_string(), v);
}
