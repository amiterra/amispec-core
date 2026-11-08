//! Deployment bundle contract (Design Doc 0026 §1.1–1.3).
//!
//! The bundle is the unit of delivery: it is simultaneously the *source*
//! (catalog pins + `topology.yaml` — why the world looks like this) and the
//! *result* (the compiled stage tree — what Flux applies), joined by the
//! deterministic compiler. Anyone holding the bundle can re-verify it by
//! recompiling `catalog + topology` and comparing [`Bundle::tree_hash`].
//!
//! ```text
//! catalog/<id>/rev<N>.yaml          # passport pins (content + sha256)
//! clusters/<id>/topology.yaml       # TopologyBlueprint — source of truth
//! clusters/<id>/01..06/…            # compiled stages (Flux input)
//! _intent/<change-id>.yaml          # audit journal (written at apply time)
//! ```
//!
//! `catalog/`, `topology.yaml` and `_intent/` are **never** referenced by the
//! compiled kustomizations — Flux sees only the stage tree.

use crate::passport::{PassportIndex, PassportSummary};
use crate::provenance::passport_pin;
use crate::{CompileError, GeneratedFile, Options, compile};
use amispec_schema::TopologyBlueprint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Prefix of every content hash this module emits.
pub const HASH_PREFIX: &str = "sha256:";

/// Content-addressed pin of one catalog passport (Design Doc 0026 §1.1).
///
/// Carries the exact catalog content — delivery bundles are self-contained
/// (`id@rev` + content + sha256) so a cluster reproduces offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPin {
    /// `metadata.id` of the passport.
    pub id: String,
    /// `metadata.version` of the passport.
    pub version: String,
    /// `metadata.passportRev` of the passport.
    pub rev: u32,
    /// `sha256:<hex>` of [`Self::content`].
    #[serde(rename = "sha256")]
    pub sha256: String,
    /// Repository path the pin is written to: `catalog/<id>/rev<N>.yaml`.
    pub path: String,
    /// Exact passport YAML (byte-for-byte the catalog content).
    pub content: String,
}

/// Meta-only view of a pin (audit journal, Design Doc 0026 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinMeta {
    pub id: String,
    pub version: String,
    pub rev: u32,
    #[serde(rename = "sha256")]
    pub sha256: String,
}

impl From<&CatalogPin> for PinMeta {
    fn from(p: &CatalogPin) -> Self {
        Self {
            id: p.id.clone(),
            version: p.version.clone(),
            rev: p.rev,
            sha256: p.sha256.clone(),
        }
    }
}

impl CatalogPin {
    /// Pin a passport document. Fails when the raw catalog content is unknown —
    /// pins are content-addressed, a synthesized document would break
    /// reproducibility.
    pub fn pin(summary: &PassportSummary, raw: &str) -> Self {
        Self {
            id: summary.id.clone(),
            version: summary.version.clone(),
            rev: summary.passport_rev,
            sha256: hash_content(raw),
            path: format!("catalog/{}/rev{}.yaml", summary.id, summary.passport_rev),
            content: raw.to_string(),
        }
    }

    /// `id@version-rev` identity line used in [`Bundle::schema_hash`].
    pub fn meta(&self) -> String {
        passport_pin(&self.id, &self.version, self.rev)
    }

    /// Integrity check: the hash must cover exactly this content.
    pub fn verify_content(&self) -> bool {
        hash_content(&self.content) == self.sha256
    }
}

/// A verified deployment bundle: sources + compiled tree + content hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Catalog pins for every passport referenced by the topology,
    /// sorted by `(id, rev)`.
    pub catalog: Vec<CatalogPin>,
    /// Canonical serialization of the `TopologyBlueprint`.
    pub topology_yaml: String,
    /// Repo path of the topology: `clusters/<id>/topology.yaml`.
    pub topology_path: String,
    /// The single cluster this bundle delivers (v1 contract: one cluster per
    /// bundle — multi-cluster blueprints are delivered per cluster).
    pub cluster_id: String,
    /// Compiled stage tree (Flux input), sorted by path.
    pub tree: Vec<GeneratedFile>,
    /// `sha256:<hex>` over the compiled tree — the review↔result binding
    /// (`expectedTreeHash` in the intent).
    pub tree_hash: String,
    /// `sha256:<hex>` over topology + resolved passport pins (Design 0021).
    pub schema_hash: String,
    /// Compiler/standard version that produced the bundle (skew detection).
    pub amispec_version: String,
}

impl Bundle {
    /// Every file the bundle contributes to the repository, sorted by path.
    ///
    /// The `_intent/` journal is appended at apply time by the agent and is
    /// deliberately **not** part of [`Self::tree_hash`] (the journal records
    /// the hash, it must not feed back into it).
    pub fn repo_files(&self) -> Vec<(&str, &str)> {
        let mut files: Vec<(&str, &str)> = Vec::new();
        for pin in &self.catalog {
            files.push((pin.path.as_str(), pin.content.as_str()));
        }
        files.push((self.topology_path.as_str(), self.topology_yaml.as_str()));
        for f in &self.tree {
            files.push((f.relative_path.as_str(), f.contents.as_str()));
        }
        files.sort_by(|a, b| a.0.cmp(b.0));
        files
    }

    /// Repo files as a map (path → content) for git writers.
    pub fn repo_tree(&self) -> BTreeMap<String, String> {
        self.repo_files()
            .into_iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .collect()
    }

    /// Compiled tree as `GeneratedFile` slice (Flux input only).
    pub fn flux_tree(&self) -> &[GeneratedFile] {
        &self.tree
    }
}

/// Bundle build failure.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error(transparent)]
    Compile(#[from] CompileError),
    #[error(
        "catalog pin requires passport content: `{passport}` is referenced by \
         the topology but not loaded with its raw document"
    )]
    MissingCatalogContent { passport: String },
    #[error(
        "delivery bundles carry exactly one cluster: topology has {count} \
         ({ids}); split the blueprint or select one cluster"
    )]
    NotSingleCluster { count: usize, ids: String },
    #[error("topology has no cluster `{cluster_id}` (has: {ids})")]
    UnknownCluster { cluster_id: String, ids: String },
    #[error("topology serialization failed: {0}")]
    Serialize(String),
}

/// Build the deployment bundle for one cluster (Design Doc 0026 §1.2).
///
/// Compiles the stage tree and assembles catalog pins + canonical
/// `topology.yaml`. Deterministic: identical inputs produce byte-identical
/// bundles (same `tree_hash`), which is the shared contract of preview and
/// apply (verify-don't-trust).
pub fn build_bundle(
    topology: &TopologyBlueprint,
    cluster_id: &str,
    passports: &PassportIndex,
    provenance: bool,
) -> Result<Bundle, BundleError> {
    if topology.clusters.len() != 1 {
        return Err(BundleError::NotSingleCluster {
            count: topology.clusters.len(),
            ids: topology
                .clusters
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    let cluster = &topology.clusters[0];
    if cluster.id != cluster_id {
        return Err(BundleError::UnknownCluster {
            cluster_id: cluster_id.to_string(),
            ids: cluster.id.clone(),
        });
    }

    // Catalog pins: every passport referenced by components, sorted by id.
    let mut pinned: BTreeMap<String, CatalogPin> = BTreeMap::new();
    for comp in &cluster.components {
        if pinned.contains_key(&comp.passport) {
            continue;
        }
        let summary =
            passports
                .get(&comp.passport)
                .ok_or_else(|| BundleError::MissingCatalogContent {
                    passport: comp.passport.clone(),
                })?;
        let raw =
            passports
                .raw_of(&comp.passport)
                .ok_or_else(|| BundleError::MissingCatalogContent {
                    passport: comp.passport.clone(),
                })?;
        pinned.insert(comp.passport.clone(), CatalogPin::pin(summary, raw));
    }
    // External resource passports are pinned when present (they do not affect
    // compilation but keep the bundle self-contained).
    for ext in &topology.external_resources {
        if pinned.contains_key(&ext.passport) {
            continue;
        }
        if let (Some(summary), Some(raw)) = (
            passports.get(&ext.passport),
            passports.raw_of(&ext.passport),
        ) {
            pinned.insert(ext.passport.clone(), CatalogPin::pin(summary, raw));
        }
    }
    let catalog: Vec<CatalogPin> = pinned.into_values().collect();

    let topology_yaml =
        serde_yaml::to_string(topology).map_err(|e| BundleError::Serialize(e.to_string()))?;
    let topology_path = format!("clusters/{cluster_id}/topology.yaml");

    // Compiled tree (the same deterministic projection `ami compile` writes).
    let opts = Options::dry();
    let opts = Options { provenance, ..opts };
    let result = compile(topology, passports, &opts)?;
    let mut tree = result.files;
    tree.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let tree_hash = hash_tree(&tree);
    let schema_hash = hash_schema(&topology_yaml, &catalog);

    Ok(Bundle {
        catalog,
        topology_yaml,
        topology_path,
        cluster_id: cluster_id.to_string(),
        tree,
        tree_hash,
        schema_hash,
        amispec_version: crate::bundle_version(),
    })
}

/// `sha256:<hex>` of raw catalog content.
pub fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{HASH_PREFIX}{:x}", hasher.finalize())
}

/// Canonical content hash of a compiled tree: sha256 over
/// `path \0 content \0` in sorted path order (byte-stable across runs and
/// platforms — no map iteration order leaks in).
pub fn hash_tree(tree: &[GeneratedFile]) -> String {
    let mut sorted: Vec<&GeneratedFile> = tree.iter().collect();
    sorted.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    let mut hasher = Sha256::new();
    for f in sorted {
        hasher.update(f.relative_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(f.contents.as_bytes());
        hasher.update(b"\0");
    }
    format!("{HASH_PREFIX}{:x}", hasher.finalize())
}

/// Schema hash (Design 0021): canonical topology + resolved passport pins.
pub fn hash_schema(topology_yaml: &str, catalog: &[CatalogPin]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(topology_yaml.as_bytes());
    hasher.update(b"\0");
    for pin in catalog {
        hasher.update(pin.meta().as_bytes());
        hasher.update(b"\0");
    }
    format!("{HASH_PREFIX}{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPOLOGY: &str = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
clusters:
  - id: c0
    name: Demo
    domain: example.io
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        pricingTier: standard-node
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    loadBalancers:
      - { id: main-l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: main-l7, scope: public, hostname: app.example.io }
      - id: db
        passport: postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: standalone }
        resources: { cpuCores: 2, memoryMb: 2048 }
    bindings:
      - { from: web, to: db, toSlot: sql-cluster, asRequirement: database }
"#;

    const WEB_PASSPORT: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: stateless-app, name: Web, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: web, protocol: http, containerPort: 8080, role: ui, defaultScope: public }
  provides: []
  requires: {}
"#;

    const DB_PASSPORT: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: postgresql, name: PG, version: "18.0.0", passportRev: 6, category: database, archetype: operator-cluster }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - { slot: sql-cluster, capability: postgres-sql, version: "18.0.0" }
  requires: {}
"#;

    fn catalog() -> PassportIndex {
        let mut idx = PassportIndex::new();
        idx.insert_document(WEB_PASSPORT).unwrap();
        idx.insert_document(DB_PASSPORT).unwrap();
        idx
    }

    fn bundle() -> Bundle {
        let topo = amispec_schema::parse_topology(TOPOLOGY).unwrap();
        build_bundle(&topo, "c0", &catalog(), true).unwrap()
    }

    #[test]
    fn bundle_layout_has_catalog_topology_and_tree() {
        let b = bundle();
        assert_eq!(b.cluster_id, "c0");
        assert_eq!(b.catalog.len(), 2);
        assert_eq!(b.catalog[0].id, "postgresql");
        assert_eq!(b.catalog[0].path, "catalog/postgresql/rev6.yaml");
        assert_eq!(b.catalog[1].path, "catalog/stateless-app/rev1.yaml");
        assert_eq!(b.topology_path, "clusters/c0/topology.yaml");
        assert!(b.topology_yaml.contains("kind: TopologyBlueprint"));
        assert!(
            b.tree
                .iter()
                .any(|f| f.relative_path.contains("05-applications"))
        );
        let paths: Vec<&str> = b.repo_files().iter().map(|(p, _)| *p).collect();
        assert!(paths.contains(&"catalog/postgresql/rev6.yaml"));
        assert!(paths.contains(&"clusters/c0/topology.yaml"));
        // repo files are sorted → deterministic writer input
        assert!(paths.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn tree_hash_is_stable_and_content_sensitive() {
        let a = bundle();
        let b = bundle();
        assert_eq!(a.tree_hash, b.tree_hash);
        assert!(a.tree_hash.starts_with("sha256:"));
        assert_eq!(a.schema_hash, b.schema_hash);

        // passport contract change (endpoint port) flips tree_hash — the
        // review↔result binding must notice content drift
        let mut idx = catalog();
        idx.insert_document(&WEB_PASSPORT.replace("8080", "8081"))
            .unwrap();
        let topo = amispec_schema::parse_topology(TOPOLOGY).unwrap();
        let c = build_bundle(&topo, "c0", &idx, true).unwrap();
        assert_ne!(a.tree_hash, c.tree_hash);

        // schema_hash covers topology + pin identity (id@version-rev, 0021):
        // a topology change flips it
        let topo2 = amispec_schema::parse_topology(
            &TOPOLOGY.replace("hostname: app.example.io", "hostname: other.example.io"),
        )
        .unwrap();
        let d = build_bundle(&topo2, "c0", &catalog(), true).unwrap();
        assert_ne!(a.schema_hash, d.schema_hash);
    }

    #[test]
    fn tree_hash_covers_compiled_tree_only() {
        let a = bundle();
        // recomputing over the same tree reproduces the hash
        assert_eq!(hash_tree(&a.tree), a.tree_hash);
    }

    #[test]
    fn kustomizations_never_reference_sources() {
        let b = bundle();
        for f in &b.tree {
            if f.relative_path.ends_with("kustomization.yaml") {
                assert!(
                    !f.contents.contains("topology.yaml"),
                    "{} references topology.yaml",
                    f.relative_path
                );
                assert!(
                    !f.contents.contains("catalog/"),
                    "{} references catalog/",
                    f.relative_path
                );
            }
        }
    }

    #[test]
    fn missing_catalog_content_fails_fast() {
        let mut idx = PassportIndex::new();
        let mut summary = PassportSummary::from_passport_yaml(WEB_PASSPORT).unwrap();
        summary.id = "stateless-app".into();
        idx.insert(summary);
        let topo = amispec_schema::parse_topology(TOPOLOGY).unwrap();
        let err = build_bundle(&topo, "c0", &idx, true).unwrap_err();
        assert!(
            matches!(err, BundleError::MissingCatalogContent { .. }),
            "{err}"
        );
    }

    #[test]
    fn multi_cluster_topology_is_rejected() {
        let yaml = TOPOLOGY.replace(
            "    bindings:\n      - { from: web, to: db, toSlot: sql-cluster, asRequirement: database }",
            "    bindings: []\n  - id: c1\n    name: Other\n    domain: other.io\n    security: { sopsRecipients: [age1abc123] }\n    cni: { engine: cilium-ebpf, clusterMeshId: 2 }\n    nodes: []\n    components: []",
        );
        let topo = amispec_schema::parse_topology(&yaml).unwrap();
        let err = build_bundle(&topo, "c0", &catalog(), true).unwrap_err();
        assert!(matches!(err, BundleError::NotSingleCluster { .. }), "{err}");
    }

    #[test]
    fn catalog_pins_roundtrip_serialization() {
        let b = bundle();
        let pin = &b.catalog[0];
        let yaml = serde_yaml::to_string(pin).unwrap();
        assert!(yaml.contains("sha256:"));
        assert!(
            yaml.contains("content"),
            "pins are self-contained: id@rev + content + hash"
        );
        let back: CatalogPin = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(&back, pin);
        assert!(pin.verify_content());

        // meta-only view for the audit journal
        let meta = PinMeta::from(pin);
        assert_eq!(meta.sha256, pin.sha256);
        let myaml = serde_yaml::to_string(&meta).unwrap();
        assert!(!myaml.contains("content"));
    }
}
