//! AmiSpec compiler: passports + topology → k3s / FluxCD tree, with reverse decompile.
//!
//! # Forward compile
//!
//! Deterministic projection of one `TopologyBlueprint` (+ optional passport
//! catalog) into the seven-stage GitOps hierarchy from the AmiSpec spec:
//!
//! ```text
//! clusters/<id>/
//!   flux-system/
//!   01-node-tuning/
//!   02-operators-and-networking/
//!   03-stateful-clusters/
//!   04a-provisioners-day2/
//!   04b-app-migrations-expand/
//!   05-applications/
//!   06-zero-trust-and-observability/
//! ```
//!
//! Every object carries Provenance labels (`amispec.io/*`) so compilation is
//! reversible via [`decompile`].
//!
//! # Reverse decompile
//!
//! [`decompile`] walks a generated tree (or any tree carrying AmiSpec
//! provenance) and rebuilds a `TopologyBlueprint` — lossless round-trip for
//! trees produced by this crate.

pub mod bundle;
mod decompile;
pub mod exposure;
mod manifest;
mod passport;
mod provenance;

pub use bundle::{Bundle, BundleError, CatalogPin, PinMeta, build_bundle};
pub use decompile::{DecompileReport, decompile, decompile_dir};
pub use exposure::{
    ExposureArtifacts, ResolvedExposure, TlsStrategy, materialize, resolve_exposures,
};
pub use passport::{
    ClientSidecar, PassportIndex, PassportSummary, ProbeDecl, ScriptSummary, SidecarListener,
};
pub use provenance::*;

pub use amispec_schema::PassportEndpoint;

/// Default StorageClass for stateful data volumes (platform contract
/// `storage-class-local`, Design Doc 0027): the SC `ami init` creates on the
/// host data root. Overridable per topology later; a single name keeps the
/// declared = enforced story simple for now.
pub const DEFAULT_STORAGE_CLASS: &str = "amiterra-local";

/// Version stamped into deployment bundles (preview↔apply skew detection).
/// Bumped together with incompatible changes to the compiled tree contract.
pub fn bundle_version() -> String {
    format!(
        "amispec-compile/{}+{}",
        env!("CARGO_PKG_VERSION"),
        amispec_schema::AMISPEC_STANDARD_VERSION
    )
}

use amispec_schema::TopologyBlueprint;
use manifest::Builder;

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Compiler options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Output root directory (created unless `dry_run`).
    pub out_dir: PathBuf,
    /// Write Provenance labels (default true).
    pub provenance: bool,
    /// Compute artifacts without writing to disk.
    pub dry_run: bool,
    /// Catalog `adapters/` root (operator adapter packs, GR-OPR-006).
    pub adapter_dir: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("out"),
            provenance: true,
            dry_run: false,
            adapter_dir: None,
        }
    }
}

impl Options {
    pub fn dry() -> Self {
        Self {
            dry_run: true,
            ..Default::default()
        }
    }
}

/// One generated file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub relative_path: String,
    pub contents: String,
}

/// Compile result summary.
#[derive(Debug, Default)]
pub struct CompileResult {
    pub files: Vec<GeneratedFile>,
    pub cluster_ids: Vec<String>,
    pub component_ids: Vec<String>,
    pub object_count: usize,
    /// Non-fatal notes (documented enforcement gaps, prereq checklists).
    pub warnings: Vec<String>,
}

/// Compile topology (+ passports) into a FluxCD-oriented manifest tree.
pub fn compile(
    topology: &TopologyBlueprint,
    passports: &PassportIndex,
    opts: &Options,
) -> Result<CompileResult, CompileError> {
    if topology.clusters.is_empty() {
        return Err(CompileError::EmptyClusters);
    }

    let mut result = CompileResult::default();
    let mut b = Builder::new(opts.provenance);

    for cluster in &topology.clusters {
        result.cluster_ids.push(cluster.id.clone());
        let root = format!("clusters/{}", cluster.id);

        // --- operator adapters (GR-OPR-002/006): supply operators (stage 02)
        // and synthesize the CR family (stage 03) via the pinned packs ---
        let adapters = match &opts.adapter_dir {
            Some(d) => Some(adapter::AdapterIndex::load(d)?),
            None => None,
        };
        let mut adapter_outputs: BTreeMap<String, adapter::AdapterOutput> = BTreeMap::new();
        let mut operator_installs: BTreeMap<String, String> = BTreeMap::new();
        for comp in &cluster.components {
            let Some(ps) = passports.get(&comp.passport) else { continue };
            let Some(ospec) = &ps.operator_spec else { continue };
            let Some(index) = adapters.as_ref() else {
                return Err(CompileError::Generic(format!(
                    "component `{}` uses engine operator-crd but Options::adapter_dir is not set",
                    comp.id
                )));
            };
            let Some(pack) = index.resolve(&ospec.adapter) else {
                return Err(CompileError::Generic(format!(
                    "component `{}`: adapter pin `{}` not found under the adapter catalog",
                    comp.id, ospec.adapter
                )));
            };
            let model = build_adapter_model(comp, ps, cluster)?;
            let out = adapter::evaluate(
                pack,
                &model,
                &std::env::temp_dir().join("amispec-adapter-work"),
            )?;
            adapter_outputs.insert(comp.id.clone(), out);
            for (op_name, raw) in adapter::operator_installs(pack)? {
                operator_installs.entry(op_name).or_insert(raw);
            }
        }
        // Service-name derivation for bindings (GR-OPR-002): adapter names for
        // operator providers, canonical `<component-id>` for k8s-native ones.
        let mut provider_names: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for comp in &cluster.components {
            let mut m = adapter_outputs
                .get(&comp.id)
                .map(|o| o.names.clone())
                .unwrap_or_default();
            m.entry("service".into()).or_insert_with(|| comp.id.clone());
            m.entry("rw".into()).or_insert_with(|| comp.id.clone());
            m.entry("ro".into()).or_insert_with(|| format!("{}-ro", comp.id));
            m.entry("pooler".into()).or_insert_with(|| format!("{}-pooler-rw", comp.id));
            provider_names.insert(comp.id.clone(), m);
        }

        // --- 00 flux-system ---
        // Seed-owned (ami gitops bootstrap, Design Doc 0026 §1.3): the compiled
        // tree must never overwrite `flux-system/` — it holds gotk-sync.yaml,
        // and clobbering it would silently break (or prune) the Git binding.
        // The root kustomization still references the directory.

        // --- 01 node-tuning ---
        let mut tuning_docs: Vec<Value> = Vec::new();
        for node in &cluster.nodes {
            tuning_docs.push(node_tuning_profile(&cluster.id, node));
        }
        b.docs(
            &format!("{root}/01-node-tuning/crd.yaml"),
            &[node_tuning_crd()],
        );
        b.docs(
            &format!("{root}/01-node-tuning/profiles.yaml"),
            &tuning_docs,
        );
        b.kustomization(
            &format!("{root}/01-node-tuning/kustomization.yaml"),
            &["crd.yaml", "profiles.yaml"],
        );

        // --- 02 operators & networking ---
        // Exposure pipeline (Design Doc 0025): zero balancing objects when the
        // cluster declares no expose[] (headless baseline invariant).
        let exposures = exposure::resolve_exposures(cluster, passports)?;
        let artifacts = exposure::materialize(cluster, &exposures, opts.provenance)?;
        result.warnings.extend(artifacts.warnings.iter().cloned());

        // NodeTuning readiness is applied by the node agent; we also emit a
        // placeholder Kustomization-visible ConfigMap of cluster CNI settings.
        let net_docs = vec![cni_config_map(&cluster.id, cluster)];
        b.docs(
            &format!("{root}/02-operators-and-networking/networking.yaml"),
            &net_docs,
        );
        let mut net_resources_owned: Vec<String> = vec!["networking.yaml".to_string()];
        for (op_name, raw) in &operator_installs {
            let fname = format!("operator-{}.yaml", op_name.replace('.', "-"));
            b.raw(&format!("{root}/02-operators-and-networking/{fname}"), raw);
            net_resources_owned.push(fname);
        }
        let mut net_resources: Vec<&str> = net_resources_owned.iter().map(|s| s.as_str()).collect();
        if !artifacts.activation.is_empty() {
            b.docs(
                &format!("{root}/02-operators-and-networking/balancer-activation.yaml"),
                &artifacts.activation,
            );
            net_resources_owned.push("balancer-activation.yaml".into());
            net_resources = net_resources_owned.iter().map(|s| s.as_str()).collect();
        }
        if !artifacts.gateways.is_empty() {
            b.docs(
                &format!("{root}/02-operators-and-networking/gateways.yaml"),
                &artifacts.gateways,
            );
            net_resources_owned.push("gateways.yaml".into());
            net_resources = net_resources_owned.iter().map(|s| s.as_str()).collect();
        }
        b.kustomization(
            &format!("{root}/02-operators-and-networking/kustomization.yaml"),
            &net_resources,
        );

        // --- 03 / 05 split stateful vs stateless ---
        let mut stateful_docs = Vec::new();
        let mut app_docs = Vec::new();
        let mut pdb_docs = Vec::new();
        let mut hpa_docs = Vec::new();
        // Adapter CR family (operator-crd components) — stage 03 product core.
        let mut cr_docs = Vec::new();
        // Internal Services (k8s-native providers) + script/token ConfigMaps.
        let mut svc_docs = Vec::new();
        let mut cm_docs = Vec::new();
        let mut pvc_docs = Vec::new();

        for comp in &cluster.components {
            result.component_ids.push(comp.id.clone());
            let passport = passports.get(&comp.passport);
            let pin = passport_pin(&comp.passport, &comp.version, comp.passport_rev);

            // GR-IMG-001 / GR-VER-004: every component resolves to a real
            // image (override or passport) — the legacy `<id>:<version>`
            // fallback is forbidden.
            let resolved_image = comp
                .workload_override
                .as_ref()
                .and_then(|w| w.image.clone())
                .or_else(|| passport.and_then(|p| p.image.clone()));
            let Some(resolved_image) = resolved_image else {
                return Err(CompileError::MissingImage(comp.id.clone()));
            };

            // user-spec-delta (lossless decompile of user values)
            let delta = user_spec_delta(comp);

            // operator-crd components: the adapter synthesized the CR family
            // (cluster/pooler/backup) — no local workload/PDB/HPA/Service.
            if let Some(out) = adapter_outputs.get(&comp.id) {
                cr_docs.extend(out.docs.iter().cloned());
                if let Some(ps) = passport {
                    cm_docs.extend(script_config_maps(comp, ps));
                    if let Some(cm) = exported_tokens_config_map(comp, ps) {
                        cm_docs.push(cm);
                    }
                }
                continue;
            }

            // Secrets (B3/ADR-0009): referenced by NAME from env/secrets —
            // the material is install-time (apply-secrets.sh / sops), never
            // placeholder objects in Git.

            // Script ConfigMaps (declared scripts) + exported token ConfigMap.
            if let Some(ps) = passport {
                cm_docs.extend(script_config_maps(comp, ps));
                if let Some(cm) = exported_tokens_config_map(comp, ps) {
                    cm_docs.push(cm);
                }
            }

            // Internal Service for non-exposed k8s-native providers
            // (exposed components get their Service from the exposure pipeline).
            if comp.expose.is_empty() {
                if let (Some(ps), Some(svc)) = (passport, passport.and_then(|p| endpoint_service(comp, p))) {
                    let _ = ps;
                    svc_docs.push(svc);
                }
            }

            // Workload object
            let sidecars = passport
                .map(|p| p.client_sidecars_for_mode(&comp.topology.mode))
                .unwrap_or_default();
            let sidecar_names: Vec<String> = sidecars.iter().map(|s| s.name.clone()).collect();

            // GR-OPR-002: StatefulSet iff engine says so.
            let stateful = passport.map(|p| p.engine == "k8s-statefulset").unwrap_or(false);
            let workload = workload_object(
                &cluster.id,
                comp,
                &pin,
                &delta,
                &sidecars,
                &sidecar_names,
                opts.provenance,
                cluster.maintenance_window.as_deref(),
                passport,
                cluster,
                &provider_names,
                &resolved_image,
                passports
                    .get(&comp.passport)
                    .and_then(|s| s.image_digest.as_deref()),
                stateful,
            );
            if stateful {
                stateful_docs.push(workload);
            } else {
                app_docs.push(workload);
                if let Some(pvc) = persistent_volume_claim(&cluster.id, comp, &pin, opts.provenance) {
                    pvc_docs.push(pvc);
                }
            }

            // PDB
            pdb_docs.push(pod_disruption_budget(
                &cluster.id,
                comp,
                &pin,
                opts.provenance,
            ));
            // HPA
            if let Some(hpa) = hpa_object(&cluster.id, comp, &pin, opts.provenance) {
                hpa_docs.push(hpa);
            }
            // expose[] is compiled by the exposure pipeline (stage 05 routes)
        }

        b.docs(
            &format!("{root}/03-stateful-clusters/stateful.yaml"),
            &stateful_docs,
        );
        // Adapter CR family (operator-crd product objects, GR-OPR-002).
        if !cr_docs.is_empty() {
            b.docs(&format!("{root}/03-stateful-clusters/crs.yaml"), &cr_docs);
        }
        let mut st_resources = vec!["stateful.yaml"];
        if !cr_docs.is_empty() {
            st_resources.push("crs.yaml");
        }
        b.kustomization(
            &format!("{root}/03-stateful-clusters/kustomization.yaml"),
            &st_resources,
        );

        // --- 04a provisioners (only for declared provider provisioners) ---
        b.docs(
            &format!("{root}/04a-provisioners-day2/jobs.yaml"),
            &provisioner_jobs(&cluster.id, topology, cluster, passports),
        );
        b.kustomization(
            &format!("{root}/04a-provisioners-day2/kustomization.yaml"),
            &["jobs.yaml"],
        );

        // --- 04b expand migrations (canonical Jobs, GR B5) ---
        b.docs(
            &format!("{root}/04b-app-migrations-expand/jobs.yaml"),
            &migration_jobs(&cluster.id, cluster, passports, &provider_names),
        );
        b.kustomization(
            &format!("{root}/04b-app-migrations-expand/kustomization.yaml"),
            &["jobs.yaml"],
        );

        // --- 05 applications ---
        b.docs(
            &format!("{root}/05-applications/namespaces.yaml"),
            &zone_namespaces(cluster, opts.provenance),
        );
        b.docs(&format!("{root}/05-applications/workloads.yaml"), &app_docs);
        b.docs(&format!("{root}/05-applications/pdb.yaml"), &pdb_docs);
        b.docs(&format!("{root}/05-applications/hpa.yaml"), &hpa_docs);
        b.docs(&format!("{root}/05-applications/services.yaml"), &svc_docs);
        b.docs(&format!("{root}/05-applications/configmaps.yaml"), &cm_docs);
        b.docs(&format!("{root}/05-applications/pvc.yaml"), &pvc_docs);
        b.docs(
            &format!("{root}/05-applications/routes.yaml"),
            &artifacts.routes,
        );
        b.kustomization(
            &format!("{root}/05-applications/kustomization.yaml"),
            &[
                "namespaces.yaml",
                "workloads.yaml",
                "pdb.yaml",
                "hpa.yaml",
                "services.yaml",
                "configmaps.yaml",
                "pvc.yaml",
                "routes.yaml",
            ],
        );

        // --- 06 zero-trust & observability (k8s-native components only) ---
        let native_comps: Vec<amispec_schema::ComponentInstance> = cluster
            .components
            .iter()
            .filter(|c| !adapter_outputs.contains_key(&c.id))
            .cloned()
            .collect();
        b.docs(
            &format!("{root}/06-zero-trust-and-observability/netpols.yaml"),
            &network_policies(&cluster.id, &native_comps, opts.provenance),
        );
        b.docs(
            &format!("{root}/06-zero-trust-and-observability/observability.yaml"),
            &observability_objects(&cluster.id, &native_comps, opts.provenance),
        );
        let mut trust_resources = vec!["netpols.yaml", "observability.yaml"];
        if !artifacts.edge_policies.is_empty() {
            b.docs(
                &format!("{root}/06-zero-trust-and-observability/edge-policies.yaml"),
                &artifacts.edge_policies,
            );
            trust_resources.push("edge-policies.yaml");
        }
        b.kustomization(
            &format!("{root}/06-zero-trust-and-observability/kustomization.yaml"),
            &trust_resources,
        );

        // root kustomization for the cluster
        b.kustomization(
            &format!("{root}/kustomization.yaml"),
            &[
                "flux-system",
                "01-node-tuning",
                "02-operators-and-networking",
                "03-stateful-clusters",
                "04a-provisioners-day2",
                "04b-app-migrations-expand",
                "05-applications",
                "06-zero-trust-and-observability",
            ],
        );
    }

    // bundle externalResources + cross-cluster links into a cluster-agnostic meta file
    b.docs(
        "clusters/_meta/external-resources.yaml",
        &external_resource_objects(topology, opts.provenance),
    );
    b.docs(
        "clusters/_meta/cross-cluster-links.yaml",
        &cross_cluster_objects(topology, opts.provenance),
    );
    b.kustomization(
        "clusters/_meta/kustomization.yaml",
        &["external-resources.yaml", "cross-cluster-links.yaml"],
    );

    result.files = b.finish();
    result.object_count = result
        .files
        .iter()
        .map(|f| f.contents.matches("\n---\n").count() + 1)
        .sum();

    if !opts.dry_run {
        write_files(&opts.out_dir, &result.files)?;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Manifest builders
// ---------------------------------------------------------------------------

/// `NodeTuningProfile` CRD — emitted with the tree so stage 01 is applyable
/// on a fresh cluster (the tuner daemon consumes the profiles; without the
/// CRD, Flux dry-run aborts the whole batch with "no matches for kind").
/// The profile payload is agent-defined: the schema stays open.
fn node_tuning_crd() -> Value {
    json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": "nodetuningprofiles.tuning.amispec.io",
            "labels": {
                LABEL_STAGE: "01-node-tuning",
            }
        },
        "spec": {
            "group": "tuning.amispec.io",
            "names": {
                "kind": "NodeTuningProfile",
                "listKind": "NodeTuningProfileList",
                "plural": "nodetuningprofiles",
                "singular": "nodetuningprofile",
            },
            "scope": "Cluster",
            "versions": [{
                "name": "v1alpha1",
                "served": true,
                "storage": true,
                "schema": {
                    "openAPIV3Schema": {
                        "type": "object",
                        "x-kubernetes-preserve-unknown-fields": true,
                    }
                }
            }]
        }
    })
}

fn node_tuning_profile(cluster_id: &str, node: &amispec_schema::Node) -> Value {
    let hw = &node.hardware;
    let sys_reserved = hw.system_reserved_mb.unwrap_or(1280);
    json!({
        "apiVersion": "tuning.amispec.io/v1alpha1",
        "kind": "NodeTuningProfile",
        "metadata": {
            "name": format!("{cluster_id}-{}", node.id),
            "labels": {
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_NODE_ID: node.id,
                LABEL_STAGE: "01-node-tuning",
            }
        },
        "spec": {
            "nodeSelector": { "kubernetes.io/hostname": node.id },
            "hardware": {
                "arch": hw.arch.clone().unwrap_or_else(|| "amd64".into()),
                "cpuCores": hw.cpu_cores,
                "memoryMb": hw.memory_mb,
                "systemReservedMb": sys_reserved,
                "systemDiskReservedGb": hw.system_disk_reserved_gb.unwrap_or(40),
                "lvmSnapshotReservePercent": hw.lvm_snapshot_reserve_percent.unwrap_or(10),
            },
            "disks": hw.disks.iter().map(|d| json!({
                "name": d.name,
                "tier": d.tier,
                "sizeGb": d.size_gb
            })).collect::<Vec<_>>(),
            "role": node.role,
            "failureDomainZone": node.failure_domain_zone.clone(),
        }
    })
}

fn cni_config_map(cluster_id: &str, cluster: &amispec_schema::Cluster) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("{cluster_id}-cni"),
            "namespace": "kube-system",
            "labels": {
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_STAGE: "02-operators-and-networking",
            }
        },
        "data": {
            "engine": cluster.cni.engine.clone(),
            "clusterMeshId": cluster.cni.cluster_mesh_id.to_string(),
            "fqdnCacheMinTtlSec": cluster.cni.fqdn_cache_min_ttl_sec.unwrap_or(3600).to_string(),
            "wireguardEncryption": cluster.cni.wireguard_encryption.unwrap_or(true).to_string(),
            "mtuDiscoveryAndMssClamp": cluster.cni.mtu_discovery_and_mss_clamp.unwrap_or(true).to_string(),
            // Deterministic CIDR formula from the spec
            "podCIDR": format!("10.{}.0.0/16", 100 + cluster.cni.cluster_mesh_id),
            "serviceCIDR": format!("10.{}.0.0/16", 200 + cluster.cni.cluster_mesh_id),
        }
    })
}

fn user_spec_delta(comp: &amispec_schema::ComponentInstance) -> Value {
    json!({
        "topology": {
            "mode": comp.topology.mode,
            "replicas": comp.topology.replicas,
            "committedReplicas": comp.topology.committed_replicas,
            "shards": comp.topology.shards,
        },
        "resources": {
            "cpuCores": comp.resources.cpu_cores,
            "memoryMb": comp.resources.memory_mb,
        },
        "config": comp.config.clone(),
        "zone": comp.zone,
        "group": comp.group,
        "backupTarget": comp.backup_target,
        "workloadOverride": comp.workload_override.as_ref().and_then(|w| w.image.as_ref().map(|_| serde_json::json!({
            "image": w.image
        }))),
    })
}

#[allow(clippy::too_many_arguments)]

// ---------------------------------------------------------------------------
// Operator-adapter model + binding resolution (GR-OPR-002/006, GR-CRED)
// ---------------------------------------------------------------------------

fn val_str(v: &serde_json::Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Bindings whose `to` is this component (its consumers).
fn incoming_bindings<'a>(
    cluster: &'a amispec_schema::Cluster,
    comp_id: &str,
) -> Vec<&'a amispec_schema::Binding> {
    let mut v: Vec<&amispec_schema::Binding> = cluster
        .bindings
        .iter()
        .filter(|b| b.to == comp_id)
        .collect();
    for c in &cluster.components {
        for b in &c.bindings {
            if b.to == comp_id {
                v.push(b);
            }
        }
    }
    v
}

/// Bindings owned by this component (its own requirements).
fn outgoing_bindings<'a>(
    cluster: &'a amispec_schema::Cluster,
    comp: &'a amispec_schema::ComponentInstance,
) -> Vec<&'a amispec_schema::Binding> {
    let mut v: Vec<&amispec_schema::Binding> = comp.bindings.iter().collect();
    for b in &cluster.bindings {
        if b.from.as_deref() == Some(comp.id.as_str()) {
            v.push(b);
        }
    }
    v
}

/// Internal service URL of a provider endpoint (name derivation contract:
/// Service = component id, namespace = provider zone).
fn provider_service_url(
    cluster: &amispec_schema::Cluster,
    provider_id: &str,
    endpoint: &str,
) -> String {
    let (zone, port) = cluster
        .components
        .iter()
        .find(|c| c.id == provider_id)
        .and_then(|c| {
            let zone = c.zone.clone().unwrap_or_else(|| "default".into());
            Some((zone, 0))
        })
        .unwrap_or_else(|| ("default".into(), 0));
    let _ = endpoint;
    let _ = port;
    format!("http://{provider_id}.{zone}.svc.cluster.local")
}

/// Model fed to the adapter pack (explicit carriers only — no hidden logic).
fn build_adapter_model(
    comp: &amispec_schema::ComponentInstance,
    ps: &PassportSummary,
    cluster: &amispec_schema::Cluster,
) -> Result<Value, CompileError> {
    let mut m = Map::new();
    m.insert("id".into(), json!(comp.id));
    m.insert("namespace".into(), json!(ns_of(comp)));
    m.insert("mode".into(), json!(comp.topology.mode));
    m.insert("replicas".into(), json!(comp.topology.replicas.unwrap_or(1)));

    let image = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image.clone())
        .or_else(|| ps.image.clone())
        .ok_or_else(|| CompileError::MissingImage(comp.id.clone()))?;
    let digest = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image_digest.clone())
        .or_else(|| ps.image_digest.clone())
        .ok_or_else(|| CompileError::MissingImage(comp.id.clone()))?;
    m.insert("image".into(), json!(image));
    m.insert("imageDigest".into(), json!(digest));

    let mut res = Map::new();
    // Whole-core values stay integers ("2", not "2.0") — CR quantity form.
    let cpu = comp.resources.cpu_cores;
    let cpu_json = if cpu.fract() == 0.0 {
        json!(cpu as i64)
    } else {
        json!(cpu)
    };
    res.insert("cpuCores".into(), cpu_json);
    res.insert("memoryMb".into(), json!(comp.resources.memory_mb));
    res.insert("hugepagesMb".into(), json!(ps.shm_size_mb.unwrap_or(0)));
    m.insert("resources".into(), Value::Object(res));

    // GUC parameters (`targetPath: postgresql.parameters.<guc>`): passport
    // defaults overlaid with topology config (declared = enforced).
    let mut cfg = Map::new();
    for (name, target) in &ps.param_target_paths {
        let Some(guc) = target.strip_prefix("postgresql.parameters.") else {
            continue;
        };
        let val = comp
            .config
            .as_ref()
            .and_then(|c| c.get(name))
            .cloned()
            .or_else(|| ps.param_defaults.get(name).cloned());
        if let Some(v) = val {
            cfg.insert(guc.to_string(), v);
        }
    }
    m.insert("config".into(), Value::Object(cfg));

    let cfg_str = |key: &str, default: &str| -> String {
        comp.config
            .as_ref()
            .and_then(|c| c.get(key))
            .map(val_str)
            .or_else(|| ps.param_defaults.get(key).map(val_str))
            .unwrap_or_else(|| default.to_string())
    };
    let data_size = comp.storage.as_ref().map(|s| s.size_gb).unwrap_or(8);
    let wal_size = comp
        .volumes
        .get("wal")
        .map(|v| v.size_gb)
        .unwrap_or(3);
    let mut vols = Map::new();
    let mut data = Map::new();
    data.insert(
        "class".into(),
        json!(comp
            .storage
            .as_ref()
            .and_then(|s| s.class.clone())
            .unwrap_or_default()),
    );
    data.insert("sizeGb".into(), json!(data_size));
    vols.insert("data".into(), Value::Object(data));
    let mut wal = Map::new();
    wal.insert(
        "class".into(),
        json!(comp
            .volumes
            .get("wal")
            .and_then(|v| v.class.clone())
            .unwrap_or_default()),
    );
    wal.insert("sizeGb".into(), json!(wal_size));
    vols.insert("wal".into(), Value::Object(wal));
    m.insert("volumes".into(), Value::Object(vols));

    // Consumption parameters (GR-OPR-005): per-binding, from consumers.
    let mut db = Map::new();
    let mut roles: Vec<Value> = Vec::new();
    for b in incoming_bindings(cluster, &comp.id) {
        let p = &b.params;
        let gp = |k: &str| p.get(k).map(val_str);
        if let Some(name) = gp("database") {
            db.insert("name".into(), json!(name));
            db.insert("owner".into(), json!(gp("deployRole").unwrap_or_default()));
            db.insert("ownerSecret".into(), json!(gp("deploySecret").unwrap_or_default()));
        }
        if let Some(rn) = gp("runtimeRole") {
            roles.push(json!({
                "name": rn,
                "secret": gp("runtimeSecret").unwrap_or_default(),
                "login": true
            }));
        }
    }
    if !db.is_empty() {
        m.insert("database".into(), Value::Object(db));
    }
    m.insert("managedRoles".into(), Value::Array(roles));

    m.insert("pooler".into(), json!({
        "enabled": true,
        "instances": cfg_str("poolerInstances", "2").parse::<u32>().unwrap_or(2),
    }));

    // Backup contract: passport operations.backup + own s3 binding params.
    let mut backup = Map::new();
    let enabled = comp.backup_target.is_some();
    backup.insert("enabled".into(), json!(enabled));
    if enabled {
        let bnd = outgoing_bindings(cluster, comp)
            .into_iter()
            .find(|b| b.params.contains_key("bucket"))
            .ok_or_else(|| CompileError::Generic(format!(
                "component `{}`: backupTarget set but no binding with params.bucket (GR-OPR-005)",
                comp.id
            )))?;
        let gp = |k: &str| bnd.params.get(k).map(val_str);
        let provider = bnd.to.clone();
        backup.insert("objectStoreName".into(), json!(gp("objectStore").unwrap_or_else(|| format!("{}-store", comp.id))));
        backup.insert("destinationPath".into(), json!(format!("s3://{}/", gp("bucket").unwrap_or_default())));
        backup.insert("endpointURL".into(), json!(format!("{}:8333", provider_service_url(cluster, &provider, "s3"))));
        backup.insert("s3Secret".into(), json!(gp("clientSecret").unwrap_or_default()));
        let bs = ps.backup.as_ref();
        backup.insert("schedule".into(), json!(bs.map(|b| b.default_cron.clone()).unwrap_or_else(|| "0 2 * * *".into())));
        backup.insert("retentionDays".into(), json!(bs.map(|b| b.retention_days).unwrap_or(30)));
    }
    m.insert("backup".into(), Value::Object(backup));

    // io_uring needs an unconfined seccomp profile (product knowledge).
    let seccomp = if cfg_str("io_method", "worker") == "io_uring" {
        "Unconfined"
    } else {
        "RuntimeDefault"
    };
    m.insert("seccomp".into(), json!(seccomp));
    Ok(Value::Object(m))
}

/// Consumer env from `requires[].envMapping` + binding params/secrets for ONE
/// process (token vocabulary: `$names.X`, `$params.X`, `$secret.<process>.<key>`.
/// Env vars scoped to other processes (per-process envMapping) are skipped.
fn binding_env(
    comp: &amispec_schema::ComponentInstance,
    ps: &PassportSummary,
    cluster: &amispec_schema::Cluster,
    provider_names: &BTreeMap<String, BTreeMap<String, String>>,
    process: &str,
) -> Vec<Value> {
    let mut env = Vec::new();
    for b in outgoing_bindings(cluster, comp) {
        let Some(req) = b.as_requirement.as_deref() else { continue };
        let Some(env_map) = ps.requires_env.get(req) else { continue };
        for (var, ev) in env_map {
            let Some(token) = ev.token_for(process) else { continue };
            if let Some(name) = token.strip_prefix("$names.") {
                let val = provider_names
                    .get(&b.to)
                    .and_then(|m| m.get(name))
                    .cloned()
                    .unwrap_or_default();
                env.push(json!({"name": var, "value": val}));
            } else if let Some(key) = token.strip_prefix("$params.") {
                let val = b.params.get(key).map(val_str).unwrap_or_default();
                env.push(json!({"name": var, "value": val}));
            } else if let Some(rest) = token.strip_prefix("$secret.") {
                let (proc, key) = rest.split_once('.').unwrap_or(("", "password"));
                let role = ps.processes.get(proc).cloned().unwrap_or_default();
                let secret = if role == "deploy" {
                    b.params.get("deploySecret")
                } else {
                    b.params.get("runtimeSecret")
                }
                .map(val_str)
                .unwrap_or_default();
                env.push(json!({"name": var, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}));
            } else {
                // Literal value (escape hatch for static env).
                env.push(json!({"name": var, "value": token}));
            }
        }
    }
    env
}

/// First process with the given role (`deploy` → migration Job, `runtime` → workload).
fn process_with_role(ps: &PassportSummary, role: &str) -> Option<String> {
    ps.processes
        .iter()
        .find(|(_, r)| r.as_str() == role)
        .map(|(n, _)| n.clone())
}

/// Static container env from `workload.container.env[]`.
fn container_env(ps: &PassportSummary) -> Vec<Value> {
    ps.env_decls
        .iter()
        .map(|e| {
            let mut m = Map::new();
            m.insert("name".into(), json!(e.name));
            if let Some(v) = &e.value {
                m.insert("value".into(), json!(v));
            }
            if let Some(fp) = &e.field_path {
                m.insert(
                    "valueFrom".into(),
                    json!({"fieldRef": {"fieldPath": fp}}),
                );
            } else if let Some(sn) = &e.secret_name {
                m.insert(
                    "valueFrom".into(),
                    json!({"secretKeyRef": {"name": sn, "key": e.secret_key.clone().unwrap_or_default()}}),
                );
            }
            Value::Object(m)
        })
        .collect()
}

/// Probe → k8s probe object. Only declared fields are emitted (absent fields
/// keep the Kubernetes defaults — spec equality with hand-written manifests).
fn probe_object(p: &ProbeDecl) -> Value {
    let mut m = Map::new();
    match p.probe_type.as_str() {
        "exec" => {
            m.insert("exec".into(), json!({"command": p.command}));
        }
        "http" => {
            let mut h = Map::new();
            h.insert("port".into(), json!(p.port.unwrap_or(80)));
            if let Some(path) = &p.path {
                h.insert("path".into(), json!(path));
            }
            m.insert("httpGet".into(), Value::Object(h));
        }
        _ => {
            m.insert("tcpSocket".into(), json!({"port": p.port.unwrap_or(0)}));
        }
    }
    if let Some(v) = p.initial_delay_seconds {
        m.insert("initialDelaySeconds".into(), json!(v));
    }
    if let Some(v) = p.period_seconds {
        m.insert("periodSeconds".into(), json!(v));
    }
    if let Some(v) = p.timeout_seconds {
        m.insert("timeoutSeconds".into(), json!(v));
    }
    if let Some(v) = p.failure_threshold {
        m.insert("failureThreshold".into(), json!(v));
    }
    Value::Object(m)
}

/// Resolve a `$params.<key>` token or literal against component config +
/// passport parameter defaults.
fn resolve_param_token(
    token: &str,
    comp: &amispec_schema::ComponentInstance,
    ps: &PassportSummary,
) -> String {
    if let Some(key) = token.strip_prefix("$params.") {
        comp.config
            .as_ref()
            .and_then(|c| c.get(key))
            .map(val_str)
            .or_else(|| ps.param_defaults.get(key).map(val_str))
            .unwrap_or_default()
    } else {
        token.to_string()
    }
}

/// Script ConfigMaps (`<component>-<script>`, key = `path` or the script name)
/// — declared content of `scripts` (Q3/A: migrations run from 04b Jobs).
fn script_config_maps(comp: &amispec_schema::ComponentInstance, ps: &PassportSummary) -> Vec<Value> {
    ps.scripts
        .iter()
        .filter(|s| !s.inline.is_empty())
        .map(|s| {
            let key = s
                .path
                .clone()
                .unwrap_or_else(|| s.name.clone());
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": format!("{}-{}", comp.id, s.name), "namespace": ns_of(comp)},
                "data": { key: s.inline }
            })
        })
        .collect()
}

/// Exported non-secret tokens (`provides[].clientContract.exportedTokens`)
/// materialized as ConfigMap `<component>-endpoint`. Values may reference the
/// provider's own parameters via `$params.<key>`.
fn exported_tokens_config_map(
    comp: &amispec_schema::ComponentInstance,
    ps: &PassportSummary,
) -> Option<Value> {
    if ps.exported_tokens.is_empty() {
        return None;
    }
    let data: Map<String, Value> = ps
        .exported_tokens
        .iter()
        .map(|(k, v)| (k.clone(), json!(resolve_param_token(v, comp, ps))))
        .collect();
    Some(json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("{}-endpoint", comp.id),
            "namespace": ns_of(comp),
            "labels": {"app.kubernetes.io/name": comp.id},
        },
        "data": Value::Object(data)
    }))
}

/// ClusterIP Service for a k8s-native provider's declared endpoints
/// (operator-crd services belong to the operator — not emitted).
fn endpoint_service(comp: &amispec_schema::ComponentInstance, ps: &PassportSummary) -> Option<Value> {
    if ps.operator_spec.is_some() || ps.endpoints.is_empty() {
        return None;
    }
    let ports: Vec<Value> = ps
        .endpoints
        .iter()
        .map(|e| json!({"name": e.name, "port": e.container_port, "targetPort": e.container_port}))
        .collect();
    Some(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": comp.id,
            "namespace": ns_of(comp),
            "labels": {"app.kubernetes.io/name": comp.id, "app.kubernetes.io/instance": comp.id}
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/name": comp.id},
            "ports": ports
        }
    }))
}

/// Standalone PVC `<component>-data` for Deployment workloads with `storage`
/// (StatefulSets use volumeClaimTemplates instead).
fn persistent_volume_claim(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    provenance: bool,
) -> Option<Value> {
    let st = comp.storage.as_ref()?;
    let mut labels = Map::new();
    labels.insert("app.kubernetes.io/name".into(), json!(comp.id));
    labels.insert("app.kubernetes.io/component".into(), json!("data"));
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!("05-applications"));
    }
    Some(json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": format!("{}-data", comp.id),
            "namespace": ns_of(comp),
            "labels": Value::Object(labels),
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": st.class.clone().unwrap_or_else(|| DEFAULT_STORAGE_CLASS.to_string()),
            "resources": {
                "requests": { "storage": format!("{}Gi", st.size_gb) }
            }
        }
    }))
}

fn workload_object(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    delta: &Value,
    sidecars: &[ClientSidecar],
    sidecar_names: &[String],
    provenance: bool,
    maintenance_window: Option<&str>,
    ps: Option<&PassportSummary>,
    cluster: &amispec_schema::Cluster,
    provider_names: &BTreeMap<String, BTreeMap<String, String>>,
    passport_image: &str,
    passport_digest: Option<&str>,
    stateful: bool,
) -> Value {
    let ns = comp.zone.clone().unwrap_or_else(|| "default".into());
    // GR-OPR-002: workload kind is engine-driven, never name-heuristic.
    let kind = if stateful { "StatefulSet" } else { "Deployment" };

    let mut labels = Map::new();
    labels.insert("app.kubernetes.io/name".into(), json!(comp.id));
    labels.insert("app.kubernetes.io/instance".into(), json!(comp.id));
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!("05-applications"));
        if let Some(z) = &comp.zone {
            labels.insert(LABEL_ZONE.into(), json!(z));
        }
        if !sidecar_names.is_empty() {
            labels.insert(
                LABEL_INJECTED_SIDECARS.into(),
                json!(sidecar_names.join(",")),
            );
        }
    }

    let mut annotations = Map::new();
    if provenance {
        annotations.insert(
            LABEL_USER_SPEC_DELTA.into(),
            json!(serde_json::to_string(delta).unwrap_or_else(|_| "{}".into())),
        );
    }
    // Invariant: rolling-switchover formula changes MUST defer to maintenanceWindow
    if let Some(mw) = maintenance_window {
        if !mw.is_empty() {
            annotations.insert("amispec.io/maintenance-window".into(), json!(mw));
            annotations.insert(
                "amispec.io/rolling-switchover-policy".into(),
                json!("defer-to-maintenance-window"),
            );
        }
    }

    // KEP-753 native sidecars + sharedQuotaFormula / preStopDrain invariants
    let init_containers: Vec<Value> = sidecars
        .iter()
        .map(|s| {
            let mut env = vec![];
            // Invariant: connection pool quota via sharedQuotaFormula (spec §compiler invariants)
            if let Some(formula) = &s.shared_quota_formula {
                // Deterministic placeholder evaluation: formula is CEL; we export
                // the raw formula plus a conservative default for graph.maxBoundConsumerPods.
                // Concrete value is computed by the capacity solver at deploy time.
                env.push(json!({
                    "name": "MAX_DB_CONNECTIONS_PER_POD_FORMULA",
                    "value": formula
                }));
                // Conservative floor matching the spec example (max(2, …))
                env.push(json!({
                    "name": "MAX_DB_CONNECTIONS_PER_POD",
                    "value": "2"
                }));
            }
            let mut c = Map::new();
            c.insert("name".into(), json!(s.name));
            c.insert("image".into(), json!(s.image));
            // KEP-753: native sidecar
            c.insert("restartPolicy".into(), json!("Always"));
            c.insert(
                "ports".into(),
                json!(
                    s.listeners
                        .iter()
                        .map(|l| json!({
                            "name": l.name,
                            "containerPort": l.base_local_port
                        }))
                        .collect::<Vec<_>>()
                ),
            );
            if !env.is_empty() {
                c.insert("env".into(), Value::Array(env));
            }
            // Invariant: preStopDrainDelaySec ONLY for standard-container
            if s.injection_target == "standard-container" {
                if let Some(sec) = s.pre_stop_drain_delay_sec {
                    c.insert(
                        "lifecycle".into(),
                        json!({
                            "preStop": {
                                "exec": {
                                    "command": ["sh", "-c", format!("sleep {sec}")]
                                }
                            }
                        }),
                    );
                }
            }
            c.insert(
                "resources".into(),
                json!({
                    "requests": {
                        "cpu": format!("{}m", s.cpu_millicores),
                        "memory": format!("{}Mi", s.memory_mb)
                    },
                    "limits": {
                        "memory": format!("{}Mi", s.memory_mb)
                    }
                }),
            );
            Value::Object(c)
        })
        .collect();

    let mut pod_spec = Map::new();
    if !init_containers.is_empty() {
        pod_spec.insert("initContainers".into(), Value::Array(init_containers));
    }
    // Invariant: terminationGracePeriodSeconds = max(gracefulStopTimeoutSec,
    //   preStopSleepSec + max(maxEndpointTimeoutSec, maxStatementTimeoutSec))
    // Defaults from the spec: 35, 5, 30, 60 → max(35, 5+60) = 65
    let graceful_stop = 35u32;
    let pre_stop = 5u32;
    let max_endpoint_or_stmt = 60u32;
    let tps = graceful_stop.max(pre_stop.saturating_add(max_endpoint_or_stmt));
    pod_spec.insert("terminationGracePeriodSeconds".into(), json!(tps));
    // GR-IMG-001: manifests pin `image@sha256:...` (override > passport).
    let image_base = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image.clone())
        .unwrap_or_else(|| passport_image.to_string());
    let image_digest = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image_digest.clone())
        .or_else(|| passport_digest.map(String::from));
    let image_ref = match image_digest {
        Some(d) => format!("{image_base}@{d}"),
        None => image_base,
    };
    // Resource envelope: explicit requests/limits from the topology, else the
    // documented default (requests = cpuCores/memoryMb, memory limit only).
    let req_cpu = comp
        .resources
        .requests
        .as_ref()
        .and_then(|r| r.cpu_cores)
        .unwrap_or(comp.resources.cpu_cores);
    let req_mem = comp
        .resources
        .requests
        .as_ref()
        .and_then(|r| r.memory_mb)
        .unwrap_or(comp.resources.memory_mb);
    let mut res = Map::new();
    res.insert(
        "requests".into(),
        json!({
            "cpu": req_cpu.to_string(),
            "memory": format!("{}Mi", req_mem)
        }),
    );
    let mut limits = Map::new();
    limits.insert(
        "memory".into(),
        json!(format!(
            "{}Mi",
            comp.resources
                .limits
                .as_ref()
                .and_then(|l| l.memory_mb)
                .unwrap_or(comp.resources.memory_mb)
        )),
    );
    if let Some(cpu) = comp.resources.limits.as_ref().and_then(|l| l.cpu_cores) {
        limits.insert("cpu".into(), json!(cpu.to_string()));
    }
    res.insert("limits".into(), Value::Object(limits));

    let mut container = json!({ "name": "app", "image": image_ref });
    if let Some(n) = ps.and_then(|p| p.container_name.as_deref()) {
        container.as_object_mut().unwrap().insert("name".into(), json!(n));
    }
    container
        .as_object_mut()
        .unwrap()
        .insert("resources".into(), Value::Object(res));
    // Command/args: topology override > passport declaration.
    if let Some(cmd) = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.command.as_ref())
        .or_else(|| ps.map(|p| &p.command))
        .filter(|c| !c.is_empty())
    {
        container
            .as_object_mut()
            .unwrap()
            .insert("command".into(), json!(cmd));
    }
    if let Some(args) = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.args.as_ref())
        .or_else(|| ps.map(|p| &p.args))
        .filter(|a| !a.is_empty())
    {
        container
            .as_object_mut()
            .unwrap()
            .insert("args".into(), json!(args));
    }
    // Env: declared static/derived env + binding env of runtime processes.
    let mut env: Vec<Value> = Vec::new();
    if let Some(ps) = ps {
        env.extend(container_env(ps));
        for (proc, role) in &ps.processes {
            if role == "runtime" {
                env.extend(binding_env(comp, ps, cluster, provider_names, proc));
            }
        }
    }
    if !env.is_empty() {
        container
            .as_object_mut()
            .unwrap()
            .insert("env".into(), Value::Array(env));
    }
    // Container ports (full inventory; expose contracts reference a subset).
    if let Some(ps) = ps
        && !ps.ports.is_empty()
    {
        let ports: Vec<Value> = ps
            .ports
            .iter()
            .map(|p| json!({"name": p.name, "containerPort": p.container_port}))
            .collect();
        container
            .as_object_mut()
            .unwrap()
            .insert("ports".into(), Value::Array(ports));
    }
    // Probes (only declared fields — absent fields keep Kubernetes defaults).
    if let Some(ps) = ps {
        let mut probes = Map::new();
        if let Some(p) = &ps.probes.readiness {
            probes.insert("readinessProbe".into(), probe_object(p));
        }
        if let Some(p) = &ps.probes.liveness {
            probes.insert("livenessProbe".into(), probe_object(p));
        }
        if let Some(p) = &ps.probes.startup {
            probes.insert("startupProbe".into(), probe_object(p));
        }
        for (k, v) in probes {
            container.as_object_mut().unwrap().insert(k, v);
        }
    }
    // Container-level security hardening (declared).
    if let Some(sc) = ps.and_then(|p| p.security_context.as_ref()) {
        let mut csc = Map::new();
        if let Some(v) = sc.allow_privilege_escalation {
            csc.insert("allowPrivilegeEscalation".into(), json!(v));
        }
        if !sc.capabilities_drop.is_empty() {
            csc.insert(
                "capabilities".into(),
                json!({"drop": sc.capabilities_drop}),
            );
        }
        if !csc.is_empty() {
            container
                .as_object_mut()
                .unwrap()
                .insert("securityContext".into(), Value::Object(csc));
        }
    }
    // Volumes: data claim + config mounts (scripts ConfigMaps / secrets).
    let mut pod_volumes: Vec<Value> = Vec::new();
    let mut mounts: Vec<Value> = Vec::new();
    if comp.storage.is_some() {
        let mount = ps
            .and_then(|p| p.data_mount_path.as_deref())
            .unwrap_or("/data");
        mounts.push(json!({ "name": "data", "mountPath": mount }));
        // Deployment workloads reference a standalone PVC (`<id>-data`);
        // StatefulSets get the claim via volumeClaimTemplates.
        if !stateful {
            pod_volumes.push(json!({
                "name": "data",
                "persistentVolumeClaim": { "claimName": format!("{}-data", comp.id) }
            }));
        }
    }
    if let Some(ps) = ps {
        for cm in &ps.config_mounts {
            let source = cm
                .source
                .as_deref()
                .map(|s| resolve_param_token(s, comp, ps))
                .unwrap_or_else(|| cm.name.clone());
            let mut vol = Map::new();
            vol.insert("name".into(), json!(cm.name));
            if cm.from_secret {
                let mut s = Map::new();
                s.insert("secretName".into(), json!(source));
                if !cm.items.is_empty() {
                    let items: Vec<Value> = cm
                        .items
                        .iter()
                        .map(|(k, p)| {
                            let mut i = Map::new();
                            i.insert("key".into(), json!(k));
                            if let Some(p) = p {
                                i.insert("path".into(), json!(p));
                            }
                            Value::Object(i)
                        })
                        .collect();
                    s.insert("items".into(), Value::Array(items));
                }
                vol.insert("secret".into(), Value::Object(s));
            } else {
                // Script ConfigMap (`<component>-<script name>`).
                let mut c = Map::new();
                c.insert("name".into(), json!(format!("{}-{}", comp.id, source)));
                if let Some(mode) = cm.default_mode {
                    c.insert("defaultMode".into(), json!(mode));
                }
                vol.insert("configMap".into(), Value::Object(c));
            }
            pod_volumes.push(Value::Object(vol));
            let mut m = Map::new();
            m.insert("name".into(), json!(cm.name));
            m.insert("mountPath".into(), json!(cm.mount_path));
            if let Some(sp) = &cm.sub_path {
                m.insert("subPath".into(), json!(sp));
            }
            if cm.read_only {
                m.insert("readOnly".into(), json!(true));
            }
            mounts.push(Value::Object(m));
        }
    }
    if !mounts.is_empty() {
        container
            .as_object_mut()
            .unwrap()
            .insert("volumeMounts".into(), Value::Array(mounts));
    }
    pod_spec.insert("containers".into(), json!([container]));
    if !pod_volumes.is_empty() {
        pod_spec.insert("volumes".into(), Value::Array(pod_volumes));
    }
    // Pod-level security context: only when the passport declares one
    // (hand-written stacks without hardening don't get platform defaults).
    if let Some(sc) = ps.and_then(|p| p.security_context.as_ref()) {
        let mut psc = Map::new();
        if let Some(v) = sc.run_as_non_root {
            psc.insert("runAsNonRoot".into(), json!(v));
        }
        if let Some(v) = sc.run_as_user {
            psc.insert("runAsUser".into(), json!(v));
        }
        if let Some(v) = sc.run_as_group {
            psc.insert("runAsGroup".into(), json!(v));
        }
        if let Some(v) = sc.fs_group {
            psc.insert("fsGroup".into(), json!(v));
        }
        if let Some(v) = &sc.seccomp_profile {
            psc.insert("seccompProfile".into(), json!({"type": v}));
        }
        if !psc.is_empty() {
            pod_spec.insert("securityContext".into(), Value::Object(psc));
        }
    }

    let mut spec = Map::new();
    // Update strategy from the passport topology mode (recreate is explicit;
    // rolling is the Kubernetes default and stays omitted).
    let strategy = ps
        .and_then(|p| p.update_strategies.get(&comp.topology.mode))
        .map(|s| s.as_str());
    if matches!(strategy, Some("recreate")) {
        spec.insert("strategy".into(), json!({"type": "Recreate"}));
    }
    if kind == "StatefulSet" {
        spec.insert("serviceName".into(), json!(comp.id.clone()));
        if let Some(st) = &comp.storage {
            // StatefulSet identity volume: one claim per replica ("data").
            spec.insert(
                "volumeClaimTemplates".into(),
                json!([{
                    "metadata": { "name": "data" },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "storageClassName": st.class.clone().unwrap_or_else(|| DEFAULT_STORAGE_CLASS.to_string()),
                        "resources": {
                            "requests": { "storage": format!("{}Gi", st.size_gb) }
                        }
                    }
                }]),
            );
        }
    }
    spec.insert(
        "replicas".into(),
        json!(comp.topology.replicas.unwrap_or(1)),
    );
    spec.insert(
        "selector".into(),
        json!({ "matchLabels": { "app.kubernetes.io/name": comp.id.clone() } }),
    );
    spec.insert(
        "template".into(),
        json!({
            "metadata": { "labels": labels.clone(), "annotations": annotations.clone() },
            "spec": Value::Object(pod_spec)
        }),
    );

    json!({
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {
            "name": comp.id.clone(),
            "namespace": ns,
            "labels": Value::Object(labels),
            "annotations": Value::Object(annotations),
        },
        "spec": Value::Object(spec)
    })
}


fn pod_disruption_budget(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    provenance: bool,
) -> Value {
    let mut labels = Map::new();
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!("05-applications"));
    }
    json!({
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {
            "name": format!("{}-pdb", comp.id),
            "namespace": ns_of(comp),
            "labels": Value::Object(labels)
        },
        "spec": {
            "maxUnavailable": 1,
            "selector": { "matchLabels": { "app.kubernetes.io/name": comp.id.clone() } }
        }
    })
}

fn hpa_object(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    provenance: bool,
) -> Option<Value> {
    let autoscaling = comp.topology.autoscaling.as_ref()?;
    let mut labels = Map::new();
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!("05-applications"));
    }
    Some(json!({
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {
            "name": format!("{}-hpa", comp.id),
            "namespace": ns_of(comp),
            "labels": Value::Object(labels)
        },
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": comp.id
            },
            "minReplicas": autoscaling.min_replicas,
            "maxReplicas": autoscaling.max_replicas,
            "behavior": {
                "scaleDown": {
                    "stabilizationWindowSeconds": autoscaling.cooldown_seconds.unwrap_or(300)
                }
            }
        }
    }))
}

/// Provisioner Jobs (04a) — emitted ONLY for binding edges whose PROVIDER
/// declares `provides[].provisioner` (GR-OPR-005: no implicit provisioning).
/// The placeholder command is the provider driver contract's job; the
/// provisioner driver itself is a catalog artifact (see adapter packs).
fn provisioner_jobs(
    cluster_id: &str,
    _topology: &TopologyBlueprint,
    cluster: &amispec_schema::Cluster,
    passports: &PassportIndex,
) -> Vec<Value> {
    let mut jobs = Vec::new();
    // Inline component bindings + cluster-level bindings (from = component id)
    let mut edges: Vec<(String, &amispec_schema::Binding)> = Vec::new();
    for comp in &cluster.components {
        for b in &comp.bindings {
            edges.push((comp.id.clone(), b));
        }
    }
    for b in &cluster.bindings {
        let from = b.from.clone().unwrap_or_else(|| "unknown".into());
        edges.push((from, b));
    }
    for (from_id, b) in edges {
        // Gate: the provider must declare a provisioner for the target slot.
        let provider_declares = cluster
            .components
            .iter()
            .find(|c| c.id == b.to)
            .and_then(|c| passports.get(&c.passport))
            .map(|ps| ps.has_provisioner)
            .unwrap_or(false);
        if !provider_declares {
            continue;
        }
        let hash = short_hash(&format!(
            "{}:{}:{}",
            from_id,
            b.to,
            b.to_slot.clone().unwrap_or_default()
        ));
        let job_ns = cluster
            .components
            .iter()
            .find(|c| c.id == from_id)
            .map(ns_of)
            .unwrap_or_else(|| "default".to_string());
        jobs.push(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": format!("provision-{}-{}", from_id, hash),
                "namespace": job_ns,
                "labels": {
                    LABEL_COMPONENT_ID: from_id,
                    LABEL_CLUSTER_ID: cluster_id,
                    LABEL_STAGE: "04a-provisioners-day2",
                },
                "annotations": {
                    LABEL_BINDING_EDGE: format!("{}->{}:{}", from_id, b.to, b.to_slot.clone().unwrap_or_default()),
                }
            },
            "spec": {
                "ttlSecondsAfterFinished": 86400,
                "backoffLimit": 3,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "provisioner",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "echo provision-binding && exit 0"]
                        }]
                    }
                }
            }
        }));
    }
    jobs
}

/// Migration Jobs (04b) — the canonical form of the deploy-process schema
/// expansion (GR: initContainer is the PoC variant). One Job per component
/// whose `lifecycle.preDeployExpandCommand` references a script; the Job runs
/// the declared script content with the deploy-role credentials.
fn migration_jobs(
    cluster_id: &str,
    cluster: &amispec_schema::Cluster,
    passports: &PassportIndex,
    provider_names: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<Value> {
    let mut jobs = Vec::new();
    for comp in &cluster.components {
        let Some(ps) = passports.get(&comp.passport) else {
            continue;
        };
        // Only components with a declared pre-deploy expansion produce jobs.
        let Some(script) = pre_deploy_script(ps) else {
            continue;
        };
        let hash = short_hash(&script.inline);
        let deploy_proc = process_with_role(ps, "deploy");
        let mut env = match &deploy_proc {
            Some(p) => binding_env(comp, ps, cluster, provider_names, p),
            None => Vec::new(),
        };
        // Ground-truth compatibility: psql/pg tools read PG* env natively.
        env.sort_by(|a, b| {
            a.get("name")
                .and_then(|v| v.as_str())
                .cmp(&b.get("name").and_then(|v| v.as_str()))
        });
        let script_key = script
            .path
            .clone()
            .unwrap_or_else(|| script.name.clone());
        let runner: Vec<String> = match script.runtime.as_str() {
            "sql" => vec![
                "psql".into(),
                "-v".into(),
                "ON_ERROR_STOP=1".into(),
                "-f".into(),
                format!("/amispec/scripts/{script_key}"),
            ],
            _ => vec!["sh".into(), format!("/amispec/scripts/{script_key}")],
        };
        jobs.push(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": format!("migrate-expand-{}-{}", comp.id, hash),
                "namespace": ns_of(comp),
                "labels": {
                    LABEL_COMPONENT_ID: comp.id,
                    LABEL_CLUSTER_ID: cluster_id,
                    LABEL_STAGE: "04b-app-migrations-expand",
                }
            },
            "spec": {
                "ttlSecondsAfterFinished": 86400,
                "backoffLimit": 3,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "migrate",
                            "image": migration_image(comp, ps),
                            "command": runner,
                            "env": env,
                            "volumeMounts": [{
                                "name": "scripts",
                                "mountPath": "/amispec/scripts",
                                "readOnly": true
                            }]
                        }],
                        "volumes": [{
                            "name": "scripts",
                            "configMap": {"name": format!("{}-{}", comp.id, script.name)}
                        }]
                    }
                }
            }
        }));
    }
    jobs
}

/// The script referenced by `workload.lifecycle.preDeployExpandCommand`.
fn pre_deploy_script(ps: &PassportSummary) -> Option<&ScriptSummary> {
    ps.pre_deploy_script.as_deref()
        .and_then(|name| ps.scripts.iter().find(|s| s.name == name))
}

/// Image for migration Jobs: the component's own image (override > passport),
/// pinned per GR-IMG-001 — the deploy process runs in the product's runtime.
fn migration_image(
    comp: &amispec_schema::ComponentInstance,
    ps: &PassportSummary,
) -> String {
    let base = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image.clone())
        .or_else(|| ps.image.clone())
        .unwrap_or_else(|| "busybox:1.36".into());
    let digest = comp
        .workload_override
        .as_ref()
        .and_then(|w| w.image_digest.clone())
        .or_else(|| ps.image_digest.clone());
    match digest {
        Some(d) => format!("{base}@{d}"),
        None => base,
    }
}

/// Namespace of a component's workload objects (zone == namespace).
fn ns_of(comp: &amispec_schema::ComponentInstance) -> String {
    comp.zone.clone().unwrap_or_else(|| "default".into())
}

/// Namespace per security zone in use (zone == namespace, AmiSpec spec).
///
/// Workloads land in `zone` namespaces; the tree must create them or Flux
/// rejects the namespaced objects ("namespace not found"). The built-in
/// `default` namespace is never emitted.
fn zone_namespaces(cluster: &amispec_schema::Cluster, provenance: bool) -> Vec<Value> {
    let mut zones: Vec<String> = cluster
        .components
        .iter()
        .filter_map(|c| c.zone.clone())
        .filter(|z| !z.is_empty() && z != "default")
        .collect();
    zones.sort();
    zones.dedup();
    zones
        .into_iter()
        .map(|z| {
            let mut labels = Map::new();
            if provenance {
                labels.insert(LABEL_CLUSTER_ID.into(), json!(&cluster.id));
                labels.insert(LABEL_STAGE.into(), json!("05-applications"));
                labels.insert(LABEL_ZONE.into(), json!(&z));
            }
            json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": z,
                    "labels": Value::Object(labels),
                }
            })
        })
        .collect()
}

fn network_policies(
    cluster_id: &str,
    comps: &[amispec_schema::ComponentInstance],
    provenance: bool,
) -> Vec<Value> {
    // kube-dns guard (always) + per-component default-deny egress stub
    let mut out = vec![json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": format!("{cluster_id}-kube-dns-guard"),
            "namespace": "kube-system",
            "labels": {
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_STAGE: "06-zero-trust-and-observability",
            }
        },
        "spec": {
            "endpointSelector": {},
            "egress": [
                {
                    // kube-system components must keep talking to the API
                    // server and node services (metrics-server, provisioners):
                    // a DNS-only egress lockdown broke them (found by A1.3).
                    "toEntities": ["cluster", "host"]
                },
                {
                    "toEndpoints": [{
                        "matchLabels": { "k8s:k8s-app": "kube-dns" }
                    }],
                    "toPorts": [{ "ports": [{ "port": "53", "protocol": "ANY" }] }]
                }
            ]
        }
    })];
    for c in comps {
        let mut labels = Map::new();
        if provenance {
            labels.insert(LABEL_COMPONENT_ID.into(), json!(c.id));
            labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
            labels.insert(LABEL_STAGE.into(), json!("06-zero-trust-and-observability"));
        }
        out.push(json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": format!("{cluster_id}-{}-egress", c.id),
                "namespace": ns_of(c),
                "labels": Value::Object(labels)
            },
            "spec": {
                "endpointSelector": {
                    "matchLabels": { "app.kubernetes.io/name": c.id.clone() }
                },
                "egress": [
                    { "toEndpoints": [{ "matchLabels": { "k8s:k8s-app": "kube-dns" } }] }
                ]
            }
        }));
    }
    out
}

fn observability_objects(
    cluster_id: &str,
    comps: &[amispec_schema::ComponentInstance],
    provenance: bool,
) -> Vec<Value> {
    let mut out = Vec::new();
    for c in comps {
        let mut labels = Map::new();
        if provenance {
            labels.insert(LABEL_COMPONENT_ID.into(), json!(c.id));
            labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
            labels.insert(LABEL_STAGE.into(), json!("06-zero-trust-and-observability"));
        }
        out.push(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": format!("{}-metrics", c.id),
                "namespace": c.zone.clone().unwrap_or_else(|| "default".into()),
                "labels": Value::Object(labels)
            },
            "spec": {
                "selector": { "app.kubernetes.io/name": c.id.clone() },
                "ports": [{ "name": "metrics", "port": 9090, "targetPort": 9090 }]
            }
        }));
    }
    out
}

fn external_resource_objects(topology: &TopologyBlueprint, provenance: bool) -> Vec<Value> {
    topology
        .external_resources
        .iter()
        .map(|e| {
            let mut meta = Map::new();
            meta.insert("name".into(), json!(e.id));
            if provenance {
                meta.insert(
                    "labels".into(),
                    json!({
                        "amispec.io/external-id": e.id,
                        "amispec.io/external-role": e.role,
                    }),
                );
                meta.insert(
                    "annotations".into(),
                    json!({
                        "amispec.io/passport-ref": e.passport,
                        "amispec.io/endpoint-fqdn": e.endpoint_fqdn,
                        "amispec.io/transport": e.transport.clone().unwrap_or_else(|| "direct".into()),
                        "amispec.io/secret-ref": e.secret_ref,
                    }),
                );
            }
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": meta,
                "data": {
                    "role": e.role,
                    "endpointFqdn": e.endpoint_fqdn,
                    "port": e.port.map(|p| p.to_string()).unwrap_or_default(),
                    "bucket": e.bucket.clone().unwrap_or_default(),
                    "region": e.region.clone().unwrap_or_default(),
                }
            })
        })
        .collect()
}

fn cross_cluster_objects(topology: &TopologyBlueprint, provenance: bool) -> Vec<Value> {
    topology
        .cross_cluster_links
        .iter()
        .map(|l| {
            let mut meta = Map::new();
            meta.insert("name".into(), json!(l.id));
            if provenance {
                meta.insert(
                    "annotations".into(),
                    json!({
                        "amispec.io/from-cluster": l.from_cluster,
                        "amispec.io/from-component": l.from_component,
                        "amispec.io/to-cluster": l.to_cluster,
                        "amispec.io/to-component": l.to_component,
                        "amispec.io/relation-type": l.relation_type,
                        "amispec.io/to-slot": l.to_slot.clone().unwrap_or_default(),
                    }),
                );
            }
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": meta,
                "data": {
                    "transport": l.transport.clone().unwrap_or_else(|| "wireguard-tunnel".into()),
                    "encryption": l.encryption.clone().unwrap_or_else(|| "wireguard-mtls".into()),
                    "maxBandwidthMbps": l.max_bandwidth_mbps.map(|v| v.to_string()).unwrap_or_default(),
                    "rpoTargetSec": l.rpo_target_sec.map(|v| v.to_string()).unwrap_or_default(),
                }
            })
        })
        .collect()
}

/// Stable 8-hex content hash for Job names (`-<sha8>` in the spec).
pub fn short_hash(input: &str) -> String {
    // FNV-1a 64-bit — deterministic, dependency-free, adequate for job suffixes
    let mut h: u64 = 0xcbf29ce484222325;
    for b in input.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", h & 0xffff_ffff)
}

fn write_files(out_dir: &Path, files: &[GeneratedFile]) -> Result<(), CompileError> {
    for f in files {
        let path = out_dir.join(&f.relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CompileError::Io(e.to_string()))?;
        }
        std::fs::write(&path, &f.contents).map_err(|e| CompileError::Io(e.to_string()))?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("topology has no clusters")]
    EmptyClusters,
    #[error(
        "component `{0}` has no image: provide workload.container.image + imageDigest          or workloadOverride.image (GR-IMG-001; the `<id>:<version>` fallback is banned, GR-VER-004)"
    )]
    MissingImage(String),
    #[error("io error: {0}")]
    Io(String),
    #[error(
        "expose[].viaBalancer `{via_balancer}` is not a loadBalancers[].id of cluster `{cluster}`"
    )]
    UnresolvedBalancer {
        via_balancer: String,
        cluster: String,
    },
    #[error(
        "expose `{endpoint}` of component `{component}` declares several viaBalancer ids, \
         but multi-via is only supported for l7-gateway balancers (one L4 Service per edge)"
    )]
    MultiViaOnL4 { endpoint: String, component: String },
    #[error(
        "balancer `{lb_id}` declares vipReachability `l2-announce` together with \
         upstreamEdge — announcing the VIP on the LAN contradicts origin hiding"
    )]
    VipReachabilityConflict { lb_id: String },
    #[error(
        "cannot resolve backend port for expose `{endpoint}` of component `{component}` \
         (passport `{passport}`): {reason}"
    )]
    UnresolvedEndpoint {
        component: String,
        endpoint: String,
        passport: String,
        reason: String,
    },
    #[error(
        "provider `{provider}` (layer `{layer}`) is not implemented — balancer `{lb_id}`; \
         known providers: cilium-envoy, cilium-ingress, cilium-l4-bgp, k3s-servicelb, \
         cloudflare, fastly"
    )]
    ProviderNotImplemented {
        provider: String,
        layer: String,
        lb_id: String,
    },
    #[error("provider `{provider}` does not support layer `{layer}` — balancer `{lb_id}`")]
    ProviderLayerMismatch {
        provider: String,
        layer: String,
        lb_id: String,
    },
    #[error("{0}")]
    Generic(String),
}

pub mod adapter;

#[cfg(test)]
mod tests {
    use super::*;
    use amispec_schema::parse_topology;

    fn mini_topology() -> TopologyBlueprint {
        let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { publisher: test-org, projectId: demo, organization: ex }
clusters:
  - id: local
    name: Local
    domain: example.local
    security: { sopsRecipients: [age1abc] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { arch: amd64, cpuCores: 2, memoryMb: 4096, disks: [{ name: d, tier: nvme-local, sizeGb: 50 }] }
    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: test-org/stateless-app
        version: "1.0.0"
        passportRev: 1
        zone: dmz
        topology: { mode: standalone, replicas: 2 }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l7, scope: public, hostname: example.io }
        bindings:
          - { to: db, asRequirement: database }
      - id: db
        passport: test-org/postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: standalone, replicas: 1 }
        resources: { cpuCores: 2, memoryMb: 2048 }
        storage: { sizeGb: 20, mediaTier: nvme-local }
    bindings: []
"#;
        parse_topology(yaml).unwrap()
    }

    #[test]
    fn stateful_storage_renders_volume_claim_and_mount() {
        // A1.3/R4: a topology `storage` declaration becomes a real PVC +
        // mount at the passport's data directory (contract: amiterra-local).
        let mut idx = PassportIndex::new();
        idx.insert(PassportSummary::from_passport_yaml(mini_passports_raw()).unwrap());
        idx.insert(
            PassportSummary::from_passport_yaml(
                r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: postgresql, publisher: test-org, title: PG, description: Test fixture, version: "18.0.0", passportRev: 6, category: database, archetype: stateful-service }
workload:
  engine: k8s-statefulset
  priorityClass: stateless-web
  container:
    image: docker.io/library/busybox:stable
    imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: sql, protocol: tcp, containerPort: 5432, role: datastore, defaultScope: cluster-private }
  provides: []
  requires: {}
hardwareAndKernel:
  resources: { minCpuCores: 0.5, minMemoryMb: 512 }
  storage: { mountPath: /var/lib/postgresql/data, minSizeGb: 10 }
"#,
            )
            .unwrap(),
        );
        let out = compile(&mini_topology(), &idx, &Options::dry()).unwrap();
        let render: String = out
            .files
            .iter()
            .map(|f| f.contents.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(render.contains("volumeClaimTemplates"), "claim rendered");
        assert!(
            render.contains("storageClassName: amiterra-local"),
            "contract SC"
        );
        assert!(
            render.contains("storage: 20Gi"),
            "size from topology storage"
        );
        assert!(
            render.contains("mountPath: /var/lib/postgresql/data"),
            "mount from passport storage.mountPath"
        );
        assert!(render.contains("kind: StatefulSet"), "stateful workload");
    }

    /// Passport contracts for the mini topology (expose port resolution).
    fn mini_passports_raw() -> &'static str {
        r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: stateless-app, publisher: test-org, title: App, description: Test fixture, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
workload:
  engine: k8s-deployment
  priorityClass: stateless-web
  container:
    image: docker.io/library/busybox:stable
    imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: web, protocol: http, containerPort: 8080, role: ui, defaultScope: public }
  provides: []
  requires: {}
"#
    }

    fn mini_passports() -> PassportIndex {
        let mut idx = PassportIndex::new();
        idx.insert(PassportSummary::from_passport_yaml(mini_passports_raw()).unwrap());
        idx.insert(
            PassportSummary::from_passport_yaml(
                r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: postgresql, publisher: test-org, title: PG, description: Test fixture, version: "18.0.0", passportRev: 6, category: database, archetype: stateful-service }
workload:
  engine: k8s-statefulset
  priorityClass: stateless-web
  container:
    image: 'docker.io/library/busybox:stable'
    imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: sql, protocol: tcp, containerPort: 5432, role: datastore, defaultScope: cluster-private }
  provides:
    - { slot: sql-cluster, capability: postgres-sql, dialect: postgresql, version: "18.0.0" }
  requires: {}
"#,
            )
            .unwrap(),
        );
        idx
    }

    #[test]
    fn compile_emits_seven_stages() {
        let topo = mini_topology();
        let out = compile(&topo, &mini_passports(), &Options::dry()).unwrap();
        let paths: Vec<_> = out.files.iter().map(|f| f.relative_path.as_str()).collect();
        for stage in [
            "01-node-tuning",
            "02-operators-and-networking",
            "03-stateful-clusters",
            "04a-provisioners-day2",
            "04b-app-migrations-expand",
            "05-applications",
            "06-zero-trust-and-observability",
        ] {
            assert!(
                paths.iter().any(|p| p.contains(stage)),
                "missing stage {stage} in {paths:?}"
            );
        }
        assert!(out.object_count > 0);
    }

    #[test]
    fn compile_is_deterministic() {
        let topo = mini_topology();
        let a = compile(&topo, &mini_passports(), &Options::dry()).unwrap();
        let b = compile(&topo, &mini_passports(), &Options::dry()).unwrap();
        assert_eq!(a.files.len(), b.files.len());
        for (x, y) in a.files.iter().zip(b.files.iter()) {
            assert_eq!(x.relative_path, y.relative_path);
            assert_eq!(x.contents, y.contents);
        }
    }

    #[test]
    fn exposure_materializes_gateway_and_resolved_route() {
        let topo = mini_topology();
        let out = compile(&topo, &mini_passports(), &Options::dry()).unwrap();
        let file = |frag: &str| {
            out.files
                .iter()
                .find(|f| f.relative_path.ends_with(frag))
                .unwrap_or_else(|| panic!("missing file {frag}"))
                .contents
                .clone()
        };
        let gateways = file("02-operators-and-networking/gateways.yaml");
        assert!(gateways.contains("kind: GatewayClass"), "{gateways}");
        assert!(gateways.contains("controllerName: io.cilium/gateway-controller"));
        assert!(gateways.contains("kind: Gateway"));
        let activation = file("02-operators-and-networking/balancer-activation.yaml");
        assert!(activation.contains("kind: HelmChartConfig"));
        assert!(activation.contains("gatewayAPI"));
        let routes = file("05-applications/routes.yaml");
        assert!(routes.contains("kind: HTTPRoute"));
        assert!(routes.contains("example.io"));
        // parentRefs resolved to the Gateway + port from the passport contract
        assert!(routes.contains("namespace: flux-system"), "{routes}");
        assert!(routes.contains("port: 8080"), "{routes}");
        assert!(
            !routes.contains("port: 80\n"),
            "hardcoded port 80 must be gone"
        );
    }

    #[test]
    fn zero_exposure_leaves_no_balancing_objects() {
        let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { publisher: test-org, projectId: demo, organization: ex }
clusters:
  - id: local
    name: Local
    domain: example.local
    security: { sopsRecipients: [age1abc] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { arch: amd64, cpuCores: 2, memoryMb: 4096, disks: [] }
    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: test-org/stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings: []
"#;
        let topo = parse_topology(yaml).unwrap();
        let out = compile(&topo, &mini_passports(), &Options::dry()).unwrap();
        for f in &out.files {
            for kind in [
                "GatewayClass",
                "Gateway",
                "HTTPRoute",
                "HelmChartConfig",
                "HelmRelease",
                "ClusterIssuer",
                "Certificate",
                "Ingress",
            ] {
                assert!(
                    !f.contents.contains(&format!("kind: {kind}")),
                    "unexpected {kind} in {}",
                    f.relative_path
                );
            }
        }
        assert!(out.warnings.is_empty());
    }

    #[test]
    fn unresolved_endpoint_fails_fast() {
        let topo = mini_topology();
        let err = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap_err();
        assert!(
            matches!(err, CompileError::UnresolvedEndpoint { .. }),
            "{err}"
        );
    }

    #[test]
    fn short_hash_stable() {
        assert_eq!(short_hash("abc"), short_hash("abc"));
        assert_eq!(short_hash("abc").len(), 8);
        assert_ne!(short_hash("abc"), short_hash("abd"));
    }
}
