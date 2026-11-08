//! AmiSpec schema types and version pins.
//!
//! This crate is the Rust projection of the normative CUE meta-schemas
//! (`schemas/component_passport.cue`, `schemas/topology_spec.cue`) from the
//! AmiSpec standard repository. It does **not** replace CUE validation; use
//! `amispec-validate` for full structural checks against the CUE schemas.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// AmiSpec standard version this crate targets (see `amispec` repo).
pub const AMISPEC_STANDARD_VERSION: &str = "1.0.0";

/// `apiVersion` for ComponentPassport documents.
pub const API_VERSION_PASSPORT: &str = "catalog.amispec.io/v1";
/// `apiVersion` for TopologyBlueprint documents.
pub const API_VERSION_TOPOLOGY: &str = "topology.amispec.io/v1";

/// Discriminator of an AmiSpec document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    ComponentPassport,
    TopologyBlueprint,
}

impl DocumentKind {
    pub fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "ComponentPassport" => Some(Self::ComponentPassport),
            "TopologyBlueprint" => Some(Self::TopologyBlueprint),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentPassport => "ComponentPassport",
            Self::TopologyBlueprint => "TopologyBlueprint",
        }
    }
}

/// Parse document kind and apiVersion from YAML text without full schema bind.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DocumentHeader {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
}

/// Topology mode names (enum in the spec).
pub const TOPOLOGY_MODES: &[&str] = &["standalone", "degraded-ha", "strict-ha", "sharded-cluster"];

/// Passport categories (enum in the spec).
pub const PASSPORT_CATEGORIES: &[&str] = &[
    "database",
    "analytics",
    "cache",
    "message-queue",
    "application",
    "ai-ml",
    "gateway",
    "observability",
    "storage",
    "security",
    "external",
];

/// Passport archetypes (enum in the spec).
pub const PASSPORT_ARCHETYPES: &[&str] = &[
    "stateless-app",
    "stateful-service",
    "operator-cluster",
    "edge-gateway",
    "external-bridge",
    "scheduled-job",
];

/// `metadata.id` pattern from the spec (`^[a-z0-9-]+$`).
pub const ID_PATTERN: &str = r"^[a-z0-9-]+$";
/// `imageDigest` pattern from the spec.
pub const IMAGE_DIGEST_PATTERN: &str = r"^sha256:[a-f0-9]{64}$";
/// `accentColor` pattern from the spec.
pub const ACCENT_COLOR_PATTERN: &str = r"^#[0-9a-fA-F]{6}$";
/// SOPS/Age recipient pattern from the spec.
pub const AGE_KEY_PATTERN: &str = r"^age1[a-z0-9]+$";
/// ScriptRef URI pattern from the spec.
pub const SCRIPT_REF_PATTERN: &str = r"^(passport|topology)://scripts/[a-zA-Z0-9_.-]+$";

/// Cluster node role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    ControlPlaneWorker,
    ControlPlaneOnly,
    WorkerOnly,
}

/// CNI engine (closed enum in the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CniEngine {
    #[serde(rename = "cilium-ebpf")]
    CiliumEbpf,
}

/// Minimal typed view of a TopologyBlueprint for compile/semantic use.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TopologyBlueprint {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: TopologyMetadata,
    #[serde(default)]
    pub clusters: Vec<Cluster>,
    #[serde(default, rename = "externalResources")]
    pub external_resources: Vec<ExternalResource>,
    #[serde(default, rename = "crossClusterLinks")]
    pub cross_cluster_links: Vec<CrossClusterLink>,
}

impl TopologyBlueprint {
    /// Kind + apiVersion header check.
    pub fn check_header(&self) -> Result<(), SchemaError> {
        if self.kind != "TopologyBlueprint" {
            return Err(SchemaError::WrongKind(self.kind.clone()));
        }
        if self.api_version != API_VERSION_TOPOLOGY {
            return Err(SchemaError::WrongApiVersion(self.api_version.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TopologyMetadata {
    #[serde(rename = "projectId")]
    pub project_id: String,
    pub organization: String,
    #[serde(rename = "gitMode")]
    pub git_mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalResource {
    pub id: String,
    pub passport: String,
    pub role: String,
    #[serde(rename = "endpointFqdn")]
    pub endpoint_fqdn: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(rename = "secretRef")]
    pub secret_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrossClusterLink {
    pub id: String,
    #[serde(rename = "fromCluster")]
    pub from_cluster: String,
    #[serde(rename = "fromComponent")]
    pub from_component: String,
    #[serde(rename = "toCluster")]
    pub to_cluster: String,
    #[serde(rename = "toComponent")]
    pub to_component: String,
    #[serde(rename = "toSlot")]
    pub to_slot: Option<String>,
    #[serde(rename = "relationType")]
    pub relation_type: String,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(rename = "maxBandwidthMbps")]
    pub max_bandwidth_mbps: Option<u32>,
    #[serde(rename = "rpoTargetSec")]
    pub rpo_target_sec: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cluster {
    pub id: String,
    pub name: String,
    pub domain: String,
    /// k3s release channel pin (spec default `v1.37`).
    #[serde(default, rename = "k3sChannel")]
    pub k3s_channel: Option<String>,
    #[serde(default)]
    pub security: Option<ClusterSecurity>,
    pub cni: CniConfig,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub components: Vec<ComponentInstance>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    #[serde(rename = "loadBalancers")]
    pub load_balancers: Vec<LoadBalancer>,
    /// Rolling-switchover maintenance window (e.g. "Sun 02:00-05:00 UTC").
    #[serde(default, rename = "maintenanceWindow")]
    pub maintenance_window: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterSecurity {
    #[serde(rename = "sopsRecipients")]
    pub sops_recipients: Vec<String>,
    #[serde(rename = "implicitTelemetryLayer")]
    pub implicit_telemetry_layer: Option<bool>,
    #[serde(rename = "imageRegistryPolicy")]
    pub image_registry_policy: Option<String>,
    #[serde(rename = "imagePullSecretRefs")]
    pub image_pull_secret_refs: Option<Vec<String>>,
    #[serde(rename = "controlPlaneQuorumMode")]
    pub control_plane_quorum_mode: Option<String>,
    #[serde(rename = "etcdBackupTarget")]
    pub etcd_backup_target: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CniConfig {
    pub engine: String,
    #[serde(rename = "clusterMeshId")]
    pub cluster_mesh_id: u32,
    #[serde(rename = "kubeProxyReplacement")]
    pub kube_proxy_replacement: Option<bool>,
    #[serde(rename = "hubbleLiveMap")]
    pub hubble_live_map: Option<bool>,
    #[serde(rename = "wireguardEncryption")]
    pub wireguard_encryption: Option<bool>,
    #[serde(rename = "mtuDiscoveryAndMssClamp")]
    pub mtu_discovery_and_mss_clamp: Option<bool>,
    #[serde(rename = "fqdnCacheMinTtlSec")]
    pub fqdn_cache_min_ttl_sec: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    pub id: String,
    pub role: String,
    #[serde(rename = "pricingTier")]
    pub pricing_tier: Option<String>,
    #[serde(rename = "failureDomainZone")]
    pub failure_domain_zone: Option<String>,
    #[serde(rename = "monthlyCostUsd")]
    pub monthly_cost_usd: Option<f64>,
    pub hardware: NodeHardware,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeHardware {
    pub arch: Option<String>,
    #[serde(rename = "cpuCores")]
    pub cpu_cores: f64,
    #[serde(rename = "memoryMb")]
    pub memory_mb: u64,
    #[serde(rename = "systemReservedMb")]
    pub system_reserved_mb: Option<u64>,
    #[serde(rename = "systemDiskReservedGb")]
    pub system_disk_reserved_gb: Option<u64>,
    #[serde(rename = "lvmSnapshotReservePercent")]
    pub lvm_snapshot_reserve_percent: Option<u32>,
    #[serde(default)]
    pub disks: Vec<Disc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Disc {
    pub name: String,
    pub tier: String,
    #[serde(rename = "sizeGb")]
    pub size_gb: u64,
}

/// User-level workload override (`workloadOverride`) — only when the passport
/// allows it. Image/command overrides are the compile-time contract; other
/// fields round-trip through the user-spec delta.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WorkloadOverride {
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentInstance {
    pub id: String,
    pub passport: String,
    pub version: String,
    #[serde(rename = "passportRev")]
    pub passport_rev: u32,
    pub topology: ComponentTopology,
    pub resources: ComponentResources,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub config: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, rename = "backupTarget")]
    pub backup_target: Option<String>,
    #[serde(default)]
    pub bootstrap: Option<Bootstrap>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub expose: Vec<Expose>,
    #[serde(default, rename = "workloadOverride")]
    pub workload_override: Option<WorkloadOverride>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentTopology {
    pub mode: String,
    #[serde(default)]
    pub replicas: Option<u32>,
    #[serde(default, rename = "committedReplicas")]
    pub committed_replicas: Option<u32>,
    #[serde(default)]
    pub shards: Option<u32>,
    #[serde(default)]
    pub autoscaling: Option<Autoscaling>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Autoscaling {
    #[serde(rename = "minReplicas")]
    pub min_replicas: u32,
    #[serde(rename = "maxReplicas")]
    pub max_replicas: u32,
    #[serde(rename = "cooldownSeconds")]
    pub cooldown_seconds: Option<u32>,
    #[serde(rename = "targetCpuPercent")]
    pub target_cpu_percent: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentResources {
    #[serde(rename = "cpuCores")]
    pub cpu_cores: f64,
    #[serde(rename = "memoryMb")]
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bootstrap {
    #[serde(rename = "fromBackupTarget")]
    pub from_backup_target: String,
    #[serde(rename = "sourceComponentId")]
    pub source_component_id: Option<String>,
    #[serde(rename = "recoveryTargetTime")]
    pub recovery_target_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Binding {
    #[serde(default)]
    pub from: Option<String>,
    pub to: String,
    #[serde(default, rename = "toSlot")]
    pub to_slot: Option<String>,
    #[serde(default, rename = "asRequirement")]
    pub as_requirement: Option<String>,
    #[serde(default, rename = "envPrefix")]
    pub env_prefix: Option<String>,
    #[serde(default, rename = "secretRotationEpoch")]
    pub secret_rotation_epoch: Option<u32>,
    #[serde(default, rename = "type")]
    pub type_: Option<String>,
    #[serde(default, rename = "deliveryGuarantee")]
    pub delivery_guarantee: Option<String>,
    #[serde(default, rename = "outboxSourceRequirement")]
    pub outbox_source_requirement: Option<String>,
}

/// Edge security policy on an `expose[]` entry.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// `none` | `oidc` | `mtls` (spec default `none`).
    #[serde(default, rename = "clientAuth")]
    pub client_auth: Option<String>,
    #[serde(default, rename = "corsAllowedOrigins")]
    pub cors_allowed_origins: Option<Vec<String>>,
    #[serde(default, rename = "rateLimitRps")]
    pub rate_limit_rps: Option<u32>,
    /// Explicitly acknowledge `scope: protected` without client authentication.
    #[serde(default, rename = "allowAnonymous")]
    pub allow_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Expose {
    /// Named `interfaces.endpoints[]` entry of the component passport;
    /// its `containerPort` becomes the route backend port (portless ADR 0009).
    pub endpoint: String,
    #[serde(rename = "viaBalancer")]
    pub via_balancer: String,
    pub scope: String,
    /// Expands to FQDN `<subdomain>.<cluster.domain>`.
    #[serde(default)]
    pub subdomain: Option<String>,
    /// Apex / external domain, used as-is (takes precedence over `subdomain`).
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default, rename = "pathPrefix")]
    pub path_prefix: Option<String>,
    #[serde(default, rename = "securityPolicy")]
    pub security_policy: Option<SecurityPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoadBalancer {
    pub id: String,
    pub layer: String,
    pub provider: String,
    #[serde(default, rename = "upstreamEdge")]
    pub upstream_edge: Option<String>,
    #[serde(default, rename = "trustedProxySource")]
    pub trusted_proxy_source: Option<serde_json::Value>,
    #[serde(default, rename = "forwardingMode")]
    pub forwarding_mode: Option<String>,
    #[serde(default, rename = "floatingIpRef")]
    pub floating_ip_ref: Option<String>,
    #[serde(default, rename = "proxyProtocolV2")]
    pub proxy_protocol_v2: Option<bool>,
    #[serde(default, rename = "http3Quic")]
    pub http3_quic: Option<bool>,
    #[serde(default)]
    pub tls: Option<String>,
}

/// Inbound endpoint contract from `interfaces.endpoints[]` of a ComponentPassport.
///
/// `expose[].endpoint` names one of these entries; its `containerPort` becomes
/// the compiled route backend port (portless composition, ADR 0009).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PassportEndpoint {
    pub name: String,
    #[serde(rename = "containerPort")]
    pub container_port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, rename = "defaultScope")]
    pub default_scope: Option<String>,
    #[serde(default, rename = "defaultSubdomain")]
    pub default_subdomain: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PassportInterfacesView {
    #[serde(default)]
    endpoints: Vec<PassportEndpoint>,
    #[serde(default)]
    provides: Vec<PassportProvideView>,
    #[serde(default)]
    requires: BTreeMap<String, PassportRequireView>,
}

#[derive(Debug, Clone, Deserialize)]
struct PassportProvideView {
    slot: String,
    capability: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PassportRequireView {
    capability: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PassportContractView {
    #[serde(default)]
    interfaces: Option<PassportInterfacesView>,
}

/// Extract `interfaces.endpoints[]` contracts from passport YAML text.
///
/// Unknown passport fields are ignored (the full passport schema is validated
/// by `amispec-validate`); this projection only reads the endpoint contract.
pub fn parse_passport_endpoints(raw: &str) -> Result<Vec<PassportEndpoint>, SchemaError> {
    let view: PassportContractView =
        serde_yaml::from_str(raw).map_err(|e| SchemaError::Parse(e.to_string()))?;
    Ok(view.interfaces.map(|i| i.endpoints).unwrap_or_default())
}

/// `provides`/`requires` slot contract of a ComponentPassport — the graph
/// edges of composition (Design Doc 0026 §1.2: dependency closure of
/// `requires` when assembling a topology from the catalog).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PassportSlots {
    pub id: String,
    /// Outgoing slots: slot name → capability.
    pub provides: BTreeMap<String, String>,
    /// Incoming requirements: slot name → capability.
    pub requires: BTreeMap<String, String>,
}

/// Extract the slot contract (`interfaces.provides` / `interfaces.requires`)
/// and passport identity from passport YAML text.
pub fn parse_passport_slots(raw: &str) -> Result<PassportSlots, SchemaError> {
    let view: PassportContractView =
        serde_yaml::from_str(raw).map_err(|e| SchemaError::Parse(e.to_string()))?;
    let doc: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| SchemaError::Parse(e.to_string()))?;
    let id = doc
        .get("metadata")
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| SchemaError::Parse("passport: metadata.id is required".into()))?
        .to_string();
    let mut slots = PassportSlots {
        id,
        ..Default::default()
    };
    if let Some(ifaces) = view.interfaces {
        for p in ifaces.provides {
            slots.provides.insert(p.slot, p.capability);
        }
        for (slot, r) in ifaces.requires {
            slots.requires.insert(slot, r.capability);
        }
    }
    Ok(slots)
}

/// Deterministic provider choice for a capability within a catalog.
///
/// When several catalog passports provide the same capability the
/// lexicographically smallest id wins (stable across doors); alternatives are
/// reported so a UI can offer a picker instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureResolution {
    /// Selected + transitively required passport ids.
    pub resolved: BTreeSet<String>,
    /// capability → chosen provider passport id.
    pub providers: BTreeMap<String, String>,
    /// capability → all provider ids (sorted) for UI pickers.
    pub alternatives: BTreeMap<String, Vec<String>>,
    /// Requirements no catalog passport can provide (from, slot, capability).
    pub unresolved: Vec<(String, String, String)>,
}

/// Compute the transitive `requires` closure of a passport selection over a
/// catalog (Design Doc 0026 §1.2/§3.1 — "pick and apply" must be an honest,
/// validated graph closure, not magic).
pub fn dependency_closure(
    catalog: &BTreeMap<String, PassportSlots>,
    selected: &[String],
) -> ClosureResolution {
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    let mut providers: BTreeMap<String, String> = BTreeMap::new();
    let mut alternatives: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unresolved: Vec<(String, String, String)> = Vec::new();

    // capability → providing passport ids (sorted → deterministic choice)
    let mut by_capability: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, slots) in catalog {
        for cap in slots.provides.values() {
            by_capability
                .entry(cap.clone())
                .or_default()
                .push(id.clone());
        }
    }
    for ids in by_capability.values_mut() {
        ids.sort();
        ids.dedup();
    }

    // BFS over required capabilities; queue is sorted for determinism.
    let mut queue: Vec<String> = selected.to_vec();
    queue.sort();
    queue.dedup();
    while let Some(id) = queue.first().cloned() {
        queue.remove(0);
        if !resolved.insert(id.clone()) {
            continue;
        }
        let Some(slots) = catalog.get(&id) else {
            // selected passport unknown to the catalog — surfaced as unresolved
            unresolved.push((
                id.clone(),
                String::from("<catalog>"),
                String::from("<missing>"),
            ));
            continue;
        };
        for (_slot, cap) in &slots.requires {
            let Some(ids) = by_capability.get(cap) else {
                unresolved.push((id.clone(), _slot.clone(), cap.clone()));
                continue;
            };
            let chosen = ids[0].clone();
            alternatives.insert(cap.clone(), ids.clone());
            providers.insert(cap.clone(), chosen.clone());
            if !resolved.contains(&chosen) {
                queue.push(chosen.clone());
            }
        }
    }

    ClosureResolution {
        resolved,
        providers,
        alternatives,
        unresolved,
    }
}

/// Document identity after classification.
#[derive(Debug, Clone)]
pub struct LoadedDocument {
    pub kind: DocumentKind,
    pub source_path: String,
    pub raw_yaml: String,
    pub header: DocumentHeader,
}

/// Parse YAML and classify the document kind.
pub fn load_document(path: &str, raw: &str) -> Result<LoadedDocument, SchemaError> {
    let header: DocumentHeader =
        serde_yaml::from_str(raw).map_err(|e| SchemaError::Parse(e.to_string()))?;
    let kind = DocumentKind::from_kind_str(&header.kind)
        .ok_or_else(|| SchemaError::UnknownKind(header.kind.clone()))?;
    Ok(LoadedDocument {
        kind,
        source_path: path.to_string(),
        raw_yaml: raw.to_string(),
        header,
    })
}

/// Parse a topology blueprint document.
pub fn parse_topology(raw: &str) -> Result<TopologyBlueprint, SchemaError> {
    let doc: TopologyBlueprint =
        serde_yaml::from_str(raw).map_err(|e| SchemaError::Parse(e.to_string()))?;
    doc.check_header()?;
    Ok(doc)
}

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("YAML parse error: {0}")]
    Parse(String),
    #[error("unknown document kind: {0}")]
    UnknownKind(String),
    #[error("wrong kind: {0}")]
    WrongKind(String),
    #[error("wrong apiVersion: {0}")]
    WrongApiVersion(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(API_VERSION_PASSPORT, "catalog.amispec.io/v1");
        assert_eq!(API_VERSION_TOPOLOGY, "topology.amispec.io/v1");
        assert_eq!(AMISPEC_STANDARD_VERSION, "1.0.0");
    }

    #[test]
    fn classifies_kinds() {
        assert_eq!(
            DocumentKind::from_kind_str("ComponentPassport"),
            Some(DocumentKind::ComponentPassport)
        );
        assert_eq!(DocumentKind::from_kind_str("Nope"), None);
    }

    const SLOTS_DOC: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: youtrack, name: YouTrack, version: "1.0.0", passportRev: 3 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides: []
  requires:
    edge: { capability: http-l7-gateway }
    database: { capability: postgres-sql }
"#;

    const BALANCER_DOC: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: balancer-cilium-l7, name: Balancer, version: "1.0.0", passportRev: 1 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - { slot: l7, capability: http-l7-gateway }
  requires: {}
"#;

    const PG_DOC: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: postgresql, name: PG, version: "18.0.0", passportRev: 6 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - { slot: sql-cluster, capability: postgres-sql }
  requires: {}
"#;

    #[test]
    fn parses_slot_contract() {
        let slots = parse_passport_slots(SLOTS_DOC).unwrap();
        assert_eq!(slots.id, "youtrack");
        assert!(slots.provides.is_empty());
        assert_eq!(
            slots.requires.get("edge").map(|s| s.as_str()),
            Some("http-l7-gateway")
        );
        assert_eq!(
            slots.requires.get("database").map(|s| s.as_str()),
            Some("postgres-sql")
        );
    }

    fn catalog() -> BTreeMap<String, PassportSlots> {
        [SLOTS_DOC, BALANCER_DOC, PG_DOC]
            .iter()
            .map(|raw| {
                let s = parse_passport_slots(raw).unwrap();
                (s.id.clone(), s)
            })
            .collect()
    }

    #[test]
    fn closure_pulls_transitive_requirements() {
        let res = dependency_closure(&catalog(), &[String::from("youtrack")]);
        assert_eq!(
            res.resolved,
            ["youtrack", "balancer-cilium-l7", "postgresql"]
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            res.providers.get("http-l7-gateway").map(|s| s.as_str()),
            Some("balancer-cilium-l7")
        );
        assert!(res.unresolved.is_empty());
    }

    #[test]
    fn closure_reports_unresolvable_capabilities() {
        let mut cat = catalog();
        cat.remove("postgresql");
        let res = dependency_closure(&cat, &[String::from("youtrack")]);
        assert_eq!(res.unresolved.len(), 1);
        assert_eq!(
            res.unresolved[0],
            ("youtrack".into(), "database".into(), "postgres-sql".into())
        );
    }

    #[test]
    fn closure_choice_is_deterministic_with_alternatives() {
        let mut cat = catalog();
        let extra = BALANCER_DOC.replace("balancer-cilium-l7", "aaa-first");
        cat.insert("aaa-first".into(), parse_passport_slots(&extra).unwrap());
        let res = dependency_closure(&cat, &[String::from("youtrack")]);
        assert_eq!(
            res.providers.get("http-l7-gateway").map(|s| s.as_str()),
            Some("aaa-first"),
            "lexicographically smallest provider wins"
        );
        assert_eq!(
            res.alternatives.get("http-l7-gateway"),
            Some(&vec![
                "aaa-first".to_string(),
                "balancer-cilium-l7".to_string()
            ])
        );
    }
}
