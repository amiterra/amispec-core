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
    /// GR-IMG-001: overrides carry the same image+digest pair.
    #[serde(default, rename = "imageDigest")]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
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
    /// Data volume declaration (`storage` in the topology schema).
    #[serde(default)]
    pub storage: Option<VolumeOverride>,
    /// Named volume overrides (`volumes` in the topology schema: wal, ...).
    #[serde(default)]
    pub volumes: BTreeMap<String, VolumeOverride>,
}

/// Topology storage declaration (`storage` in CUE `#VolumeTopologyOverride`):
/// size and media tier of the component's data volume.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct VolumeOverride {
    #[serde(rename = "sizeGb")]
    pub size_gb: u32,
    #[serde(default, rename = "committedSizeGb")]
    pub committed_size_gb: Option<u32>,
    // CUE default: *"nvme-local" — keep serde in lockstep (cue_contract).
    #[serde(default = "default_media_tier", rename = "mediaTier")]
    pub media_tier: String,
    /// Concrete CSI storage class name (CUE `#VolumeTopologyOverride.class`).
    #[serde(default)]
    pub class: Option<String>,
}

fn default_media_tier() -> String {
    "nvme-local".to_string()
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
    /// Explicit Burstable request envelope (default: cpuCores/memoryMb).
    #[serde(default)]
    pub requests: Option<ResourceEnvelope>,
    /// Explicit limit envelope (default: memoryMb, no cpu limit).
    #[serde(default)]
    pub limits: Option<ResourceEnvelope>,
}

/// Request/limit envelope (`topology.resources.{requests,limits}`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ResourceEnvelope {
    #[serde(default, rename = "cpuCores")]
    pub cpu_cores: Option<f64>,
    #[serde(default, rename = "memoryMb")]
    pub memory_mb: Option<u64>,
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
    /// Per-env overrides of the generated binding environment.
    #[serde(default, rename = "envOverrides")]
    pub env_overrides: BTreeMap<String, String>,
    /// GR-OPR-005: consumption parameters (database/role/secret names) —
    /// declared per binding so N consumers of one slot stay independent.
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
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

/// Balancer reference(s) on an `expose[]` entry: one id, or several when the
/// same endpoint is exposed through multiple balancers (HA).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ViaBalancer {
    One(String),
    Many(Vec<String>),
}

impl ViaBalancer {
    /// All declared balancer ids, in declaration order.
    pub fn ids(&self) -> Vec<&str> {
        match self {
            ViaBalancer::One(id) => vec![id.as_str()],
            ViaBalancer::Many(ids) => ids.iter().map(String::as_str).collect(),
        }
    }
}

/// How external clients physically reach the balancer VIP (Design Doc 0025
/// §3.11: network prerequisites are *declared*, never invented by the
/// compiler). Absent = `none` (fail-closed) + a compile warning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VipReachability {
    /// ARP announcements via Cilium L2 (compiler materializes a scoped
    /// `CiliumL2AnnouncementPolicy` per balancer).
    L2Announce,
    /// BGP routing to the VIP (Day-2 peering; compiler emits only a checklist).
    Bgp,
    /// No announcements: reachability comes from elsewhere (edge / manual).
    #[default]
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Expose {
    /// Named `interfaces.endpoints[]` entry of the component passport;
    /// its `containerPort` becomes the route backend port (portless ADR 0009).
    pub endpoint: String,
    #[serde(rename = "viaBalancer")]
    pub via_balancer: ViaBalancer,
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
    /// Declared VIP reachability model; `None` (absent) behaves like
    /// `VipReachability::None` plus a compile warning (fail-closed).
    #[serde(default, rename = "vipReachability")]
    pub vip_reachability: Option<VipReachability>,
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
    #[serde(default)]
    version: Option<String>,
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
    /// Effective software version — explicit `metadata.version` or the
    /// version core of a version-ful image tag (GR-VER-001).
    pub version: Option<String>,
    /// Provider-side access declaration per provides slot (GR-CRED-002).
    pub provides_access: BTreeMap<String, AccessDecl>,
    /// Explicit `provides[].version` per slot (defaults to `version`).
    pub provides_versions: BTreeMap<String, String>,
    /// `requires[].version` range expressions per slot (GR-VER-003).
    pub requires_versions: BTreeMap<String, String>,
    /// Consumer-side credential processes flattened to `uses` entries
    /// (GR-CRED-001): (required slot, verbs, resources, plugins).
    pub process_uses: Vec<ProcessUse>,
}

/// `provides[].access` — what the provider can enforce (GR-CRED-002).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessDecl {
    pub fulfillment: Vec<String>,
    pub plugins: Vec<String>,
}

/// One `processes[].uses[]` entry of a consumer passport (GR-CRED-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessUse {
    pub slot: String,
    pub verbs: Vec<String>,
    pub resources: Vec<String>,
    pub plugins: Vec<String>,
}


/// Parsed version: numeric core segments + optional suffix (GR-VER-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub core: Vec<u64>,
    pub suffix: Option<String>,
}

/// `metadata.version`-shaped version: 2-4 numeric segments + optional suffix.
pub fn parse_version(s: &str) -> Option<ParsedVersion> {
    let (core_str, suffix) = match s.split_once('-') {
        Some((c, rest)) => (c, Some(rest.to_string())),
        None => (s, None),
    };
    let segs: Vec<u64> = core_str
        .split('.')
        .map(|x| {
            if x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                x.parse::<u64>().ok()
            }
        })
        .collect::<Option<Vec<u64>>>()?;
    if !(2..=4).contains(&segs.len()) {
        return None;
    }
    if let Some(sx) = &suffix {
        if sx.is_empty()
            || !sx
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return None;
        }
    }
    Some(ParsedVersion {
        core: segs,
        suffix,
    })
}

/// Version ordering with zero-padded cores; a prerelease suffix sorts BEFORE
/// the plain release of the same core (semver rule, GR-VER-002).
pub fn cmp_versions(a: &ParsedVersion, b: &ParsedVersion) -> std::cmp::Ordering {
    let n = a.core.len().max(b.core.len());
    for i in 0..n {
        let x = a.core.get(i).copied().unwrap_or(0);
        let y = b.core.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    match (&a.suffix, &b.suffix) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

/// Range clause: comparator + version (GR-VER-003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeClause {
    pub op: RangeOp,
    pub version: ParsedVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

/// Parse a GR-VER-003 range: comparators AND-ed by spaces, `*`/empty = any.
/// `None` = invalid syntax (distinct from "any", which is `Some(vec![])`).
pub fn parse_version_range(s: &str) -> Option<Vec<RangeClause>> {
    let t = s.trim();
    if t.is_empty() || t == "*" {
        return Some(Vec::new());
    }
    // GR-VER-003 grammar allows whitespace between the comparator and the
    // version (`>= 18.0 < 19.0`); merge a bare operator token with the version
    // token that follows it so both spaced and glued forms parse alike.
    let words: Vec<&str> = t.split_whitespace().collect();
    let mut tokens: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if matches!(w, ">=" | "<=" | "!=" | ">" | "<" | "=" | "==") && i + 1 < words.len() {
            tokens.push(format!(
                "{}{}",
                if w == "==" { "=" } else { w },
                words[i + 1]
            ));
            i += 2;
        } else {
            tokens.push(w.to_string());
            i += 1;
        }
    }
    let mut out = Vec::new();
    for tok in &tokens {
        let tok = tok.as_str();
        let (op, ver) = if let Some(rest) = tok.strip_prefix(">=") {
            (RangeOp::Ge, rest)
        } else if let Some(rest) = tok.strip_prefix("<=") {
            (RangeOp::Le, rest)
        } else if let Some(rest) = tok.strip_prefix("!=") {
            (RangeOp::Ne, rest)
        } else if let Some(rest) = tok.strip_prefix('>') {
            (RangeOp::Gt, rest)
        } else if let Some(rest) = tok.strip_prefix('<') {
            (RangeOp::Lt, rest)
        } else if let Some(rest) = tok.strip_prefix('=') {
            (RangeOp::Eq, rest)
        } else {
            (RangeOp::Eq, tok)
        };
        let version = parse_version(ver.strip_prefix('v').unwrap_or(ver))?;
        out.push(RangeClause { op, version });
    }
    Some(out)
}

/// `true` when `version` satisfies every clause of `range` (AND semantics).
pub fn version_in_range(version: &str, clauses: &[RangeClause]) -> Option<bool> {
    let v = parse_version(version)?;
    Some(clauses.iter().all(|c| {
        let ord = cmp_versions(&v, &c.version);
        match c.op {
            RangeOp::Eq => ord.is_eq(),
            RangeOp::Ne => ord.is_ne(),
            RangeOp::Gt => ord.is_gt(),
            RangeOp::Ge => ord.is_ge(),
            RangeOp::Lt => ord.is_lt(),
            RangeOp::Le => ord.is_le(),
        }
    }))
}

/// Nested lookup helper for serde_yaml values (no JSON-pointer support there).
fn vget<'a>(v: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    Some(cur)
}

/// Leading version core `v?N(.N){1,3}` of a tag/version string (GR-VER-002).
pub fn tag_version_core(s: &str) -> Option<String> {
    let t = s.strip_prefix('v').unwrap_or(s);
    let b = t.as_bytes();
    let (mut i, mut segs, mut end) = (0usize, 0usize, 0usize);
    while i < b.len() {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            break;
        }
        segs += 1;
        end = i;
        if segs < 4 && i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        break;
    }
    if (2..=4).contains(&segs) {
        Some(t[..end].to_string())
    } else {
        None
    }
}

/// Image tag from an `image` ref (after the last `:` of the last path segment).
pub fn image_tag(image: &str) -> Option<&str> {
    let last = image.rsplit('/').next()?;
    match last.rsplit_once(':') {
        Some((_, tag)) if !tag.is_empty() => Some(tag),
        _ => None,
    }
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
    // Canonical key is the two-level ref `<publisher>/<id>` (GR-META-001);
    // publisher-less docs key on the bare id (transitional).
    let id = match doc
        .get("metadata")
        .and_then(|m| m.get("publisher"))
        .and_then(|v| v.as_str())
    {
        Some(p) if !p.is_empty() => format!("{p}/{id}"),
        _ => id,
    };
    let mut slots = PassportSlots {
        id,
        ..Default::default()
    };
    if let Some(ifaces) = view.interfaces {
        for p in ifaces.provides {
            slots.provides.insert(p.slot, p.capability);
        }
        for (slot, r) in ifaces.requires {
            if let Some(range) = r.version {
                slots.requires_versions.insert(slot.clone(), range);
            }
            slots.requires.insert(slot, r.capability);
        }
    }
    // Effective version (GR-VER-001): explicit or derived from a version-ful tag.
    slots.version = vget(&doc, &["metadata", "version"])
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            vget(&doc, &["workload", "container", "image"])
                .and_then(|v| v.as_str())
                .and_then(image_tag)
                .and_then(tag_version_core)
        });
    // Provider access declaration per provides slot (GR-CRED-002).
    if let Some(provides) = vget(&doc, &["interfaces", "provides"]).and_then(|v| v.as_sequence()) {
        for p in provides {
            let Some(slot) = p.get("slot").and_then(|v| v.as_str()) else {
                continue;
            };
            let mut decl = AccessDecl::default();
            if let Some(access) = p.get("access") {
                if let Some(vs) = access.get("fulfillment").and_then(|v| v.as_sequence()) {
                    decl.fulfillment =
                        vs.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
                if let Some(ps) = access.get("plugins").and_then(|v| v.as_sequence()) {
                    decl.plugins =
                        ps.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
            }
            if let Some(v) = p.get("version").and_then(|v| v.as_str()) {
                slots.provides_versions.insert(slot.to_string(), v.to_string());
            }
            slots.provides_access.insert(slot.to_string(), decl);
        }
    }
    // Consumer credential processes flattened to uses (GR-CRED-001).
    if let Some(procs) = doc.get("processes").and_then(|v| v.as_mapping()) {
        for (_, proc) in procs {
            let Some(uses) = proc.get("uses").and_then(|v| v.as_sequence()) else {
                continue;
            };
            for u in uses {
                let Some(slot) = u.get("slot").and_then(|v| v.as_str()) else {
                    continue;
                };
                let mut verbs = Vec::new();
                let mut resources = Vec::new();
                let mut plugins = Vec::new();
                if let Some(gs) = u.get("grants").and_then(|v| v.as_sequence()) {
                    for g in gs {
                        if let Some(vs) = g.get("verbs").and_then(|v| v.as_sequence()) {
                            verbs.extend(vs.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                        if let Some(rs) = g.get("resources").and_then(|v| v.as_sequence()) {
                            resources.extend(rs.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                    }
                }
                if let Some(ps) = u.get("plugins").and_then(|v| v.as_sequence()) {
                    plugins.extend(ps.iter().filter_map(|v| v.as_str().map(String::from)));
                }
                slots.process_uses.push(ProcessUse {
                    slot: slot.to_string(),
                    verbs,
                    resources,
                    plugins,
                });
            }
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
metadata: { publisher: test-org, id: youtrack, title: YouTrack, description: Test fixture, version: "1.0.0", passportRev: 3 }
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
metadata: { publisher: test-org, id: balancer-cilium-l7, title: Balancer, description: Test fixture, version: "1.0.0", passportRev: 1 }
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
metadata: { publisher: test-org, id: postgresql, title: PG, description: Test fixture, version: "18.0.0", passportRev: 6 }
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
        assert_eq!(slots.id, "test-org/youtrack");
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
        let res = dependency_closure(&catalog(), &[String::from("test-org/youtrack")]);
        assert_eq!(
            res.resolved,
            ["test-org/youtrack", "test-org/balancer-cilium-l7", "test-org/postgresql"]
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            res.providers.get("http-l7-gateway").map(|s| s.as_str()),
            Some("test-org/balancer-cilium-l7")
        );
        assert!(res.unresolved.is_empty());
    }

    #[test]
    fn closure_reports_unresolvable_capabilities() {
        let mut cat = catalog();
        cat.remove("test-org/postgresql");
        let res = dependency_closure(&cat, &[String::from("test-org/youtrack")]);
        assert_eq!(res.unresolved.len(), 1);
        assert_eq!(
            res.unresolved[0],
            ("test-org/youtrack".into(), "database".into(), "postgres-sql".into())
        );
    }

    #[test]
    fn closure_choice_is_deterministic_with_alternatives() {
        let mut cat = catalog();
        let extra = BALANCER_DOC.replace("balancer-cilium-l7", "aaa-first");
        cat.insert("test-org/aaa-first".into(), parse_passport_slots(&extra).unwrap());
        let res = dependency_closure(&cat, &[String::from("test-org/youtrack")]);
        assert_eq!(
            res.providers.get("http-l7-gateway").map(|s| s.as_str()),
            Some("test-org/aaa-first"),
            "lexicographically smallest provider wins"
        );
        assert_eq!(
            res.alternatives.get("http-l7-gateway"),
            Some(&vec![
                "test-org/aaa-first".to_string(),
                "test-org/balancer-cilium-l7".to_string()
            ])
        );
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn version_parse_and_compare() {
        let a = parse_version("17.11").unwrap();
        let b = parse_version("17.11.0").unwrap();
        assert_eq!(cmp_versions(&a, &b), std::cmp::Ordering::Equal); // zero-pad
        let rc = parse_version("1.2.3-rc.1").unwrap();
        let rel = parse_version("1.2.3").unwrap();
        assert_eq!(cmp_versions(&rc, &rel), std::cmp::Ordering::Less); // prerelease first
        assert!(parse_version("1").is_none()); // 2..4 segments only
    }

    #[test]
    fn version_ranges() {
        let clauses = parse_version_range(">=16.0 <18.0").unwrap();
        assert_eq!(clauses.len(), 2);
        assert_eq!(version_in_range("17.11", &clauses), Some(true));
        assert_eq!(version_in_range("18.0.0", &clauses), Some(false));
        assert_eq!(version_in_range("16.0", &clauses), Some(true));
        assert_eq!(version_in_range("15.9", &clauses), Some(false));
        let any = parse_version_range("*").unwrap();
        assert!(any.is_empty());
        assert_eq!(version_in_range("24.3.1.2672", &any), Some(true));
        let ne = parse_version_range("!=1.0.0").unwrap();
        assert_eq!(version_in_range("1.0.0", &ne), Some(false));
        assert_eq!(version_in_range("1.0.1", &ne), Some(true));
        assert!(parse_version_range(">=bogus").is_none());
    }
}
