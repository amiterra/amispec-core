//! AmiSpec schema types and version pins.
//!
//! This crate is the Rust projection of the normative CUE meta-schemas
//! (`schemas/component_passport.cue`, `schemas/topology_spec.cue`) from the
//! AmiSpec standard repository. It does **not** replace CUE validation; use
//! `amispec-validate` for full structural checks against the CUE schemas.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// AmiSpec standard version this crate targets (see `amispec` repo).
pub const AMISPEC_STANDARD_VERSION: &str = "1.0.0";

/// `apiVersion` for ComponentPassport documents.
pub const API_VERSION_PASSPORT: &str = "catalog.amispec.io/v1";
/// `apiVersion` for TopologyBlueprint documents.
pub const API_VERSION_TOPOLOGY: &str = "topology.amispec.io/v1";
/// `apiVersion` for CanvasLayout documents.
pub const API_VERSION_LAYOUT: &str = "topology.amispec.io/v1";

/// Discriminator of an AmiSpec document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    ComponentPassport,
    TopologyBlueprint,
    CanvasLayout,
}

impl DocumentKind {
    pub fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "ComponentPassport" => Some(Self::ComponentPassport),
            "TopologyBlueprint" => Some(Self::TopologyBlueprint),
            "CanvasLayout" => Some(Self::CanvasLayout),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentPassport => "ComponentPassport",
            Self::TopologyBlueprint => "TopologyBlueprint",
            Self::CanvasLayout => "CanvasLayout",
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
pub const TOPOLOGY_MODES: &[&str] = &[
    "standalone",
    "degraded-ha",
    "strict-ha",
    "sharded-cluster",
];

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Expose {
    pub endpoint: String,
    #[serde(rename = "viaBalancer")]
    pub via_balancer: String,
    pub scope: String,
    #[serde(default)]
    pub subdomain: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default, rename = "pathPrefix")]
    pub path_prefix: Option<String>,
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
}
