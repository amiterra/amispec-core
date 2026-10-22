//! Reverse builder: FluxCD tree with AmiSpec provenance → `TopologyBlueprint`.
//!
//! Lossless for trees produced by [`crate::compile`]. Objects without provenance
//! are skipped with a warning (brownfield import lives in product tools).

use crate::provenance::*;
use amispec_schema::{
    Binding, Cluster, ClusterSecurity, ComponentInstance, ComponentResources, ComponentTopology,
    CrossClusterLink, CniConfig, Disc, Expose, ExternalResource, LoadBalancer, Node, NodeHardware,
    TopologyBlueprint, TopologyMetadata,
};
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

/// Decompile report.
#[derive(Debug, Default)]
pub struct DecompileReport {
    pub topology: Option<TopologyBlueprint>,
    pub files_scanned: usize,
    pub objects_with_provenance: usize,
    pub warnings: Vec<String>,
}

/// Decompile a directory tree (e.g. `out/clusters/`).
pub fn decompile_dir(root: &Path) -> Result<DecompileReport, DecompileError> {
    if !root.exists() {
        return Err(DecompileError::Io(format!("path not found: {}", root.display())));
    }
    let mut docs: Vec<Value> = Vec::new();
    let mut scanned = 0usize;
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        scanned += 1;
        let raw = std::fs::read_to_string(path)
            .map_err(|e| DecompileError::Io(format!("{}: {e}", path.display())))?;
        // multi-doc YAML
        for doc in serde_yaml::Deserializer::from_str(&raw) {
            let value = Value::deserialize(doc)
                .map_err(|e| DecompileError::Parse(format!("{}: {e}", path.display())))?;
            docs.push(value);
        }
    }
    let mut report = decompile(&docs);
    report.files_scanned = scanned;
    Ok(report)
}

/// Decompile loaded YAML documents.
pub fn decompile(docs: &[Value]) -> DecompileReport {
    let mut report = DecompileReport {
        files_scanned: docs.len(),
        ..Default::default()
    };

    let mut clusters: BTreeMap<String, ClusterBuilder> = BTreeMap::new();
    let mut externals: Vec<ExternalResource> = Vec::new();
    let mut links: Vec<CrossClusterLink> = Vec::new();

    for doc in docs {
        let kind = get_str(Some(doc), "kind").unwrap_or_default();
        let meta = doc.get("metadata");
        let labels = meta.and_then(|m| m.get("labels"));
        let annotations = meta.and_then(|m| m.get("annotations"));

        let component_id = get_str(labels, LABEL_COMPONENT_ID)
            .or_else(|| get_str(annotations, LABEL_COMPONENT_ID));
        let cluster_id = get_str(labels, LABEL_CLUSTER_ID).unwrap_or_else(|| "decompiled".into());
        let stage = get_str(labels, LABEL_STAGE);

        if component_id.is_some() || stage.is_some() {
            report.objects_with_provenance += 1;
        }

        match kind.as_str() {
            "NodeTuningProfile" => {
                let cb = clusters.entry(cluster_id).or_default();
                if let Some(node) = node_from_tuning(doc) {
                    cb.nodes.insert(node.id.clone(), node);
                }
            }
            "GatewayClass" => {
                let cb = clusters.entry(cluster_id).or_default();
                if let Some(lb) = lb_from_gateway(doc, annotations) {
                    cb.load_balancers.insert(lb.id.clone(), lb);
                }
            }
            "Deployment" | "StatefulSet" => {
                let Some(cid) = component_id.clone() else { continue };
                let cb = clusters.entry(cluster_id).or_default();
                let entry = cb.components.entry(cid.clone()).or_insert_with(|| {
                    let pin = get_str(labels, LABEL_PASSPORT)
                        .and_then(|p| parse_passport_pin(&p));
                    ComponentInstance {
                        id: cid,
                        passport: pin.as_ref().map(|p| p.0.clone()).unwrap_or_else(|| "unknown".into()),
                        version: pin.as_ref().map(|p| p.1.clone()).unwrap_or_else(|| "0.0.0".into()),
                        passport_rev: pin.map(|p| p.2).unwrap_or(1),
                        topology: ComponentTopology {
                            mode: "standalone".into(),
                            replicas: Some(1),
                            committed_replicas: None,
                            shards: None,
                            autoscaling: None,
                        },
                        resources: ComponentResources {
                            cpu_cores: 1.0,
                            memory_mb: 256,
                        },
                        zone: get_str(labels, LABEL_ZONE),
                        group: None,
                        config: None,
                        backup_target: None,
                        bootstrap: None,
                        bindings: Vec::new(),
                        expose: Vec::new(),
                    }
                });
                apply_workload_facts(entry, doc, labels, annotations);
            }
            "Secret" => {
                let Some(cid) = component_id.clone() else { continue };
                let cb = clusters.entry(cluster_id).or_default();
                let comp = cb
                    .components
                    .entry(cid.clone())
                    .or_insert_with(|| blank_component(&cid));
                if let Some(edges) = get_str(annotations, LABEL_BINDING_EDGE) {
                    for edge in edges.split(',').filter(|s| !s.is_empty()) {
                        if let Some(b) = parse_edge(edge, &cid) {
                            if !comp
                                .bindings
                                .iter()
                                .any(|x| x.to == b.to && x.to_slot == b.to_slot)
                            {
                                comp.bindings.push(b);
                            }
                        }
                    }
                }
                if let Some(delta) = get_str(annotations, LABEL_USER_SPEC_DELTA) {
                    apply_user_delta(comp, &delta);
                }
            }
            "HorizontalPodAutoscaler" => {
                let Some(cid) = component_id.clone() else { continue };
                let cb = clusters.entry(cluster_id).or_default();
                let comp = cb
                    .components
                    .entry(cid.clone())
                    .or_insert_with(|| blank_component(&cid));
                if let Some(as_) = hpa_to_autoscaling(doc) {
                    comp.topology.autoscaling = Some(as_);
                }
            }
            "HTTPRoute" => {
                let Some(cid) = component_id.clone() else { continue };
                let cb = clusters.entry(cluster_id).or_default();
                let comp = cb
                    .components
                    .entry(cid.clone())
                    .or_insert_with(|| blank_component(&cid));
                if let Some(ex) = route_to_expose(doc) {
                    if !comp.expose.iter().any(|e| e.endpoint == ex.endpoint) {
                        comp.expose.push(ex);
                    }
                }
            }
            "ConfigMap" => {
                if get_str(labels, "amispec.io/external-id").is_some() {
                    if let Some(e) = external_from_cm(doc, annotations) {
                        externals.push(e);
                    }
                } else if get_str(annotations, "amispec.io/from-cluster").is_some() {
                    if let Some(l) = link_from_cm(doc, annotations) {
                        links.push(l);
                    }
                }
            }
            _ => {}
        }
    }

    if clusters.is_empty() && externals.is_empty() {
        report.warnings.push(
            "no AmiSpec provenance found; decompile produced an empty topology".into(),
        );
        report.topology = None;
        return report;
    }

    let mut cluster_list: Vec<Cluster> = Vec::new();
    for (id, mut cb) in clusters {
        // cluster-level bindings derived from component bindings
        let mut cluster_bindings = Vec::new();
        for c in cb.components.values() {
            for b in &c.bindings {
                let mut bb = b.clone();
                bb.from = Some(c.id.clone());
                cluster_bindings.push(bb);
            }
        }
        let domain = cb.domain.take().unwrap_or_else(|| format!("{id}.local"));
        let name = cb.name.take().unwrap_or_else(|| id.clone());
        cluster_list.push(Cluster {
            id,
            name,
            domain,
            security: Some(ClusterSecurity {
                sops_recipients: std::mem::take(&mut cb.sops_recipients),
                implicit_telemetry_layer: Some(true),
                image_registry_policy: None,
                image_pull_secret_refs: None,
                control_plane_quorum_mode: None,
                etcd_backup_target: None,
            }),
            cni: cb.cni.take().unwrap_or(CniConfig {
                engine: "cilium-ebpf".into(),
                cluster_mesh_id: 1,
                kube_proxy_replacement: Some(true),
                hubble_live_map: Some(true),
                wireguard_encryption: Some(true),
                mtu_discovery_and_mss_clamp: Some(true),
                fqdn_cache_min_ttl_sec: Some(3600),
            }),
            nodes: cb.nodes.into_values().collect(),
            components: cb.components.into_values().collect(),
            bindings: cluster_bindings,
            load_balancers: cb.load_balancers.into_values().collect(),
            maintenance_window: cb.maintenance_window,
        });
    }

    report.topology = Some(TopologyBlueprint {
        api_version: "topology.amispec.io/v1".into(),
        kind: "TopologyBlueprint".into(),
        metadata: TopologyMetadata {
            project_id: "decompiled".into(),
            organization: "amispec".into(),
            git_mode: None,
        },
        clusters: cluster_list,
        external_resources: externals,
        cross_cluster_links: links,
    });
    report
}

#[derive(Default)]
struct ClusterBuilder {
    maintenance_window: Option<String>,
    name: Option<String>,
    domain: Option<String>,
    sops_recipients: Vec<String>,
    cni: Option<CniConfig>,
    nodes: BTreeMap<String, Node>,
    components: BTreeMap<String, ComponentInstance>,
    load_balancers: BTreeMap<String, LoadBalancer>,
}

fn blank_component(id: &str) -> ComponentInstance {
    ComponentInstance {
        id: id.into(),
        passport: "unknown".into(),
        version: "0.0.0".into(),
        passport_rev: 1,
        topology: ComponentTopology {
            mode: "standalone".into(),
            replicas: Some(1),
            committed_replicas: None,
            shards: None,
            autoscaling: None,
        },
        resources: ComponentResources {
            cpu_cores: 1.0,
            memory_mb: 256,
        },
        zone: None,
        group: None,
        config: None,
        backup_target: None,
        bootstrap: None,
        bindings: Vec::new(),
        expose: Vec::new(),
    }
}

fn get<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    v.and_then(|m| m.get(key))
}

fn get_str(v: Option<&Value>, key: &str) -> Option<String> {
    get(v, key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn yaml_path<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    Some(cur)
}

fn meta_name(doc: &Value) -> Option<String> {
    get_str(doc.get("metadata"), "name")
}

fn node_from_tuning(doc: &Value) -> Option<Node> {
    let name = meta_name(doc)?;
    let node_id = name
        .split_once('-')
        .map(|(_, n)| n.to_string())
        .unwrap_or(name);
    let spec = doc.get("spec")?;
    let hw = spec.get("hardware")?;
    Some(Node {
        id: node_id,
        role: get_str(Some(spec), "role").unwrap_or_else(|| "control-plane-worker".into()),
        pricing_tier: None,
        failure_domain_zone: get_str(Some(spec), "failureDomainZone"),
        monthly_cost_usd: None,
        hardware: NodeHardware {
            arch: get_str(Some(hw), "arch"),
            cpu_cores: get(Some(hw), "cpuCores").and_then(|v| v.as_f64()).unwrap_or(1.0),
            memory_mb: get(Some(hw), "memoryMb").and_then(|v| v.as_u64()).unwrap_or(1024),
            system_reserved_mb: get(Some(hw), "systemReservedMb").and_then(|v| v.as_u64()),
            system_disk_reserved_gb: get(Some(hw), "systemDiskReservedGb").and_then(|v| v.as_u64()),
            lvm_snapshot_reserve_percent: get(Some(hw), "lvmSnapshotReservePercent")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
            disks: get(Some(spec), "disks")
                .and_then(|d| d.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .map(|d| Disc {
                            name: get_str(Some(d), "name").unwrap_or_default(),
                            tier: get_str(Some(d), "tier").unwrap_or_default(),
                            size_gb: get(Some(d), "sizeGb").and_then(|v| v.as_u64()).unwrap_or(1),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        },
    })
}

fn lb_from_gateway(doc: &Value, annotations: Option<&Value>) -> Option<LoadBalancer> {
    let name = meta_name(doc)?;
    let labels = get(doc.get("metadata"), "labels")?;
    let id = get_str(Some(labels), "amispec.io/lb-id").unwrap_or_else(|| {
        name.split_once('-')
            .map(|(_, r)| r.to_string())
            .unwrap_or(name)
    });
    Some(LoadBalancer {
        id,
        layer: get_str(Some(labels), "amispec.io/lb-layer")
            .unwrap_or_else(|| "l7-gateway".into()),
        provider: get_str(annotations, "amispec.io/lb-provider")
            .unwrap_or_else(|| "cilium-envoy".into()),
        upstream_edge: get_str(annotations, "amispec.io/upstream-edge"),
        trusted_proxy_source: None,
        forwarding_mode: get_str(annotations, "amispec.io/forwarding-mode"),
        floating_ip_ref: None,
        proxy_protocol_v2: None,
        http3_quic: None,
        tls: get_str(annotations, "amispec.io/tls"),
    })
}

fn apply_workload_facts(
    comp: &mut ComponentInstance,
    doc: &Value,
    labels: Option<&Value>,
    annotations: Option<&Value>,
) {
    let spec = doc.get("spec");
    if let Some(rep) = get(spec, "replicas").and_then(|v| v.as_u64()) {
        comp.topology.replicas = Some(rep as u32);
    }
    if let Some(ns) = get_str(doc.get("metadata"), "namespace") {
        comp.zone = Some(ns);
    }
    if let Some(p) = get_str(labels, LABEL_PASSPORT) {
        if let Some((id, ver, rev)) = parse_passport_pin(&p) {
            comp.passport = id;
            comp.version = ver;
            comp.passport_rev = rev;
        }
    }
    if let Some(delta) = get_str(annotations, LABEL_USER_SPEC_DELTA) {
        apply_user_delta(comp, &delta);
    }
    if let Some(mem) = get(spec, "template")
        .and_then(|t| t.get("spec"))
        .and_then(|p| p.get("containers"))
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("resources"))
        .and_then(|r| r.get("requests"))
        .and_then(|r| r.get("memory"))
        .and_then(|v| v.as_str())
    {
        let digits: String = mem.chars().filter(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            comp.resources.memory_mb = n;
        }
    }
}

fn apply_user_delta(comp: &mut ComponentInstance, delta_json: &str) {
    // delta is stored as JSON string in an annotation
    let Ok(v) = serde_json::from_str::<serde_json::Value>(delta_json) else {
        return;
    };
    if let Some(mode) = v.pointer("/topology/mode").and_then(|x| x.as_str()) {
        comp.topology.mode = mode.to_string();
    }
    if let Some(rep) = v.pointer("/topology/replicas").and_then(|x| x.as_u64()) {
        comp.topology.replicas = Some(rep as u32);
    }
    if let Some(comm) = v.pointer("/topology/committedReplicas").and_then(|x| x.as_u64()) {
        comp.topology.committed_replicas = Some(comm as u32);
    }
    if let Some(cpu) = v.pointer("/resources/cpuCores").and_then(|x| x.as_f64()) {
        comp.resources.cpu_cores = cpu;
    }
    if let Some(mem) = v.pointer("/resources/memoryMb").and_then(|x| x.as_u64()) {
        comp.resources.memory_mb = mem;
    }
    if let Some(zone) = v.pointer("/zone").and_then(|x| x.as_str()) {
        comp.zone = Some(zone.to_string());
    }
    if let Some(g) = v.pointer("/group").and_then(|x| x.as_str()) {
        comp.group = Some(g.to_string());
    }
    if let Some(bt) = v.pointer("/backupTarget").and_then(|x| x.as_str()) {
        comp.backup_target = Some(bt.to_string());
    }
    if let Some(cfg) = v.get("config").and_then(|c| c.as_object()) {
        let mut map = BTreeMap::new();
        for (k, val) in cfg {
            map.insert(k.clone(), val.clone());
        }
        comp.config = Some(map);
    }
}

fn parse_edge(edge: &str, from: &str) -> Option<Binding> {
    // `from->to:slot`
    let (left, slot) = match edge.split_once(':') {
        Some((l, s)) => (l, Some(s.to_string()).filter(|s| !s.is_empty())),
        None => (edge, None),
    };
    let (_f, to) = left.split_once("->")?;
    Some(Binding {
        from: Some(from.to_string()),
        to: to.to_string(),
        to_slot: slot,
        as_requirement: None,
        env_prefix: None,
        secret_rotation_epoch: None,
        type_: None,
        delivery_guarantee: None,
        outbox_source_requirement: None,
    })
}


fn hpa_to_autoscaling(doc: &Value) -> Option<amispec_schema::Autoscaling> {
    let spec = doc.get("spec")?;
    let min = get(Some(spec), "minReplicas").and_then(|v| v.as_u64())? as u32;
    let max = get(Some(spec), "maxReplicas").and_then(|v| v.as_u64())? as u32;
    let cooldown = yaml_path(
        spec,
        &["behavior", "scaleDown", "stabilizationWindowSeconds"],
    )
    .and_then(|v| v.as_u64())
    .map(|v| v as u32);
    Some(amispec_schema::Autoscaling {
        min_replicas: min,
        max_replicas: max,
        cooldown_seconds: cooldown,
        target_cpu_percent: None,
    })
}

fn route_to_expose(doc: &Value) -> Option<Expose> {
    let name = meta_name(doc)?;
    let labels = get(doc.get("metadata"), "labels")?;
    let endpoint = name.split_once('-').map(|(_, e)| e.to_string()).unwrap_or(name);
    let hostname = doc
        .get("spec")
        .and_then(|s| s.get("hostnames"))
        .and_then(|h| h.get(0))
        .and_then(|h| h.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Some(Expose {
        endpoint,
        via_balancer: get_str(Some(labels), "amispec.io/via-balancer").unwrap_or_default(),
        scope: get_str(Some(labels), "amispec.io/scope").unwrap_or_else(|| "public".into()),
        subdomain: None,
        hostname,
        path_prefix: yaml_path(doc, &["spec", "rules", "0", "matches", "0", "path", "value"])
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn external_from_cm(doc: &Value, annotations: Option<&Value>) -> Option<ExternalResource> {
    let labels = get(doc.get("metadata"), "labels")?;
    let id = get_str(Some(labels), "amispec.io/external-id").or_else(|| meta_name(doc))?;
    let data = doc.get("data")?;
    let data = Some(data);
    Some(ExternalResource {
        id,
        passport: get_str(annotations, "amispec.io/passport-ref")
            .unwrap_or_else(|| "external".into()),
        role: get_str(data, "role").unwrap_or_else(|| "backup-vault".into()),
        endpoint_fqdn: get_str(data, "endpointFqdn").unwrap_or_default(),
        port: get_str(data, "port").and_then(|p| p.parse().ok()),
        transport: get_str(annotations, "amispec.io/transport"),
        region: get_str(data, "region"),
        bucket: get_str(data, "bucket"),
        secret_ref: Some(get_str(annotations, "amispec.io/secret-ref")
            .unwrap_or_else(|| "sops://unknown".into())),
    })
}

fn link_from_cm(doc: &Value, annotations: Option<&Value>) -> Option<CrossClusterLink> {
    let a = annotations?;
    let data = doc.get("data");
    Some(CrossClusterLink {
        id: meta_name(doc)?,
        from_cluster: get_str(Some(a), "amispec.io/from-cluster")?,
        from_component: get_str(Some(a), "amispec.io/from-component").unwrap_or_default(),
        to_cluster: get_str(Some(a), "amispec.io/to-cluster")?,
        to_component: get_str(Some(a), "amispec.io/to-component").unwrap_or_default(),
        to_slot: get_str(Some(a), "amispec.io/to-slot").filter(|s| !s.is_empty()),
        relation_type: get_str(Some(a), "amispec.io/relation-type")
            .unwrap_or_else(|| "active-passive-replication".into()),
        transport: get_str(data, "transport"),
        encryption: get_str(data, "encryption"),
        max_bandwidth_mbps: get_str(data, "maxBandwidthMbps").and_then(|s| s.parse().ok()),
        rpo_target_sec: get_str(data, "rpoTargetSec").and_then(|s| s.parse().ok()),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum DecompileError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

use serde::Deserialize as _;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;

    #[test]
    fn get_str_reads_mapping() {
        let v: Value = serde_yaml::from_str("name: web\n").unwrap();
        assert_eq!(get_str(Some(&v), "name").as_deref(), Some("web"));
        assert!(get_str(Some(&v), "missing").is_none());
        assert!(get_str(None, "name").is_none());
    }

    #[test]
    fn yaml_path_walks_nested() {
        let v: Value = serde_yaml::from_str("a:\n  b:\n    c: 1\n").unwrap();
        assert!(yaml_path(&v, &["a", "b", "c"]).is_some());
        assert!(yaml_path(&v, &["a", "x"]).is_none());
    }

    #[test]
    fn parse_edge_formats() {
        let b = parse_edge("web->db:sql-cluster", "web").unwrap();
        assert_eq!(b.to, "db");
        assert_eq!(b.to_slot.as_deref(), Some("sql-cluster"));
        assert_eq!(b.from.as_deref(), Some("web"));
        let b2 = parse_edge("web->queue", "web").unwrap();
        assert_eq!(b2.to, "queue");
        assert!(b2.to_slot.is_none());
        assert!(parse_edge("noarrow", "web").is_none());
    }

    #[test]
    fn parse_user_delta_overlay() {
        let mut c = blank_component("web");
        apply_user_delta(
            &mut c,
            r#"{"topology":{"mode":"strict-ha","replicas":4},"resources":{"cpuCores":2,"memoryMb":1024},"backupTarget":"s3"}"#,
        );
        assert_eq!(c.topology.mode, "strict-ha");
        assert_eq!(c.topology.replicas, Some(4));
        assert_eq!(c.resources.memory_mb, 1024);
        assert_eq!(c.backup_target.as_deref(), Some("s3"));
    }
}
