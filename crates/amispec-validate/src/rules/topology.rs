//! TopologyBlueprint structural + semantic rules.

use crate::patterns::{is_age_key, is_sha256_digest, is_sops_uri, is_slug, is_script_ref};
use crate::report::Finding;
use super::deep;
use crate::value::*;

const CNI_ENGINE: &str = "cilium-ebpf";
const TOPOLOGY_MODES: &[&str] = &["standalone", "degraded-ha", "strict-ha", "sharded-cluster"];
const GIT_MODES: &[&str] = &["managed-embedded", "byo-git"];
const NODE_ROLES: &[&str] = &["control-plane-worker", "control-plane-only", "worker-only"];
const PRICING: &[&str] = &["micro-vps", "standard-node", "heavy-bare-metal"];
const ARCH: &[&str] = &["amd64", "arm64"];
const MEDIA_TIERS: &[&str] = &["nvme-local", "ssd-network", "hdd-bulk", "ram-tmpfs"];
const LB_LAYERS: &[&str] = &["edge-proxy", "l7-gateway", "l4-balancer"];
const EXTERNAL_ROLES: &[&str] = &["migration-source", "hybrid-bridge", "backup-vault"];
const RELATIONS: &[&str] = &[
    "active-passive-replication",
    "global-service-mesh",
    "telemetry-and-events-uplink",
];
const BINDING_TYPES: &[&str] = &["service-binding", "live-migration-replica", "oidc-protection"];
const DELIVERY: &[&str] = &["direct", "transactional-outbox"];
const EXPOSE_SCOPES: &[&str] = &["public", "protected"];

pub fn check(root: &Map, out: &mut Vec<Finding>) {
    // metadata
    let Some(meta) = root.get("metadata") else {
        out.push(Finding::error("metadata", "required", "metadata is required"));
        return;
    };
    if let Some(pid) = req_str(meta, "projectId", "metadata", out) {
        if !is_slug(&pid) {
            out.push(Finding::error(
                "metadata.projectId",
                "id-regex",
                format!("projectId `{pid}` MUST match ^[a-z0-9-]+$"),
            ));
        }
    }
    req_str(meta, "organization", "metadata", out);
    check_enum(meta, "gitMode", "metadata", GIT_MODES, out, "git-mode-enum");

    // externalResources
    if let Some(exts) = root.get("externalResources").and_then(as_seq) {
        let mut ids = std::collections::BTreeSet::new();
        for (i, e) in exts.iter().enumerate() {
            let epath = format!("externalResources[{i}]");
            if let Some(id) = req_str(e, "id", &epath, out) {
                if !is_slug(&id) {
                    out.push(Finding::error(
                        format!("{epath}.id"),
                        "id-regex",
                        format!("id `{id}` MUST match ^[a-z0-9-]+$"),
                    ));
                }
                if !ids.insert(id.clone()) {
                    out.push(Finding::error(
                        format!("{epath}.id"),
                        "id-unique",
                        format!("duplicate externalResources id `{id}`"),
                    ));
                }
            }
            req_str(e, "passport", &epath, out);
            req_enum(e, "role", &epath, EXTERNAL_ROLES, out, "external-role-enum");
            req_str(e, "endpointFqdn", &epath, out);
            check_int_range(e, "port", &epath, 1, Some(65535), out, "port-range");
            match opt_str(e, "secretRef") {
                Some(s) if is_sops_uri(s) => {}
                Some(s) => out.push(Finding::error(
                    format!("{epath}.secretRef"),
                    "sops-uri",
                    format!("`{s}` MUST match ^sops://.*$"),
                )),
                None => out.push(Finding::error(
                    format!("{epath}.secretRef"),
                    "required",
                    "secretRef is required",
                )),
            }
        }
    }

    // clusters (non-empty)
    let Some(clusters) = root.get("clusters").and_then(as_seq) else {
        out.push(Finding::error(
            "clusters",
            "required",
            "clusters MUST be a non-empty list",
        ));
        return;
    };
    if clusters.is_empty() {
        out.push(Finding::error(
            "clusters",
            "clusters-min-items",
            "clusters MUST be a non-empty list",
        ));
        return;
    }

    let mut mesh_ids: std::collections::BTreeMap<i64, String> = Default::default();
    let mut cluster_ids: std::collections::BTreeSet<String> = Default::default();

    for (ci, cluster) in clusters.iter().enumerate() {
        let cpath = format!("clusters[{ci}]");
        let cid = match req_str(cluster, "id", &cpath, out) {
            Some(id) => {
                if !is_slug(&id) {
                    out.push(Finding::error(
                        format!("{cpath}.id"),
                        "id-regex",
                        format!("cluster id `{id}` MUST match ^[a-z0-9-]+$"),
                    ));
                }
                if !cluster_ids.insert(id.clone()) {
                    out.push(Finding::error(
                        format!("{cpath}.id"),
                        "id-unique",
                        format!("duplicate cluster id `{id}`"),
                    ));
                }
                id
            }
            None => format!("clusters[{ci}]"),
        };
        req_str(cluster, "name", &cpath, out);
        req_str(cluster, "domain", &cpath, out);

        // security / sops
        let Some(sec) = cluster.get("security") else {
            out.push(Finding::error(
                format!("{cpath}.security"),
                "required",
                "security is required",
            ));
            continue;
        };
        match sec.get("sopsRecipients").and_then(as_seq) {
            Some(list) if !list.is_empty() => {
                for (ki, k) in list.iter().enumerate() {
                    let Some(s) = as_str(k) else {
                        out.push(Finding::error(
                            format!("{cpath}.security.sopsRecipients[{ki}]"),
                            "type-string",
                            "recipient MUST be a string",
                        ));
                        continue;
                    };
                    if !is_age_key(s) {
                        out.push(Finding::error(
                            format!("{cpath}.security.sopsRecipients[{ki}]"),
                            "sops-key-regex",
                            format!("`{s}` MUST match ^age1[a-z0-9]+$"),
                        ));
                    }
                }
            }
            _ => out.push(Finding::error(
                format!("{cpath}.security.sopsRecipients"),
                "sops-min-items",
                "sopsRecipients MUST be a non-empty list",
            )),
        }
        if let Some(refs) = sec.get("imagePullSecretRefs").and_then(as_seq) {
            for (ri, r) in refs.iter().enumerate() {
                if let Some(s) = as_str(r) {
                    if !is_sops_uri(s) {
                        out.push(Finding::error(
                            format!("{cpath}.security.imagePullSecretRefs[{ri}]"),
                            "sops-uri",
                            format!("`{s}` MUST match ^sops://.*$"),
                        ));
                    }
                }
            }
        }

        // cni
        let Some(cni) = cluster.get("cni") else {
            out.push(Finding::error(format!("{cpath}.cni"), "required", "cni is required"));
            continue;
        };
        if let Some(eng) = opt_str(cni, "engine") {
            if eng != CNI_ENGINE {
                out.push(Finding::error(
                    format!("{cpath}.cni.engine"),
                    "cni-engine-enum",
                    format!("engine `{eng}` MUST be `cilium-ebpf`"),
                ));
            }
        } else {
            out.push(Finding::error(
                format!("{cpath}.cni.engine"),
                "required",
                "cni.engine is required",
            ));
        }
        deep::check_cni_literal(cni, &format!("{cpath}.cni"), out);
        match get(cni, "clusterMeshId").and_then(as_i64) {
            Some(id) if (1..=50).contains(&id) => {
                if let Some(prev) = mesh_ids.insert(id, cid.clone()) {
                    out.push(Finding::error(
                        format!("{cpath}.cni.clusterMeshId"),
                        "cluster-mesh-unique",
                        format!("clusterMeshId {id} already used by `{prev}`"),
                    ));
                }
            }
            Some(id) => out.push(Finding::error(
                format!("{cpath}.cni.clusterMeshId"),
                "cluster-mesh-range",
                format!("clusterMeshId {id} MUST be in 1..=50"),
            )),
            None => out.push(Finding::error(
                format!("{cpath}.cni.clusterMeshId"),
                "required",
                "clusterMeshId is required",
            )),
        }

        // nodes
        let Some(nodes) = cluster.get("nodes").and_then(as_seq) else {
            out.push(Finding::error(format!("{cpath}.nodes"), "required", "nodes is required"));
            continue;
        };
        for (ni, node) in nodes.iter().enumerate() {
            let npath = format!("{cpath}.nodes[{ni}]");
            req_str(node, "id", &npath, out);
            req_enum(node, "role", &npath, NODE_ROLES, out, "node-role-enum");
            check_enum(node, "pricingTier", &npath, PRICING, out, "pricing-enum");
            let Some(hw) = node.get("hardware") else {
                out.push(Finding::error(
                    format!("{npath}.hardware"),
                    "required",
                    "hardware is required",
                ));
                continue;
            };
            check_enum(hw, "arch", &format!("{npath}.hardware"), ARCH, out, "arch-enum");
            match get(hw, "cpuCores").and_then(as_f64) {
                Some(c) if c > 0.0 => {}
                Some(c) => out.push(Finding::error(
                    format!("{npath}.hardware.cpuCores"),
                    "cpu-positive",
                    format!("cpuCores {c} MUST be > 0"),
                )),
                None => out.push(Finding::error(
                    format!("{npath}.hardware.cpuCores"),
                    "required",
                    "cpuCores is required",
                )),
            }
            match get(hw, "memoryMb").and_then(as_i64) {
                Some(m) if m >= 1 => {}
                Some(m) => out.push(Finding::error(
                    format!("{npath}.hardware.memoryMb"),
                    "mem-min",
                    format!("memoryMb {m} MUST be >= 1"),
                )),
                None => out.push(Finding::error(
                    format!("{npath}.hardware.memoryMb"),
                    "required",
                    "memoryMb is required",
                )),
            }
            check_int_range(
                hw,
                "systemReservedMb",
                &format!("{npath}.hardware"),
                0,
                None,
                out,
                "sys-reserved",
            );
            check_int_range(
                hw,
                "lvmSnapshotReservePercent",
                &format!("{npath}.hardware"),
                0,
                Some(100),
                out,
                "lvm-reserve",
            );
            if let Some(disks) = hw.get("disks").and_then(as_seq) {
                for (di, d) in disks.iter().enumerate() {
                    let dpath = format!("{npath}.hardware.disks[{di}]");
                    req_str(d, "name", &dpath, out);
                    req_enum(d, "tier", &dpath, MEDIA_TIERS, out, "media-tier-enum");
                    match get(d, "sizeGb").and_then(as_i64) {
                        Some(s) if s >= 1 => {}
                        Some(s) => out.push(Finding::error(
                            format!("{dpath}.sizeGb"),
                            "disk-size",
                            format!("sizeGb {s} MUST be >= 1"),
                        )),
                        None => out.push(Finding::error(
                            format!("{dpath}.sizeGb"),
                            "required",
                            "sizeGb is required",
                        )),
                    }
                }
            }
        }

        // load balancers
        if let Some(lbs) = cluster.get("loadBalancers").and_then(as_seq) {
            for (li, lb) in lbs.iter().enumerate() {
                let lpath = format!("{cpath}.loadBalancers[{li}]");
                req_str(lb, "id", &lpath, out);
                req_enum(lb, "layer", &lpath, LB_LAYERS, out, "lb-layer-enum");
                req_str(lb, "provider", &lpath, out);
            }
        }

        // components
        let Some(comps) = cluster.get("components").and_then(as_seq) else {
            out.push(Finding::error(
                format!("{cpath}.components"),
                "required",
                "components is required (may be empty)",
            ));
            continue;
        };
        let mut comp_ids = std::collections::BTreeSet::new();
        for (i, comp) in comps.iter().enumerate() {
            let ppath = format!("{cpath}.components[{i}]");
            let comp_id = match req_str(comp, "id", &ppath, out) {
                Some(id) => {
                    if !is_slug(&id) {
                        out.push(Finding::error(
                            format!("{ppath}.id"),
                            "id-regex",
                            format!("component id `{id}` MUST match ^[a-z0-9-]+$"),
                        ));
                    }
                    if !comp_ids.insert(id.clone()) {
                        out.push(Finding::error(
                            format!("{ppath}.id"),
                            "id-unique",
                            format!("duplicate component id `{id}`"),
                        ));
                    }
                    id
                }
                None => format!("components[{i}]"),
            };
            req_str(comp, "passport", &ppath, out);
            req_str(comp, "version", &ppath, out);
            match get(comp, "passportRev").and_then(as_i64) {
                Some(n) if n >= 1 => {}
                Some(n) => out.push(Finding::error(
                    format!("{ppath}.passportRev"),
                    "passportRev-min",
                    format!("passportRev {n} MUST be >= 1"),
                )),
                None => out.push(Finding::error(
                    format!("{ppath}.passportRev"),
                    "required",
                    "passportRev is required",
                )),
            }

            if let Some(lr) = opt_str(comp, "licenseSecretRef") {
                if !is_sops_uri(lr) {
                    out.push(Finding::error(
                        format!("{ppath}.licenseSecretRef"),
                        "sops-uri",
                        format!("`{lr}` MUST match ^sops://.*$"),
                    ));
                }
            }
            if let Some(ir) = opt_str(comp, "imagePullSecretRef") {
                if !is_sops_uri(ir) {
                    out.push(Finding::error(
                        format!("{ppath}.imagePullSecretRef"),
                        "sops-uri",
                        format!("`{ir}` MUST match ^sops://.*$"),
                    ));
                }
            }

            let Some(topo) = comp.get("topology") else {
                out.push(Finding::error(
                    format!("{ppath}.topology"),
                    "required",
                    "topology is required",
                ));
                continue;
            };
            req_enum(
                topo,
                "mode",
                &format!("{ppath}.topology"),
                TOPOLOGY_MODES,
                out,
                "topology-mode-enum",
            );
            if let (Some(rep), Some(comm)) = (
                get(topo, "replicas").and_then(as_u64),
                get(topo, "committedReplicas").and_then(as_u64),
            ) {
                if comm > rep {
                    out.push(Finding::error(
                        format!("{ppath}.topology.committedReplicas"),
                        "committed-replicas",
                        format!("committedReplicas {comm} > replicas {rep}"),
                    ));
                }
            }
            if let Some(as_) = get(topo, "autoscaling") {
                let apath = format!("{ppath}.topology.autoscaling");
                if let Some(cm) = get(as_, "customMetric") {
                    deep::check_custom_metric(cm, &format!("{apath}.customMetric"), out);
                }
                match get(as_, "minReplicas").and_then(as_u64) {
                    Some(n) if n >= 1 => {}
                    _ => out.push(Finding::error(
                        format!("{apath}.minReplicas"),
                        "required",
                        "minReplicas MUST be >= 1",
                    )),
                }
                match get(as_, "maxReplicas").and_then(as_u64) {
                    Some(n) if n >= 1 => {}
                    _ => out.push(Finding::error(
                        format!("{apath}.maxReplicas"),
                        "required",
                        "maxReplicas MUST be >= 1",
                    )),
                }
                check_int_range(as_, "targetCpuPercent", &apath, 10, Some(95), out, "cpu-target");
            }

            let Some(res) = comp.get("resources") else {
                out.push(Finding::error(
                    format!("{ppath}.resources"),
                    "required",
                    "resources is required",
                ));
                continue;
            };
            match get(res, "cpuCores").and_then(as_f64) {
                Some(c) if c > 0.0 => {}
                Some(c) => out.push(Finding::error(
                    format!("{ppath}.resources.cpuCores"),
                    "cpu-positive",
                    format!("cpuCores {c} MUST be > 0"),
                )),
                None => out.push(Finding::error(
                    format!("{ppath}.resources.cpuCores"),
                    "required",
                    "cpuCores is required",
                )),
            }
            match get(res, "memoryMb").and_then(as_i64) {
                Some(m) if m >= 64 => {}
                Some(m) => out.push(Finding::error(
                    format!("{ppath}.resources.memoryMb"),
                    "mem-min",
                    format!("memoryMb {m} MUST be >= 64"),
                )),
                None => out.push(Finding::error(
                    format!("{ppath}.resources.memoryMb"),
                    "required",
                    "memoryMb is required",
                )),
            }

            if let Some(st) = comp.get("storage") {
                check_int_range(st, "sizeGb", &format!("{ppath}.storage"), 1, None, out, "disk-size");
                check_enum(
                    st,
                    "mediaTier",
                    &format!("{ppath}.storage"),
                    MEDIA_TIERS,
                    out,
                    "media-tier-enum",
                );
            }

            if let Some(wo) = comp.get("workloadOverride") {
                if let Some(d) = opt_str(wo, "imageDigest") {
                    if !is_sha256_digest(d) {
                        out.push(Finding::error(
                            format!("{ppath}.workloadOverride.imageDigest"),
                            "image-digest-regex",
                            format!("`{d}` MUST match ^sha256:[a-f0-9]{{64}}$"),
                        ));
                    }
                }
                for cmd in ["preDeployExpandCommand", "postDeployContractCommand", "preScaleDownDrainCommand"] {
                    if let Some(script) = get(wo, cmd).and_then(as_str) {
                        if script.contains("://") && !is_script_ref(script) && !script.starts_with("scripts/") {
                            // allow raw argv arrays only; strings that look like URIs must match
                            if script.contains("://") {
                                out.push(Finding::error(
                                    format!("{ppath}.workloadOverride.{cmd}"),
                                    "script-ref-regex",
                                    format!("`{script}` MUST match scriptRef pattern when it is a URI"),
                                ));
                            }
                        }
                    }
                }
            }

            for (bi, b) in comp.get("bindings").and_then(as_seq).unwrap_or(&vec![]).iter().enumerate() {
                check_binding(b, &format!("{ppath}.bindings[{bi}]"), &comp_ids, out);
            }

            if let Some(expose) = comp.get("expose").and_then(as_seq) {
                for (ei, ex) in expose.iter().enumerate() {
                    let epath = format!("{ppath}.expose[{ei}]");
                    req_str(ex, "endpoint", &epath, out);
                    req_str(ex, "viaBalancer", &epath, out);
                    req_enum(ex, "scope", &epath, EXPOSE_SCOPES, out, "expose-scope-enum");
                }
            }

            let _ = comp_id;
        }

        // cluster-level bindings
        for (bi, b) in cluster.get("bindings").and_then(as_seq).unwrap_or(&vec![]).iter().enumerate() {
            check_binding(b, &format!("{cpath}.bindings[{bi}]"), &comp_ids, out);
            if get(b, "from").and_then(as_str).is_none() {
                out.push(Finding::error(
                    format!("{cpath}.bindings[{bi}].from"),
                    "required",
                    "from is required on cluster-level bindings",
                ));
            }
        }
    }

    // cross-cluster links
    if let Some(links) = root.get("crossClusterLinks").and_then(as_seq) {
        for (i, link) in links.iter().enumerate() {
            let lpath = format!("crossClusterLinks[{i}]");
            req_str(link, "id", &lpath, out);
            for field in ["fromCluster", "fromComponent", "toCluster", "toComponent"] {
                req_str(link, field, &lpath, out);
            }
            req_enum(link, "relationType", &lpath, RELATIONS, out, "relation-enum");
            for field in ["fromCluster", "toCluster"] {
                if let Some(c) = opt_str(link, field) {
                    if !cluster_ids.contains(c) {
                        out.push(Finding::error(
                            format!("{lpath}.{field}"),
                            "cross-cluster-ref",
                            format!("`{c}` is not a cluster id in this blueprint"),
                        ));
                    }
                }
            }
        }
    }

    // ===== deep nested rules =====
    if let Some(exts) = root.get("externalResources").and_then(as_seq) {
        for (i, e) in exts.iter().enumerate() {
            check_enum(e, "transport", &format!("externalResources[{i}]"), deep::TRANSPORT, out, "transport-enum");
        }
    }
    if let Some(scripts) = root.get("scripts") {
        deep::check_scripts(scripts, "scripts", out);
    }
    for (ci, cluster) in clusters.iter().enumerate() {
        let cpath = format!("clusters[{ci}]");
        if let Some(sec) = cluster.get("security") {
            deep::check_cluster_security(sec, &format!("{cpath}.security"), out);
        }
        if let Some(lbs) = cluster.get("loadBalancers").and_then(as_seq) {
            for (li, lb) in lbs.iter().enumerate() {
                deep::check_load_balancer(lb, &format!("{cpath}.loadBalancers[{li}]"), out);
            }
        }
        if let Some(zones) = cluster.get("securityZones").and_then(as_seq) {
            for (zi, z) in zones.iter().enumerate() {
                deep::check_security_zone(z, &format!("{cpath}.securityZones[{zi}]"), out);
            }
        }
        if let Some(comps) = cluster.get("components").and_then(as_seq) {
            for (i, comp) in comps.iter().enumerate() {
                let ppath = format!("{cpath}.components[{i}]");
                if let Some(st) = comp.get("storage") {
                    deep::check_storage_override(st, &format!("{ppath}.storage"), out);
                }
                if let Some(vols) = comp.get("volumes") {
                    deep::check_volumes_map(vols, &format!("{ppath}.volumes"), out);
                }
                if let Some(ex) = comp.get("expose").and_then(as_seq) {
                    for (ei, e) in ex.iter().enumerate() {
                        deep::check_expose(e, &format!("{ppath}.expose[{ei}]"), out);
                    }
                }
                if let Some(boot) = comp.get("bootstrap") {
                    req_str(boot, "fromBackupTarget", &format!("{ppath}.bootstrap"), out);
                    if let Some(t) = opt_str(boot, "recoveryTargetTime") {
                        if t != "latest" && t.is_empty() {
                            out.push(Finding::error(
                                format!("{ppath}.bootstrap.recoveryTargetTime"),
                                "recovery-time",
                                "recoveryTargetTime MUST be `latest` or an ISO-8601 timestamp",
                            ));
                        }
                    }
                }
                if let Some(wo) = comp.get("workloadOverride") {
                    for cmd in ["preDeployExpandCommand", "postDeployContractCommand", "preScaleDownDrainCommand"] {
                        deep::check_script_ref_field(wo, cmd, &format!("{ppath}.workloadOverride"), out);
                    }
                }
                if let Some(eg) = comp.get("egressOverride") {
                    check_enum(
                        eg,
                        "mode",
                        &format!("{ppath}.egressOverride"),
                        EGRESS_MODES,
                        out,
                        "egress-enum",
                    );
                }
            }
        }
    }
    if let Some(links) = root.get("crossClusterLinks").and_then(as_seq) {
        for (i, link) in links.iter().enumerate() {
            deep::check_cross_cluster_link(link, &format!("crossClusterLinks[{i}]"), out);
        }
    }
}

const EGRESS_MODES: &[&str] = &["graph-only", "allow-public-internet", "allow-fqdn-whitelist"];


fn check_binding(
    b: &Yaml,
    bpath: &str,
    comp_ids: &std::collections::BTreeSet<String>,
    out: &mut Vec<Finding>,
) {
    req_str(b, "to", bpath, out);
    check_enum(b, "type", bpath, BINDING_TYPES, out, "binding-type-enum");
    check_enum(b, "deliveryGuarantee", bpath, DELIVERY, out, "delivery-enum");
    check_int_range(b, "secretRotationEpoch", bpath, 1, None, out, "rotation-epoch");
    if let Some(to) = opt_str(b, "to") {
        // resolution is soft: target may be externalResources or a component in another cluster
        if !comp_ids.contains(to) && !is_slug(to) {
            out.push(Finding::error(
                format!("{bpath}.to"),
                "binding-target",
                format!("binding target `{to}` is not a valid id"),
            ));
        }
    }
    if opt_str(b, "deliveryGuarantee") == Some("transactional-outbox")
        && get(b, "outboxSourceRequirement").is_none()
    {
        out.push(Finding::warning(
            format!("{bpath}.outboxSourceRequirement"),
            "outbox-source",
            "transactional-outbox SHOULD set outboxSourceRequirement",
        ));
    }
}
