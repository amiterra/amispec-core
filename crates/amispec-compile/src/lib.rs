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

mod decompile;
mod manifest;
mod passport;
mod provenance;

pub use decompile::{decompile, decompile_dir, DecompileReport};
pub use passport::{ClientSidecar, PassportIndex, PassportSummary, SidecarListener};
pub use provenance::*;

use amispec_schema::TopologyBlueprint;
use manifest::Builder;

use serde_json::{json, Map, Value};
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
}

impl Default for Options {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("out"),
            provenance: true,
            dry_run: false,
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

        // --- 00 flux-system ---
        b.kustomization(&format!("{root}/flux-system/kustomization.yaml"), &[]);

        // --- 01 node-tuning ---
        let mut tuning_docs: Vec<Value> = Vec::new();
        for node in &cluster.nodes {
            tuning_docs.push(node_tuning_profile(&cluster.id, node));
        }
        b.docs(&format!("{root}/01-node-tuning/profiles.yaml"), &tuning_docs);
        b.kustomization(
            &format!("{root}/01-node-tuning/kustomization.yaml"),
            &["profiles.yaml"],
        );

        // --- 02 operators & networking ---
        let mut net_docs = Vec::new();
        for lb in &cluster.load_balancers {
            net_docs.push(gateway_class(&cluster.id, lb));
        }
        // NodeTuning readiness is applied by the node agent; we also emit a
        // placeholder Kustomization-visible ConfigMap of cluster CNI settings.
        net_docs.push(cni_config_map(&cluster.id, cluster));
        b.docs(
            &format!("{root}/02-operators-and-networking/networking.yaml"),
            &net_docs,
        );
        b.kustomization(
            &format!("{root}/02-operators-and-networking/kustomization.yaml"),
            &["networking.yaml"],
        );

        // --- 03 / 05 split stateful vs stateless ---
        let mut stateful_docs = Vec::new();
        let mut app_docs = Vec::new();
        let mut pdb_docs = Vec::new();
        let mut hpa_docs = Vec::new();
        let mut secret_docs = Vec::new();
        let mut route_docs = Vec::new();

        for comp in &cluster.components {
            result.component_ids.push(comp.id.clone());
            let passport = passports.get(&comp.passport);
            let pin = passport_pin(&comp.passport, &comp.version, comp.passport_rev);

            // user-spec-delta (lossless decompile of user values)
            let delta = user_spec_delta(comp);

            // Secrets stubs for bindings + license/pull refs
            // Include inline bindings and cluster-level edges that start from this component.
            let mut edges: Vec<String> = comp
                .bindings
                .iter()
                .map(|b| {
                    format!(
                        "{}->{}:{}",
                        comp.id,
                        b.to,
                        b.to_slot.clone().unwrap_or_default()
                    )
                })
                .collect();
            for b in &cluster.bindings {
                if b.from.as_deref() == Some(comp.id.as_str()) {
                    let edge = format!(
                        "{}->{}:{}",
                        comp.id,
                        b.to,
                        b.to_slot.clone().unwrap_or_default()
                    );
                    if !edges.contains(&edge) {
                        edges.push(edge);
                    }
                }
            }
            secret_docs.push(binding_secret(&cluster.id, comp, &pin, &delta, &edges));

            // Workload object
            let sidecars = passport
                .map(|p| p.client_sidecars_for_mode(&comp.topology.mode))
                .unwrap_or_default();
            let sidecar_names: Vec<String> = sidecars.iter().map(|s| s.name.clone()).collect();

            let workload = workload_object(
                &cluster.id,
                comp,
                &pin,
                &delta,
                &sidecars,
                &sidecar_names,
                opts.provenance,
                cluster.maintenance_window.as_deref(),
            );

            let stateful = is_stateful(comp, passport);
            if stateful {
                stateful_docs.push(workload);
            } else {
                app_docs.push(workload);
            }

            // PDB
            pdb_docs.push(pod_disruption_budget(&cluster.id, comp, &pin, opts.provenance));
            // HPA
            if let Some(hpa) = hpa_object(&cluster.id, comp, &pin, opts.provenance) {
                hpa_docs.push(hpa);
            }
            // expose → HTTPRoute
            for ex in &comp.expose {
                route_docs.push(http_route(&cluster.id, comp, ex, &pin, opts.provenance));
            }
        }

        b.docs(&format!("{root}/03-stateful-clusters/stateful.yaml"), &stateful_docs);
        b.kustomization(
            &format!("{root}/03-stateful-clusters/kustomization.yaml"),
            &["stateful.yaml"],
        );

        // --- 04a provisioners (content-addressed job stubs) ---
        b.docs(
            &format!("{root}/04a-provisioners-day2/jobs.yaml"),
            &provisioner_jobs(&cluster.id, topology, cluster),
        );
        b.kustomization(
            &format!("{root}/04a-provisioners-day2/kustomization.yaml"),
            &["jobs.yaml"],
        );

        // --- 04b expand migrations ---
        b.docs(
            &format!("{root}/04b-app-migrations-expand/jobs.yaml"),
            &migration_jobs(&cluster.id, &cluster.components),
        );
        b.kustomization(
            &format!("{root}/04b-app-migrations-expand/kustomization.yaml"),
            &["jobs.yaml"],
        );

        // --- 05 applications ---
        b.docs(&format!("{root}/05-applications/workloads.yaml"), &app_docs);
        b.docs(&format!("{root}/05-applications/pdb.yaml"), &pdb_docs);
        b.docs(&format!("{root}/05-applications/hpa.yaml"), &hpa_docs);
        b.docs(&format!("{root}/05-applications/secrets.yaml"), &secret_docs);
        b.docs(&format!("{root}/05-applications/routes.yaml"), &route_docs);
        b.kustomization(
            &format!("{root}/05-applications/kustomization.yaml"),
            &[
                "workloads.yaml",
                "pdb.yaml",
                "hpa.yaml",
                "secrets.yaml",
                "routes.yaml",
            ],
        );

        // --- 06 zero-trust & observability ---
        b.docs(
            &format!("{root}/06-zero-trust-and-observability/netpols.yaml"),
            &network_policies(&cluster.id, &cluster.components, opts.provenance),
        );
        b.docs(
            &format!("{root}/06-zero-trust-and-observability/observability.yaml"),
            &observability_objects(&cluster.id, &cluster.components, opts.provenance),
        );
        b.kustomization(
            &format!("{root}/06-zero-trust-and-observability/kustomization.yaml"),
            &["netpols.yaml", "observability.yaml"],
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

fn gateway_class(cluster_id: &str, lb: &amispec_schema::LoadBalancer) -> Value {
    let mut m = Map::new();
    m.insert("apiVersion".into(), json!("gateway.networking.k8s.io/v1"));
    m.insert("kind".into(), json!("GatewayClass"));
    m.insert("metadata".into(), json!({
        "name": format!("{cluster_id}-{}", lb.id),
        "labels": {
            LABEL_CLUSTER_ID: cluster_id,
            LABEL_STAGE: "02-operators-and-networking",
            "amispec.io/lb-layer": lb.layer,
            "amispec.io/lb-id": lb.id,
        },
        "annotations": {
            "amispec.io/lb-provider": lb.provider,
            "amispec.io/upstream-edge": lb.upstream_edge.clone().unwrap_or_default(),
            "amispec.io/tls": lb.tls.clone().unwrap_or_else(|| "none".into()),
            "amispec.io/forwarding-mode": lb.forwarding_mode.clone().unwrap_or_else(|| "ebpf-dsr-maglev".into()),
        }
    }));
    m.insert("spec".into(), json!({
        "controllerName": format!("amispec.io/{}", lb.provider)
    }));
    Value::Object(m)
}

fn cni_config_map(cluster_id: &str, cluster: &amispec_schema::Cluster) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("{cluster_id}-cni"),
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
    })
}

#[allow(clippy::too_many_arguments)]
fn workload_object(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    delta: &Value,
    sidecars: &[ClientSidecar],
    sidecar_names: &[String],
    provenance: bool,
    maintenance_window: Option<&str>,
) -> Value {
    let ns = comp.zone.clone().unwrap_or_else(|| "default".into());
    let kind = if is_stateful_name(&comp.passport) {
        "StatefulSet"
    } else {
        "Deployment"
    };

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
    annotations.insert(
        "reloader.stakater.com/auto".into(),
        json!("true"),
    );
    if provenance {
        annotations.insert(
            LABEL_USER_SPEC_DELTA.into(),
            json!(serde_json::to_string(delta).unwrap_or_else(|_| "{}".into())),
        );
    }
    // Invariant: rolling-switchover formula changes MUST defer to maintenanceWindow
    if let Some(mw) = maintenance_window {
        if !mw.is_empty() {
            annotations.insert(
                "amispec.io/maintenance-window".into(),
                json!(mw),
            );
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
                json!(s.listeners.iter().map(|l| json!({
                    "name": l.name,
                    "containerPort": l.base_local_port
                })).collect::<Vec<_>>()),
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
    pod_spec.insert(
        "containers".into(),
        json!([{
            "name": "app",
            "image": format!("{}:{}", comp.passport, comp.version),
            "resources": {
                "requests": {
                    "cpu": comp.resources.cpu_cores.to_string(),
                    "memory": format!("{}Mi", comp.resources.memory_mb)
                },
                "limits": {
                    "memory": format!("{}Mi", comp.resources.memory_mb)
                }
            }
        }]),
    );
    pod_spec.insert(
        "securityContext".into(),
        json!({
            "runAsNonRoot": true,
            "runAsUser": 10001,
            "fsGroup": 10001
        }),
    );

    let mut spec = Map::new();
    if kind == "StatefulSet" {
        spec.insert("serviceName".into(), json!(comp.id.clone()));
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

fn is_stateful(comp: &amispec_schema::ComponentInstance, passport: Option<&PassportSummary>) -> bool {
    if let Some(p) = passport {
        return p.stateful;
    }
    is_stateful_name(&comp.passport)
}

fn is_stateful_name(passport: &str) -> bool {
    let p = passport.to_ascii_lowercase();
    p.contains("postgres")
        || p.contains("clickhouse")
        || p.contains("valkey")
        || p.contains("redis")
        || p.contains("mysql")
        || p.contains("stateful")
        || p.contains("sql")
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

fn http_route(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    ex: &amispec_schema::Expose,
    pin: &str,
    provenance: bool,
) -> Value {
    let mut labels = Map::new();
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!("05-applications"));
        labels.insert("amispec.io/scope".into(), json!(ex.scope.clone()));
        labels.insert("amispec.io/via-balancer".into(), json!(ex.via_balancer.clone()));
    }
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": format!("{}-{}", comp.id, ex.endpoint),
            "namespace": comp.zone.clone().unwrap_or_else(|| "default".into()),
            "labels": Value::Object(labels)
        },
        "spec": {
            "hostnames": [ex.hostname.clone().or_else(|| ex.subdomain.clone()).unwrap_or_default()],
            "parentRefs": [{ "name": ex.via_balancer.clone() }],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": ex.path_prefix.clone().unwrap_or_else(|| "/".into()) } }],
                "backendRefs": [{ "name": comp.id.clone(), "port": 80 }]
            }]
        }
    })
}

fn binding_secret(
    cluster_id: &str,
    comp: &amispec_schema::ComponentInstance,
    pin: &str,
    delta: &Value,
    edges: &[String],
) -> Value {
    let mut annotations = Map::new();
    annotations.insert(
        LABEL_USER_SPEC_DELTA.into(),
        json!(serde_json::to_string(delta).unwrap_or_else(|_| "{}".into())),
    );
    if !edges.is_empty() {
        annotations.insert(LABEL_BINDING_EDGE.into(), json!(edges.join(",")));
    }
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": format!("{}-bindings", comp.id),
            "namespace": comp.zone.clone().unwrap_or_else(|| "default".into()),
            "labels": {
                LABEL_COMPONENT_ID: comp.id,
                LABEL_PASSPORT: pin,
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_STAGE: "05-applications",
            },
            "annotations": Value::Object(annotations),
        },
        "type": "Opaque",
        "stringData": {
            // placeholder keys; real values come from SOPS
            "_amispec.component": comp.id.clone(),
            "_amispec.passport": pin.to_string(),
        }
    })
}

fn provisioner_jobs(
    cluster_id: &str,
    topology: &TopologyBlueprint,
    cluster: &amispec_schema::Cluster,
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
        let hash = short_hash(&format!(
            "{}:{}:{}",
            from_id,
            b.to,
            b.to_slot.clone().unwrap_or_default()
        ));
        jobs.push(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": format!("provision-{}-{}", from_id, hash),
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
    // external resources are referenced for backup-vault etc.
    let _ = topology;
    jobs
}

fn migration_jobs(cluster_id: &str, comps: &[amispec_schema::ComponentInstance]) -> Vec<Value> {
    let mut jobs = Vec::new();
    for comp in comps {
        let hash = short_hash(&format!("expand:{}", comp.id));
        jobs.push(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": format!("migrate-expand-{}-{}", comp.id, hash),
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
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "echo expand-schema && exit 0"]
                        }]
                    }
                }
            }
        }));
    }
    jobs
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
            "labels": {
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_STAGE: "06-zero-trust-and-observability",
            }
        },
        "spec": {
            "endpointSelector": {},
            "egress": [{
                "toEndpoints": [{
                    "matchLabels": { "k8s:k8s-app": "kube-dns" }
                }],
                "toPorts": [{ "ports": [{ "port": "53", "protocol": "ANY" }] }]
            }]
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
    #[error("io error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use amispec_schema::parse_topology;

    fn mini_topology() -> TopologyBlueprint {
        let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
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
        passport: stateless-app
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
        passport: postgresql
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
    fn compile_emits_seven_stages() {
        let topo = mini_topology();
        let out = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
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
        let a = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
        let b = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
        assert_eq!(a.files.len(), b.files.len());
        for (x, y) in a.files.iter().zip(b.files.iter()) {
            assert_eq!(x.relative_path, y.relative_path);
            assert_eq!(x.contents, y.contents);
        }
    }

    #[test]
    fn short_hash_stable() {
        assert_eq!(short_hash("abc"), short_hash("abc"));
        assert_eq!(short_hash("abc").len(), 8);
        assert_ne!(short_hash("abc"), short_hash("abd"));
    }
}
