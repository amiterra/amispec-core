//! Cross-crate tests: compile/decompile round-trip and AmiSpec fixtures.

use amispec_compile::{compile, decompile, decompile_dir, Options, PassportIndex};
use amispec_schema::parse_topology;
use std::path::{Path, PathBuf};

fn standard_tests_root() -> PathBuf {
    if let Ok(root) = std::env::var("AMISPEC_TEST_ROOT") {
        return PathBuf::from(root);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("amispec")
        .join("tests")
}

fn load_topology(name: &str) -> amispec_schema::TopologyBlueprint {
    let path = standard_tests_root().join("valid").join(name);
    let raw = std::fs::read_to_string(&path).expect("read fixture");
    parse_topology(&raw).expect("parse fixture")
}

#[test]
fn compile_minimal_topology_emits_stage_tree() {
    let topo = load_topology("topology-minimal.yaml");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("compile-out");
    let result = compile(
        &topo,
        &PassportIndex::default(),
        &Options {
            out_dir: out.clone(),
            provenance: true,
            dry_run: false,
        },
    )
    .expect("compile");
    assert!(!result.cluster_ids.is_empty());
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
            out.join(format!("clusters/{}/", result.cluster_ids[0]))
                .join(stage)
                .join("kustomization.yaml")
                .exists(),
            "missing {stage}"
        );
    }
}

#[test]
fn compile_is_deterministic() {
    let topo = load_topology("topology-minimal.yaml");
    let a = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
    let b = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
    assert_eq!(a.files.len(), b.files.len());
    for (x, y) in a.files.iter().zip(b.files.iter()) {
        assert_eq!(x.relative_path, y.relative_path);
        assert_eq!(x.contents, y.contents);
    }
}

#[test]
fn roundtrip_compile_decompile_preserves_components() {
    let topo = load_topology("topology-minimal.yaml");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("roundtrip");
    let _ = std::fs::remove_dir_all(&out);
    compile(
        &topo,
        &PassportIndex::default(),
        &Options {
            out_dir: out.clone(),
            provenance: true,
            dry_run: false,
        },
    )
    .unwrap();

    let report = decompile_dir(&out).expect("decompile dir");
    assert!(report.objects_with_provenance > 0, "expected provenance");
    let rebuilt = report.topology.expect("topology");

    // clusters preserved
    let orig_ids: Vec<_> = topo.clusters.iter().map(|c| c.id.clone()).collect();
    let new_ids: Vec<_> = rebuilt.clusters.iter().map(|c| c.id.clone()).collect();
    for id in &orig_ids {
        assert!(new_ids.contains(id), "missing cluster {id} in {new_ids:?}");
    }

    // component ids preserved
    for oc in topo.clusters.iter().flat_map(|c| &c.components) {
        let found = rebuilt
            .clusters
            .iter()
            .flat_map(|c| &c.components)
            .any(|c| c.id == oc.id);
        assert!(found, "missing component {}", oc.id);
    }

    // passport pin round-trip
    let orig_pg = topo
        .clusters
        .iter()
        .flat_map(|c| &c.components)
        .find(|c| c.passport == "postgresql")
        .expect("pg in fixture");
    let new_pg = rebuilt
        .clusters
        .iter()
        .flat_map(|c| &c.components)
        .find(|c| c.id == orig_pg.id)
        .expect("pg rebuilt");
    assert_eq!(new_pg.passport, orig_pg.passport);
    assert_eq!(new_pg.version, orig_pg.version);
    assert_eq!(new_pg.passport_rev, orig_pg.passport_rev);
}

#[test]
fn provenance_labels_present_on_workloads() {
    let topo = load_topology("topology-minimal.yaml");
    let result = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
    let apps = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("05-applications/workloads.yaml"))
        .expect("workloads file");
    assert!(apps.contents.contains("amispec.io/component-id"));
    assert!(apps.contents.contains("amispec.io/passport"));
    assert!(apps.contents.contains("amispec.io/user-spec-delta"));
    let secrets = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("05-applications/secrets.yaml"))
        .expect("secrets file");
    assert!(secrets.contents.contains("amispec.io/binding-edge"));
}

#[test]
fn compiler_invariants_present() {
    let topo = load_topology("topology-minimal.yaml");
    let result = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
    let workloads = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("workloads.yaml"))
        .unwrap()
        .contents
        .clone();
    // Invariant: terminationGracePeriodSeconds = max(35, 5+60) = 65
    assert!(
        workloads.contains("terminationGracePeriodSeconds") && workloads.contains("65"),
        "missing grace period"
    );
    // Provenance user-spec-delta
    assert!(workloads.contains("amispec.io/user-spec-delta"));
    // jobs have ttlSecondsAfterFinished and hash suffix
    let jobs = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("04a-provisioners"))
        .unwrap()
        .contents
        .clone();
    assert!(jobs.contains("ttlSecondsAfterFinished"));
    assert!(jobs.contains("provision-"));
    // CIDR formula in networking
    let net = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("networking.yaml"))
        .unwrap()
        .contents
        .clone();
    assert!(net.contains("10.101.0.0/16") || net.contains("podCIDR"));
    assert!(net.contains("10.201.0.0/16") || net.contains("serviceCIDR"));
}

#[test]
fn sidecar_pre_stop_only_for_standard_container() {
    use amispec_compile::{ClientSidecar, PassportIndex, PassportSummary, SidecarListener};
    let mut idx = PassportIndex::new();
    idx.insert(PassportSummary {
        id: "stateless-app".into(),
        version: "1.0.0".into(),
        passport_rev: 1,
        stateful: false,
        client_sidecars: vec![(
            vec!["standalone".into()],
            ClientSidecar {
                name: "pgbouncer-sidecar".into(),
                image: "example/pgbouncer:1".into(),
                injection_target: "k8s-native-init-restart-always".into(),
                listeners: vec![SidecarListener {
                    name: "rw".into(),
                    base_local_port: 5432,
                    target_role: "primary-rw".into(),
                }],
                cpu_millicores: 50,
                memory_mb: 48,
                shared_quota_formula: Some("max(2, 10)".into()),
                pre_stop_drain_delay_sec: Some(5),
            },
        )],
    });
    let topo = load_topology("topology-minimal.yaml");
    let result = compile(&topo, &idx, &Options::dry()).unwrap();
    let workloads = result
        .files
        .iter()
        .find(|f| f.relative_path.contains("workloads.yaml"))
        .unwrap()
        .contents
        .clone();
    assert!(workloads.contains("pgbouncer-sidecar"));
    assert!(workloads.contains("MAX_DB_CONNECTIONS_PER_POD"));
    // k8s-native must NOT emit preStop sleep
    let web_section = &workloads[workloads.find("component-id: web").unwrap_or(0)..];
    assert!(
        !web_section.contains("sleep 5"),
        "preStop must not appear for k8s-native-init-restart-always"
    );
}

#[test]
fn roundtrip_preserves_autoscaling() {
    let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
clusters:
  - id: local
    name: Local
    domain: example.local
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    components:
      - id: workers
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology:
          mode: standalone
          replicas: 3
          autoscaling:
            minReplicas: 2
            maxReplicas: 8
            cooldownSeconds: 300
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings: []
"#;
    let topo = parse_topology(yaml).unwrap();
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hpa-rt");
    let _ = std::fs::remove_dir_all(&out);
    compile(
        &topo,
        &PassportIndex::default(),
        &Options {
            out_dir: out.clone(),
            provenance: true,
            dry_run: false,
        },
    )
    .unwrap();
    let report = decompile_dir(&out).unwrap();
    let rebuilt = report.topology.unwrap();
    let comp = rebuilt
        .clusters
        .iter()
        .flat_map(|c| &c.components)
        .find(|c| c.id == "workers")
        .expect("workers");
    let as_ = comp.topology.autoscaling.as_ref().expect("autoscaling");
    assert_eq!(as_.min_replicas, 2);
    assert_eq!(as_.max_replicas, 8);
    assert_eq!(as_.cooldown_seconds, Some(300));
}

#[test]
fn decompile_empty_without_provenance() {
    let report = decompile(&[]);
    assert!(report.topology.is_none() || report.objects_with_provenance == 0);
}

#[test]
fn multi_cluster_roundtrip() {
    let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: multi, organization: ex }
clusters:
  - id: prod-eu
    name: Prod
    domain: example.io
    security: { sopsRecipients: [age1aaaa], maintenanceWindow: "Sun 02:00-05:00 UTC" }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    components:
      - id: pg-main
        passport: postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: strict-ha, replicas: 3, committedReplicas: 3 }
        resources: { cpuCores: 4, memoryMb: 16384 }
    bindings: []
  - id: dr-eu
    name: DR
    domain: dr.example.io
    security: { sopsRecipients: [age1bbbb] }
    cni: { engine: cilium-ebpf, clusterMeshId: 2 }
    nodes:
      - id: d1
        role: worker-only
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    components:
      - id: pg-dr
        passport: postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: degraded-ha, replicas: 2 }
        resources: { cpuCores: 2, memoryMb: 8192 }
    bindings: []
crossClusterLinks:
  - id: geo-dr
    fromCluster: prod-eu
    fromComponent: pg-main
    toCluster: dr-eu
    toComponent: pg-dr
    toSlot: sql-cluster
    relationType: active-passive-replication
    transport: wireguard-tunnel
    encryption: wireguard-mtls
    maxBandwidthMbps: 500
    rpoTargetSec: 5
"#;
    let topo = parse_topology(yaml).unwrap();
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("multi-rt");
    let _ = std::fs::remove_dir_all(&out);
    let result = compile(
        &topo,
        &PassportIndex::default(),
        &Options { out_dir: out.clone(), provenance: true, dry_run: false },
    )
    .unwrap();
    assert_eq!(result.cluster_ids.len(), 2);
    // both cluster roots exist
    assert!(out.join("clusters/prod-eu/kustomization.yaml").exists());
    assert!(out.join("clusters/dr-eu/kustomization.yaml").exists());
    // CIDR formula uses distinct mesh ids
    let net = std::fs::read_to_string(out.join("clusters/prod-eu/02-operators-and-networking/networking.yaml")).unwrap();
    assert!(net.contains("10.101.0.0/16"));
    let net2 = std::fs::read_to_string(out.join("clusters/dr-eu/02-operators-and-networking/networking.yaml")).unwrap();
    assert!(net2.contains("10.102.0.0/16"));
    // cross-cluster meta
    let meta = std::fs::read_to_string(out.join("clusters/_meta/cross-cluster-links.yaml")).unwrap();
    assert!(meta.contains("active-passive-replication"));
    // decompile keeps both clusters + link
    let report = decompile_dir(&out).unwrap();
    let rebuilt = report.topology.unwrap();
    assert_eq!(rebuilt.clusters.len(), 2);
    assert_eq!(rebuilt.cross_cluster_links.len(), 1);
    assert_eq!(rebuilt.cross_cluster_links[0].relation_type, "active-passive-replication");
}

#[test]
fn stateful_passport_uses_statefulset() {
    let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: st, organization: ex }
clusters:
  - id: local
    name: L
    domain: l.local
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    components:
      - id: pg
        passport: postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: standalone }
        resources: { cpuCores: 2, memoryMb: 2048 }
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings: []
"#;
    let topo = parse_topology(yaml).unwrap();
    let result = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap();
    let stateful = result.files.iter().find(|f| f.relative_path.contains("03-stateful")).unwrap();
    let apps = result.files.iter().find(|f| f.relative_path.contains("workloads.yaml")).unwrap();
    assert!(stateful.contents.contains("StatefulSet"));
    assert!(stateful.contents.contains("pg"));
    assert!(apps.contents.contains("Deployment"));
    assert!(apps.contents.contains("web"));
}

#[test]
fn compile_rejects_empty_clusters() {
    let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: empty, organization: ex }
clusters: []
"#;
    // clusters MinItems is schema-level; parse may still succeed depending on serde
    if let Ok(topo) = parse_topology(yaml) {
        let err = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap_err();
        assert!(matches!(err, amispec_compile::CompileError::EmptyClusters));
    }
}

#[test]
fn decompile_missing_dir_is_error() {
    let err = decompile_dir(Path::new("/nonexistent-amispec-path")).unwrap_err();
    let _ = err;
}

#[test]
fn write_files_creates_tree() {
    let topo = load_topology("topology-minimal.yaml");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("write-files");
    let _ = std::fs::remove_dir_all(&out);
    let result = compile(
        &topo,
        &PassportIndex::default(),
        &Options { out_dir: out.clone(), provenance: true, dry_run: false },
    )
    .unwrap();
    assert!(result.files.len() >= 15);
    for f in &result.files {
        assert!(out.join(&f.relative_path).exists(), "missing {}", f.relative_path);
    }
}
