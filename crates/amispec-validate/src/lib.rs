//! AmiSpec configuration validator.
//!
//! Validates `ComponentPassport`, `TopologyBlueprint`, and `CanvasLayout`
//! documents against the AmiSpec 1.0 meta-schemas.
//!
//! # Design
//!
//! * **Dependency-light** — `serde` + `serde_yaml` + `thiserror` only; pattern
//!   checks are hand-written (auditable, no `regex`).
//! * **Layered** — parse → structural (types/enums/ranges/regex) → semantic
//!   (graph, uniqueness, budgets) → optional authoritative `cue vet`.
//! * **Safe** — no shell interpolation; temp files are uniquely named and
//!   always cleaned up; pure functions on borrowed YAML values.
//! * **Testable** — unit tests per rule + conformance suite against the
//!   AmiSpec standard fixtures.
//!
//! # Example
//!
//! ```no_run
//! let yaml = "kind: ComponentPassport\n";
//! let report = amispec_validate::validate_str("app.yaml", yaml, &Default::default());
//! if !report.is_ok() {
//!     for e in report.errors() {
//!         eprintln!("{}: {}", e.path, e.message);
//!     }
//! }
//! ```

mod patterns;
mod report;
mod rules;
mod value;

pub use patterns::*;
pub use report::{Finding, Report, Severity};
pub use rules::{validate_topology_str, Options};

use report::Finding as F;
use rules::validate as validate_inner;
use value::Yaml;

/// AmiSpec standard version this validator targets.
pub const AMISPEC_STANDARD_VERSION: &str = "1.0.0";

/// Document kinds defined by AmiSpec 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    ComponentPassport,
    TopologyBlueprint,
    CanvasLayout,
}

impl DocumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentPassport => "ComponentPassport",
            Self::TopologyBlueprint => "TopologyBlueprint",
            Self::CanvasLayout => "CanvasLayout",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ComponentPassport" => Some(Self::ComponentPassport),
            "TopologyBlueprint" => Some(Self::TopologyBlueprint),
            "CanvasLayout" => Some(Self::CanvasLayout),
            _ => None,
        }
    }
}

/// Expected `apiVersion` per kind.
pub fn expected_api_version(kind: DocumentKind) -> &'static str {
    match kind {
        DocumentKind::ComponentPassport => "catalog.amispec.io/v1",
        DocumentKind::TopologyBlueprint | DocumentKind::CanvasLayout => "topology.amispec.io/v1",
    }
}

/// Validate YAML text for `source` (used in messages).
pub fn validate_str(source: &str, yaml: &str, opts: &Options) -> Report {
    let mut report = Report::new(source);
    let value = match serde_yaml::from_str::<Yaml>(yaml) {
        Ok(v) => v,
        Err(e) => {
            report.push(F::error("$", "parse", format!("invalid YAML: {e}")));
            return report;
        }
    };

    let Some(root) = value.as_mapping() else {
        report.push(F::error("$", "parse", "document root MUST be a mapping"));
        return report;
    };

    let kind_str = root.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let Some(kind) = DocumentKind::parse(kind_str) else {
        report.push(F::error(
            "kind",
            "kind-enum",
            format!(
                "unknown kind `{kind_str}` (expected ComponentPassport | TopologyBlueprint | CanvasLayout)"
            ),
        ));
        return report;
    };
    report.kind = Some(kind);

    let api = root.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
    let expected = expected_api_version(kind);
    if api != expected {
        report.push(F::error(
            "apiVersion",
            "api-version",
            format!("apiVersion `{api}` MUST be `{expected}` for {kind_str}"),
        ));
    }

    validate_inner(kind, root, &mut report);

    if opts.use_cue {
        if let Some(dir) = opts.schema_dir.as_deref() {
            rules::cue::run_cue_vet(kind, yaml, dir, &mut report);
        } else {
            report.push(F::warning(
                "$",
                "cue-config",
                "use_cue set but schema_dir missing; skipped cue vet",
            ));
        }
    }

    report
}

/// Validate a YAML file on disk.
pub fn validate_file(path: &std::path::Path, opts: &Options) -> Report {
    let source = path.display().to_string();
    match std::fs::read_to_string(path) {
        Ok(yaml) => validate_str(&source, &yaml, opts),
        Err(e) => {
            let mut report = Report::new(&source);
            report.push(F::error("$", "io", format!("cannot read file: {e}")));
            report
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Options {
        Options::default()
    }

    #[test]
    fn rejects_unknown_kind() {
        let r = validate_str("t", "kind: Nope\n", &opts());
        assert!(!r.is_ok());
        assert!(r.errors().any(|e| e.rule == "kind-enum"));
    }

    #[test]
    fn rejects_bad_yaml() {
        let r = validate_str("t", ": : :", &opts());
        assert!(!r.is_ok());
    }

    #[test]
    fn rejects_wrong_api_version() {
        let yaml = r#"
apiVersion: catalog.amispec.io/v9
kind: ComponentPassport
metadata: { id: a, name: b, version: "1", passportRev: 1, category: application, archetype: stateless-app }
"#;
        let r = validate_str("t", yaml, &opts());
        assert!(r.errors().any(|e| e.rule == "api-version"));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn opts() -> Options {
        Options::default()
    }

    fn assert_rule(yaml: &str, rule: &str) {
        let r = validate_str("t", yaml, &opts());
        assert!(
            r.errors().any(|e| e.rule == rule),
            "expected {rule}, got {:?}",
            r.findings
        );
    }

    const PASSPORT_PREFIX: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata:
  id: demo
  name: Demo
  version: "1.0.0"
  passportRev: 1
  category: application
  archetype: stateless-app
  distribution: { tier: open-core, license: Apache-2.0 }
  canvasUI: { icon: x, accentColor: '#000000', nodeShape: standard-card }
topologyModes:
  standalone:
    description: d
    minNodes: 1
    replicas: 1
    scaleDownPolicy: immediate
    disruptionBudget: { maxUnavailable: 1, updateStrategy: rolling }
    podAntiAffinity: soft
workload: { engine: k8s-deployment, priorityClass: background-batch }
interfaces: { egressDefaultMode: graph-only, endpoints: [], provides: [], requires: {} }
"#;

    const PASSPORT_SUFFIX: &str = r#"
operations:
  observability: { scrapeInterval: 30s }
"#;

    #[test]
    fn rejects_bad_merge_strategy() {
        let yaml = format!(
            "{PASSPORT_PREFIX}hardwareAndKernel:\n  resources:\n    minCpuCores: 0.1\n    minMemoryMb: 64\n    recommendedMemoryMb: 128\n  kernelTuning:\n    priority: 10\n    sysctl:\n      vm.swappiness: {{ value: 1, mergeStrategy: bogus }}\n{PASSPORT_SUFFIX}"
        );
        assert_rule(&yaml, "merge-strategy-enum");
    }

    #[test]
    fn rejects_bad_vertical_scale() {
        let yaml = format!(
            "{PASSPORT_PREFIX}hardwareAndKernel:\n  resources:\n    minCpuCores: 0.1\n    minMemoryMb: 64\n    recommendedMemoryMb: 128\n    verticalScalePolicy: {{ cpu: nope, memory: in-place-grow-only }}\n{PASSPORT_SUFFIX}"
        );
        assert_rule(&yaml, "vert-cpu-enum");
    }

    #[test]
    fn rejects_bad_day2_execution_type() {
        let yaml = format!(
            "{PASSPORT_PREFIX}hardwareAndKernel:\n  resources:\n    minCpuCores: 0.1\n    minMemoryMb: 64\n    recommendedMemoryMb: 128\noperations:\n  day2Actions:\n    - id: a\n      title: t\n      category: first-aid\n      executionType: shell\n  observability:\n    scrapeInterval: 30s\n"
        );
        assert_rule(&yaml, "day2-exec-enum");
    }

    #[test]
    fn rejects_bad_volume_and_kernel() {
        let yaml = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata:
  id: demo
  name: Demo
  version: "1.0.0"
  passportRev: 1
  category: application
  archetype: stateless-app
  distribution: { tier: open-core, license: Apache-2.0 }
  canvasUI: { icon: x, accentColor: '#000000', nodeShape: standard-card }
topologyModes:
  standalone:
    description: d
    minNodes: 1
    replicas: 1
    scaleDownPolicy: immediate
    disruptionBudget: { maxUnavailable: 1, updateStrategy: rolling }
    podAntiAffinity: soft
workload: { engine: k8s-deployment, priorityClass: background-batch }
interfaces: { egressDefaultMode: graph-only, endpoints: [], provides: [], requires: {} }
hardwareAndKernel:
  resources: { minCpuCores: 0.1, minMemoryMb: 64, recommendedMemoryMb: 128 }
  storage:
    mountPath: /data
    minSizeGb: 1
    defaultSizeGb: 2
    resizePolicy: shrink-please
    deletionPolicy: wipe
    nodeLossRecovery: ignore
    mediaTier: floppy
    lvmOptions:
      provisioner: handmade
      volumeBindingMode: whenever
      filesystem: fat32
operations:
  observability: { scrapeInterval: 30s }
"#;
        for rule in [
            "resize-policy-enum",
            "deletion-policy-enum",
            "node-loss-enum",
            "media-tier-enum",
            "lvm-provisioner-enum",
            "volume-binding-enum",
            "filesystem-enum",
        ] {
            assert_rule(yaml, rule);
        }
    }

    #[test]
    fn rejects_bad_anomaly_algorithm_and_backup() {
        let yaml = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata:
  id: demo
  name: Demo
  version: "1.0.0"
  passportRev: 1
  category: database
  archetype: operator-cluster
  distribution: { tier: open-core, license: Apache-2.0 }
  canvasUI: { icon: x, accentColor: '#000000', nodeShape: database-cylinder }
topologyModes:
  standalone:
    description: d
    minNodes: 1
    replicas: 1
    scaleDownPolicy: immediate
    disruptionBudget: { maxUnavailable: 1, updateStrategy: rolling }
    podAntiAffinity: soft
workload: { engine: operator-crd, priorityClass: stateful-core }
interfaces: { egressDefaultMode: graph-only, endpoints: [], provides: [], requires: {} }
hardwareAndKernel:
  resources: { minCpuCores: 0.1, minMemoryMb: 64, recommendedMemoryMb: 128 }
operations:
  observability:
    scrapeInterval: 30s
    localAnomalyRules:
      - { metric: m, algorithm: astrology }
  backup:
    mode: operator-managed
    driver: x
    versionCoupling: guess
    targetReplicaRole: primary-when-easy
"#;
        for rule in ["anomaly-algo-enum", "version-coupling-enum", "target-replica-enum"] {
            assert_rule(yaml, rule);
        }
    }

    #[test]
    fn rejects_bad_topology_transport() {
        let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: p, organization: o }
clusters:
  - id: c1
    name: n
    domain: d
    security:
      sopsRecipients: [age1abc]
      controlPlaneQuorumMode: bogus-quorum
      imageRegistryPolicy: open-mirror
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 1, memoryMb: 1024, disks: [] }
    components: []
crossClusterLinks:
  - id: l1
    fromCluster: c1
    fromComponent: a
    toCluster: c1
    toComponent: b
    relationType: global-service-mesh
    transport: carrier-pigeon
    encryption: none-please
"#;
        for rule in [
            "transport-enum",
            "encryption-enum",
            "control-plane-quorum-enum",
            "image-registry-enum",
        ] {
            assert_rule(yaml, rule);
        }
    }

    #[test]
    fn rejects_bad_mount_flag() {
        let yaml = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata:
  id: demo
  name: Demo
  version: "1.0.0"
  passportRev: 1
  category: application
  archetype: stateless-app
  distribution: { tier: open-core, license: Apache-2.0 }
  canvasUI: { icon: x, accentColor: '#000000', nodeShape: standard-card }
topologyModes:
  standalone:
    description: d
    minNodes: 1
    replicas: 1
    scaleDownPolicy: immediate
    disruptionBudget: { maxUnavailable: 1, updateStrategy: rolling }
    podAntiAffinity: soft
workload: { engine: k8s-deployment, priorityClass: background-batch }
interfaces: { egressDefaultMode: graph-only, endpoints: [], provides: [], requires: {} }
hardwareAndKernel:
  resources: { minCpuCores: 0.1, minMemoryMb: 64, recommendedMemoryMb: 128 }
  storage:
    mountPath: /data
    minSizeGb: 1
    defaultSizeGb: 2
    lvmOptions:
      provisioner: topolvm-nvme
      volumeBindingMode: WaitForFirstConsumer
      mountFlags: [noatime, suid, exec]
      filesystem: xfs
operations:
  observability: { scrapeInterval: 30s }
"#;
        let r = validate_str("t", yaml, &opts());
        let flags: Vec<_> = r
            .errors()
            .filter(|e| e.rule == "mount-flag-enum")
            .map(|e| e.message.clone())
            .collect();
        assert_eq!(flags.len(), 2, "{flags:?} in {:?}", r.findings);
        assert!(flags.iter().any(|m| m.contains("suid")));
        assert!(flags.iter().any(|m| m.contains("exec")));
    }

    #[test]
    fn rejects_liveness_not_local_only() {
        let yaml = format!(
            "{PASSPORT_PREFIX}hardwareAndKernel:\n  resources:\n    minCpuCores: 0.1\n    minMemoryMb: 64\n    recommendedMemoryMb: 128\nworkload:\n  engine: k8s-deployment\n  priorityClass: background-batch\n  probes:\n    liveness:\n      type: http\n      path: /health\n      port: 8080\n      localProcessOnly: false\n{PASSPORT_SUFFIX}"
        );
        // workload appears twice — rebuild prefix without workload
        let yaml = yaml.replace(
            "workload: { engine: k8s-deployment, priorityClass: background-batch }\ninterfaces",
            "interfaces",
        );
        assert_rule(&yaml, "liveness-local-only");
    }

    #[test]
    fn rejects_empty_shared_quota_formula() {
        let yaml = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata:
  id: demo
  name: Demo
  version: "1.0.0"
  passportRev: 1
  category: database
  archetype: operator-cluster
  distribution: { tier: open-core, license: Apache-2.0 }
  canvasUI: { icon: x, accentColor: '#000000', nodeShape: database-cylinder }
topologyModes:
  standalone:
    description: d
    minNodes: 1
    replicas: 1
    scaleDownPolicy: immediate
    disruptionBudget: { maxUnavailable: 1, updateStrategy: rolling }
    podAntiAffinity: soft
workload: { engine: operator-crd, priorityClass: stateful-core }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - slot: sql-cluster
      capability: postgres-sql
      version: "18.0.0"
      clientContract:
        injectWhenModes: [degraded-ha]
        sidecar:
          name: pgbouncer
          image: example/pgbouncer:1
          injectionTarget: k8s-native-init-restart-always
          deduplicationScope: per-target-component
          portAllocationStrategy: deterministic-offset
          sharedQuotaFormula: "   "
          listeners:
            - { name: rw, baseLocalPort: 5432, targetRole: primary-rw }
          resources: { cpuMillicores: 50, memoryMb: 48 }
          configTemplate: t.j2
        exportedTokens: { uri: "u" }
  requires: {}
hardwareAndKernel:
  resources: { minCpuCores: 0.1, minMemoryMb: 64, recommendedMemoryMb: 128 }
operations:
  observability: { scrapeInterval: 30s }
"#;
        assert_rule(yaml, "shared-quota");
    }
}
