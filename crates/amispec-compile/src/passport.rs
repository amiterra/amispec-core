//! Passport view used by the compiler (sidecar injection, statefulness,
//! expose endpoint contracts).
//!
//! Full passports live in the AmiSpec catalog; the compiler only needs the
//! subset that affects generated manifests.

use amispec_schema::{PassportEndpoint, parse_passport_endpoints};
use std::collections::BTreeMap;

/// One listener on a client sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarListener {
    pub name: String,
    pub base_local_port: u16,
    pub target_role: String,
}

/// Client sidecar from `clientContract.sidecar` (KEP-753).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSidecar {
    pub name: String,
    pub image: String,
    pub injection_target: String,
    pub listeners: Vec<SidecarListener>,
    pub cpu_millicores: u32,
    pub memory_mb: u32,
    /// Optional CEL quota formula (spec `sharedQuotaFormula`).
    pub shared_quota_formula: Option<String>,
    /// preStop drain delay; only emitted for `standard-container`.
    pub pre_stop_drain_delay_sec: Option<u32>,
}

/// Minimal passport facts required at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportSummary {
    pub id: String,
    pub version: String,
    pub passport_rev: u32,
    pub stateful: bool,
    /// Sidecars injected when topology mode is in `inject_when_modes`.
    pub client_sidecars: Vec<(Vec<String>, ClientSidecar)>,
    /// Inbound endpoint contracts (`interfaces.endpoints[]`): the `expose[]`
    /// port source (portless composition, ADR 0009).
    pub endpoints: Vec<PassportEndpoint>,
    /// Data directory the workload expects its volume mounted at
    /// (`hardwareAndKernel.storage.mountPath`).
    pub data_mount_path: Option<String>,
    /// Default container image (`workload.container.image`).
    pub image: Option<String>,
    /// Immutable pin (`workload.container.imageDigest`), GR-IMG-001.
    pub image_digest: Option<String>,
    /// Workload engine; kind selection is engine-driven (GR-OPR-002).
    pub engine: String,
    /// Container command/args from `workload.container`.
    pub command: Vec<String>,
    pub args: Vec<String>,
    /// Container name inside the pod (`workload.container.name`, default `app`).
    pub container_name: Option<String>,
    /// `workload.operatorSpec` — operator supply + adapter pin (GR-OPR-006).
    pub operator_spec: Option<OperatorSpecSummary>,
    /// `scripts`: name -> (runtime, path, inline).
    pub scripts: Vec<ScriptSummary>,
    /// `parameters` defaults (declared config contract).
    pub param_defaults: BTreeMap<String, serde_json::Value>,
    /// `parameters.<k>.targetPath` (CR placement of each parameter).
    pub param_target_paths: BTreeMap<String, String>,
    /// `interfaces.requires[].envMapping`: requirement key -> env -> token
    /// (shared or per-process).
    pub requires_env: BTreeMap<String, BTreeMap<String, EnvValue>>,
    /// `processes`: process name -> role (deploy|runtime).
    pub processes: BTreeMap<String, String>,
    /// `operations.backup` (mode/driver/cron/retention).
    pub backup: Option<BackupSummary>,
    /// Whether any `provides[]` declares a provisioner (04a jobs).
    pub has_provisioner: bool,
    /// `workload.configMounts` (volumes for scripts/secrets).
    pub config_mounts: Vec<ConfigMountDecl>,
    /// `hardwareAndKernel.resources.shmSizeMb` (hugepages budget for adapters).
    pub shm_size_mb: Option<u64>,
    /// `workload.container.env[]` (static/derived env).
    pub env_decls: Vec<EnvDecl>,
    /// `workload.container.ports[]` (full container port inventory).
    pub ports: Vec<PortDecl>,
    /// `workload.container.securityContext`.
    pub security_context: Option<SecurityContextDecl>,
    /// `workload.probes`.
    pub probes: ProbesDecl,
    /// `topologyModes.<mode>.disruptionBudget.updateStrategy` per mode.
    pub update_strategies: BTreeMap<String, String>,
    /// `provides[].clientContract.exportedTokens` (merged).
    pub exported_tokens: BTreeMap<String, String>,
    /// `workload.lifecycle.preDeployExpandCommand` script name (04b Jobs).
    pub pre_deploy_script: Option<String>,
}

/// Operator supply facts (`workload.operatorSpec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSpecSummary {
    pub adapter: String,
    pub crd_api_version: String,
    pub crd_kind: String,
}

/// Passport script (`scripts.<name>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSummary {
    pub name: String,
    pub runtime: String,
    pub path: Option<String>,
    pub inline: String,
}

/// Backup contract (`operations.backup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    pub mode: String,
    pub driver: String,
    pub default_cron: String,
    pub retention_days: u32,
}

/// One `requires[].envMapping` value: shared across processes, or scoped per
/// process (deploy vs runtime may need different endpoints/credentials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvValue {
    Shared(String),
    PerProcess(BTreeMap<String, String>),
}

impl EnvValue {
    /// Token for the given process (per-process entry, else the shared one).
    pub fn token_for(&self, process: &str) -> Option<&str> {
        match self {
            EnvValue::Shared(t) => Some(t.as_str()),
            EnvValue::PerProcess(m) => m.get(process).map(|s| s.as_str()),
        }
    }
}

/// Container env declaration (`workload.container.env[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDecl {
    pub name: String,
    pub value: Option<String>,
    pub field_path: Option<String>,
    pub secret_name: Option<String>,
    pub secret_key: Option<String>,
}

/// Container port declaration (`workload.container.ports[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortDecl {
    pub name: String,
    pub container_port: u16,
}

/// Container/pod security context (`workload.container.securityContext`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityContextDecl {
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub run_as_group: Option<i64>,
    pub fs_group: Option<i64>,
    pub seccomp_profile: Option<String>,
    pub allow_privilege_escalation: Option<bool>,
    pub capabilities_drop: Vec<String>,
}

/// One health probe (`workload.probes.{startup,liveness,readiness}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeDecl {
    pub probe_type: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub command: Vec<String>,
    pub period_seconds: Option<u32>,
    pub timeout_seconds: Option<u32>,
    pub failure_threshold: Option<u32>,
    pub initial_delay_seconds: Option<u32>,
}

/// Probes block (`workload.probes`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbesDecl {
    pub startup: Option<ProbeDecl>,
    pub liveness: Option<ProbeDecl>,
    pub readiness: Option<ProbeDecl>,
}

/// Config mount (`workload.configMounts[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigMountDecl {
    /// Pod volume name.
    pub name: String,
    pub mount_path: String,
    pub sub_path: Option<String>,
    /// `true` → Secret source, `false` → script ConfigMap `<component>-<name>`.
    pub from_secret: bool,
    /// Source name (`$params.<k>` token or literal); default = `name`.
    pub source: Option<String>,
    /// Secret/ConfigMap items projection (`key` + optional `path`).
    pub items: Vec<(String, Option<String>)>,
    pub read_only: bool,
    pub default_mode: Option<i32>,
}

impl PassportSummary {
    /// Sidecars applicable to the selected topology mode.
    pub fn client_sidecars_for_mode(&self, mode: &str) -> Vec<ClientSidecar> {
        self.client_sidecars
            .iter()
            .filter(|(modes, _)| modes.iter().any(|m| m == mode) || modes.is_empty())
            .map(|(_, s)| s.clone())
            .collect()
    }

    /// Backend port for a named endpoint contract (`expose[].endpoint`).
    pub fn endpoint_port(&self, endpoint: &str) -> Option<u16> {
        self.endpoints
            .iter()
            .find(|e| e.name == endpoint)
            .map(|e| e.container_port)
    }

    /// Build a summary from passport YAML text (metadata + endpoint contract).
    ///
    /// Sidecars are not projected here — inject them explicitly when needed.
    /// Errors when the document is not a `ComponentPassport` or cannot parse.
    pub fn from_passport_yaml(raw: &str) -> Result<Self, String> {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(raw).map_err(|e| format!("passport YAML: {e}"))?;
        let meta = doc
            .get("metadata")
            .ok_or("passport: metadata is required")?;
        let id = meta
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("passport: metadata.id is required")?
            .to_string();
        let publisher = meta
            .get("publisher")
            .and_then(|v| v.as_str())
            .ok_or("passport: metadata.publisher is required (GR-META-001)")?
            .to_string();
        // Canonical identity is the two-level ref `<publisher>/<id>`.
        let id = format!("{publisher}/{id}");
        let version = meta
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0")
            .to_string();
        let passport_rev = meta
            .get("passportRev")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        let archetype = meta.get("archetype").and_then(|v| v.as_str()).unwrap_or("");
        let stateful = matches!(archetype, "stateful-service" | "operator-cluster");
        let endpoints = parse_passport_endpoints(raw).map_err(|e| e.to_string())?;
        let data_mount_path = doc
            .get("hardwareAndKernel")
            .and_then(|v| v.get("storage"))
            .and_then(|v| v.get("mountPath"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let image = doc
            .get("workload")
            .and_then(|v| v.get("container"))
            .and_then(|v| v.get("image"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let image_digest = doc
            .get("workload")
            .and_then(|v| v.get("container"))
            .and_then(|v| v.get("imageDigest"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let engine = doc
            .get("workload")
            .and_then(|v| v.get("engine"))
            .and_then(|v| v.as_str())
            .unwrap_or("k8s-deployment")
            .to_string();
        let container = doc
            .get("workload")
            .and_then(|v| v.get("container"))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null);
        let str_list = |v: Option<&serde_yaml::Value>| -> Vec<String> {
            v.and_then(|x| x.as_sequence())
                .map(|s| {
                    s.iter()
                        .filter_map(|i| i.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let command = str_list(container.get("command"));
        let args = str_list(container.get("args"));
        let container_name = container.get("name").and_then(|x| x.as_str()).map(String::from);
        let operator_spec = doc
            .get("workload")
            .and_then(|v| v.get("operatorSpec"))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                let get = |k: &str| {
                    m.get(serde_yaml::Value::String(k.to_string()))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                };
                OperatorSpecSummary {
                    adapter: get("adapter"),
                    crd_api_version: get("crdApiVersion"),
                    crd_kind: get("crdKind"),
                }
            });
        let mut scripts = Vec::new();
        if let Some(sm) = doc.get("scripts").and_then(|v| v.as_mapping()) {
            for (k, v) in sm {
                let name = k.as_str().unwrap_or_default().to_string();
                let runtime = v.get("runtime").and_then(|x| x.as_str()).unwrap_or("posix-sh").to_string();
                let path = v.get("path").and_then(|x| x.as_str()).map(String::from);
                let inline = v.get("inline").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                scripts.push(ScriptSummary { name, runtime, path, inline });
            }
        }
        let mut param_defaults = BTreeMap::new();
        let mut param_target_paths = BTreeMap::new();
        if let Some(pm) = doc.get("parameters").and_then(|v| v.as_mapping()) {
            for (k, v) in pm {
                let key = k.as_str().unwrap_or_default().to_string();
                if let Some(d) = v.get("default") {
                    if let Ok(j) = serde_yaml::to_value(d).and_then(|_| Ok(serde_json::to_value(
                        serde_yaml::from_value::<serde_json::Value>(d.clone()).unwrap_or_default(),
                    ).unwrap_or_default())) {
                        param_defaults.insert(key.clone(), j);
                    }
                }
                if let Some(tp) = v.get("targetPath").and_then(|x| x.as_str()) {
                    param_target_paths.insert(key.clone(), tp.to_string());
                }
            }
        }
        let mut requires_env = BTreeMap::new();
        if let Some(req) = doc.get("interfaces").and_then(|v| v.get("requires")).and_then(|v| v.as_mapping()) {
            for (k, v) in req {
                let key = k.as_str().unwrap_or_default().to_string();
                let mut envs = BTreeMap::new();
                if let Some(em) = v.get("envMapping").and_then(|x| x.as_mapping()) {
                    for (ek, ev) in em {
                        let Some(e) = ek.as_str() else { continue };
                        if let Some(t) = ev.as_str() {
                            envs.insert(e.to_string(), EnvValue::Shared(t.to_string()));
                        } else if let Some(pm) = ev.as_mapping() {
                            let mut per = BTreeMap::new();
                            for (pk, pv) in pm {
                                if let (Some(p), Some(t)) = (pk.as_str(), pv.as_str()) {
                                    per.insert(p.to_string(), t.to_string());
                                }
                            }
                            envs.insert(e.to_string(), EnvValue::PerProcess(per));
                        }
                    }
                }
                requires_env.insert(key, envs);
            }
        }
        let mut processes = BTreeMap::new();
        if let Some(pr) = doc.get("processes").and_then(|v| v.as_mapping()) {
            for (k, v) in pr {
                processes.insert(
                    k.as_str().unwrap_or_default().to_string(),
                    v.get("role").and_then(|x| x.as_str()).unwrap_or("runtime").to_string(),
                );
            }
        }
        let backup = doc
            .get("operations")
            .and_then(|v| v.get("backup"))
            .map(|b| BackupSummary {
                mode: b.get("mode").and_then(|x| x.as_str()).unwrap_or("custom-job").to_string(),
                driver: b.get("driver").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                default_cron: b.get("defaultCron").and_then(|x| x.as_str()).unwrap_or("0 2 * * *").to_string(),
                retention_days: b.get("retentionDays").and_then(|x| x.as_u64()).unwrap_or(30) as u32,
            });
        let has_provisioner = doc
            .get("interfaces")
            .and_then(|v| v.get("provides"))
            .and_then(|v| v.as_sequence())
            .map(|s| s.iter().any(|p| p.get("provisioner").is_some()))
            .unwrap_or(false);
        let mut config_mounts = Vec::new();
        if let Some(cm) = doc.get("workload").and_then(|v| v.get("configMounts")).and_then(|v| v.as_sequence()) {
            for m in cm {
                let (Some(n), Some(p)) = (
                    m.get("name").and_then(|x| x.as_str()),
                    m.get("mountPath").and_then(|x| x.as_str()),
                ) else {
                    continue;
                };
                let items = m
                    .get("items")
                    .and_then(|x| x.as_sequence())
                    .map(|s| {
                        s.iter()
                            .filter_map(|i| {
                                Some((
                                    i.get("key").and_then(|x| x.as_str())?.to_string(),
                                    i.get("path").and_then(|x| x.as_str()).map(String::from),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                config_mounts.push(ConfigMountDecl {
                    name: n.to_string(),
                    mount_path: p.to_string(),
                    sub_path: m.get("subPath").and_then(|x| x.as_str()).map(String::from),
                    from_secret: m
                        .get("fromSecret")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(true),
                    source: m.get("source").and_then(|x| x.as_str()).map(String::from),
                    items,
                    read_only: m.get("readOnly").and_then(|x| x.as_bool()).unwrap_or(true),
                    default_mode: m.get("defaultMode").and_then(|x| x.as_i64()).map(|v| v as i32),
                });
            }
        }
        let mut env_decls = Vec::new();
        let mut ports = Vec::new();
        if let Some(c) = doc.get("workload").and_then(|v| v.get("container")) {
            if let Some(ea) = c.get("env").and_then(|v| v.as_sequence()) {
                for e in ea {
                    let Some(name) = e.get("name").and_then(|x| x.as_str()) else { continue };
                    let vf = e.get("valueFrom");
                    env_decls.push(EnvDecl {
                        name: name.to_string(),
                        value: e.get("value").and_then(|x| x.as_str()).map(String::from),
                        field_path: vf
                            .and_then(|v| v.get("fieldRef"))
                            .and_then(|v| v.get("fieldPath"))
                            .and_then(|x| x.as_str())
                            .map(String::from),
                        secret_name: vf
                            .and_then(|v| v.get("secretKeyRef"))
                            .and_then(|v| v.get("name"))
                            .and_then(|x| x.as_str())
                            .map(String::from),
                        secret_key: vf
                            .and_then(|v| v.get("secretKeyRef"))
                            .and_then(|v| v.get("key"))
                            .and_then(|x| x.as_str())
                            .map(String::from),
                    });
                }
            }
            if let Some(pa) = c.get("ports").and_then(|v| v.as_sequence()) {
                for p in pa {
                    if let (Some(n), Some(cp)) = (
                        p.get("name").and_then(|x| x.as_str()),
                        p.get("containerPort").and_then(|x| x.as_u64()),
                    ) {
                        ports.push(PortDecl {
                            name: n.to_string(),
                            container_port: cp as u16,
                        });
                    }
                }
            }
        }
        let security_context = doc
            .get("workload")
            .and_then(|v| v.get("container"))
            .and_then(|v| v.get("securityContext"))
            .map(|s| SecurityContextDecl {
                run_as_non_root: s.get("runAsNonRoot").and_then(|x| x.as_bool()),
                run_as_user: s.get("runAsUser").and_then(|x| x.as_i64()),
                run_as_group: s.get("runAsGroup").and_then(|x| x.as_i64()),
                fs_group: s.get("fsGroup").and_then(|x| x.as_i64()),
                seccomp_profile: s.get("seccompProfile").and_then(|x| x.as_str()).map(String::from),
                allow_privilege_escalation: s.get("allowPrivilegeEscalation").and_then(|x| x.as_bool()),
                capabilities_drop: s
                    .get("capabilitiesDrop")
                    .and_then(|x| x.as_sequence())
                    .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
            });
        let parse_probe = |p: &serde_yaml::Value| -> Option<ProbeDecl> {
            Some(ProbeDecl {
                probe_type: p.get("type").and_then(|x| x.as_str()).unwrap_or("http").to_string(),
                port: p.get("port").and_then(|x| x.as_u64()).map(|v| v as u16),
                path: p.get("path").and_then(|x| x.as_str()).map(String::from),
                command: p
                    .get("command")
                    .and_then(|x| x.as_sequence())
                    .map(|s| s.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                period_seconds: p.get("periodSeconds").and_then(|x| x.as_u64()).map(|v| v as u32),
                timeout_seconds: p.get("timeoutSeconds").and_then(|x| x.as_u64()).map(|v| v as u32),
                failure_threshold: p.get("failureThreshold").and_then(|x| x.as_u64()).map(|v| v as u32),
                initial_delay_seconds: p
                    .get("initialDelaySeconds")
                    .and_then(|x| x.as_u64())
                    .map(|v| v as u32),
            })
        };
        let probes = doc
            .get("workload")
            .and_then(|v| v.get("probes"))
            .map(|p| ProbesDecl {
                startup: p.get("startup").and_then(parse_probe),
                liveness: p.get("liveness").and_then(parse_probe),
                readiness: p.get("readiness").and_then(parse_probe),
            })
            .unwrap_or_default();
        let mut update_strategies = BTreeMap::new();
        if let Some(tm) = doc.get("topologyModes").and_then(|v| v.as_mapping()) {
            for (k, v) in tm {
                if let (Some(mode), Some(st)) = (
                    k.as_str(),
                    v.get("disruptionBudget")
                        .and_then(|d| d.get("updateStrategy"))
                        .and_then(|x| x.as_str()),
                ) {
                    update_strategies.insert(mode.to_string(), st.to_string());
                }
            }
        }
        let mut exported_tokens = BTreeMap::new();
        if let Some(provs) = doc.get("interfaces").and_then(|v| v.get("provides")).and_then(|v| v.as_sequence()) {
            for p in provs {
                if let Some(tokens) = p
                    .get("clientContract")
                    .and_then(|v| v.get("exportedTokens"))
                    .and_then(|v| v.as_mapping())
                {
                    for (tk, tv) in tokens {
                        if let (Some(t), Some(val)) = (tk.as_str(), tv.as_str()) {
                            exported_tokens.insert(t.to_string(), val.to_string());
                        }
                    }
                }
            }
        }
        let pre_deploy_script = doc
            .get("workload")
            .and_then(|v| v.get("lifecycle"))
            .and_then(|v| v.get("preDeployExpandCommand"))
            .and_then(|v| v.get("scriptRef"))
            .and_then(|v| v.as_str())
            .map(|s| s.rsplit('/').next().unwrap_or_default().to_string());
        let shm_size_mb = doc
            .get("hardwareAndKernel")
            .and_then(|v| v.get("resources"))
            .and_then(|v| v.get("shmSizeMb"))
            .and_then(|v| v.as_u64());
        Ok(Self {
            id,
            version,
            passport_rev,
            engine,
            stateful,
            client_sidecars: Vec::new(),
            endpoints,
            data_mount_path,
            image,
            image_digest,
            command,
            args,
            container_name,
            operator_spec,
            scripts,
            param_defaults,
            param_target_paths,
            requires_env,
            processes,
            backup,
            has_provisioner,
            config_mounts,
            shm_size_mb,
            env_decls,
            ports,
            security_context,
            probes,
            update_strategies,
            exported_tokens,
            pre_deploy_script,
        })
    }
}

/// Catalog lookup by passport id (or path).
///
/// Also retains the raw passport YAML per id — the deployment bundle pins
/// exact catalog content (Design Doc 0026 §1.1), so the compiler must be able
/// to reproduce `catalog/<id>/rev<N>.yaml` byte-for-byte.
#[derive(Debug, Default, Clone)]
pub struct PassportIndex {
    inner: BTreeMap<String, PassportSummary>,
    raw: BTreeMap<String, String>,
}

impl PassportIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: PassportSummary) {
        self.inner.insert(summary.id.clone(), summary);
    }

    /// Parse and index a passport document, retaining its raw YAML for
    /// catalog pins. The summary id must match `metadata.id`.
    pub fn insert_document(&mut self, raw: &str) -> Result<(), String> {
        let summary = PassportSummary::from_passport_yaml(raw)?;
        self.raw.insert(summary.id.clone(), raw.to_string());
        self.inner.insert(summary.id.clone(), summary);
        Ok(())
    }

    /// Raw YAML of a catalog passport (for bundle pins), when known.
    pub fn raw_of(&self, id: &str) -> Option<&str> {
        self.raw.get(id).map(|s| s.as_str())
    }

    pub fn get(&self, id: &str) -> Option<&PassportSummary> {
        self.inner.get(id)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl FromIterator<PassportSummary> for PassportIndex {
    fn from_iter<T: IntoIterator<Item = PassportSummary>>(iter: T) -> Self {
        let mut idx = PassportIndex::new();
        for s in iter {
            idx.insert(s);
        }
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sidecar(name: &str, modes: Vec<&str>) -> (Vec<String>, ClientSidecar) {
        (
            modes.into_iter().map(String::from).collect(),
            ClientSidecar {
                name: name.into(),
                image: format!("example/{name}:1"),
                injection_target: "k8s-native-init-restart-always".into(),
                listeners: vec![SidecarListener {
                    name: "rw".into(),
                    base_local_port: 5432,
                    target_role: "primary-rw".into(),
                }],
                cpu_millicores: 50,
                memory_mb: 48,
                shared_quota_formula: None,
                pre_stop_drain_delay_sec: Some(5),
            },
        )
    }

    #[test]
    fn sidecars_filtered_by_mode() {
        let p = PassportSummary {
            id: "test-org/postgresql".into(),
            version: "18.0.0".into(),
            passport_rev: 6,
            engine: "k8s-statefulset".into(),
        stateful: true,
            client_sidecars: vec![
                sidecar("pgbouncer", vec!["degraded-ha", "strict-ha"]),
                sidecar("always", vec![]),
            ],
            endpoints: Vec::new(),
            data_mount_path: None,
            image: None,
            image_digest: None,
            command: Vec::new(),
            args: Vec::new(),
            container_name: None,
            operator_spec: None,
            scripts: Vec::new(),
            param_defaults: BTreeMap::new(),
            param_target_paths: BTreeMap::new(),
            requires_env: BTreeMap::new(),
            processes: BTreeMap::new(),
            backup: None,
            has_provisioner: false,
            config_mounts: Vec::new(),
            shm_size_mb: None,
            env_decls: Vec::new(),
            ports: Vec::new(),
            security_context: None,
            probes: ProbesDecl::default(),
            update_strategies: BTreeMap::new(),
            exported_tokens: BTreeMap::new(),
            pre_deploy_script: None,
        };
        let got = p.client_sidecars_for_mode("standalone");
        assert_eq!(got.len(), 1, "only empty-mode (always) sidecar");
        assert_eq!(got[0].name, "always");
        let got2 = p.client_sidecars_for_mode("strict-ha");
        assert_eq!(got2.len(), 2);
    }

    #[test]
    fn index_lookup() {
        let mut idx = PassportIndex::new();
        assert!(idx.is_empty());
        idx.insert(PassportSummary {
            id: "test-org/stateless-app".into(),
            version: "1.0.0".into(),
            passport_rev: 1,
            engine: "k8s-deployment".into(),
        stateful: false,
            client_sidecars: vec![],
            endpoints: Vec::new(),
            data_mount_path: None,
            image: None,
            image_digest: None,
            command: Vec::new(),
            args: Vec::new(),
            container_name: None,
            operator_spec: None,
            scripts: Vec::new(),
            param_defaults: BTreeMap::new(),
            param_target_paths: BTreeMap::new(),
            requires_env: BTreeMap::new(),
            processes: BTreeMap::new(),
            backup: None,
            has_provisioner: false,
            config_mounts: Vec::new(),
            shm_size_mb: None,
            env_decls: Vec::new(),
            ports: Vec::new(),
            security_context: None,
            probes: ProbesDecl::default(),
            update_strategies: BTreeMap::new(),
            exported_tokens: BTreeMap::new(),
            pre_deploy_script: None,
        });
        assert_eq!(idx.len(), 1);
        assert!(idx.get("test-org/stateless-app").is_some());
        assert!(idx.get("missing").is_none());
        let collected: PassportIndex = vec![].into_iter().collect();
        assert!(collected.is_empty());
    }

    #[test]
    fn endpoint_contract_resolves_port() {
        let raw = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: demo-web, publisher: test-org, title: Web, description: Test fixture, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
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
    - { name: admin, protocol: http, containerPort: 9090, role: management, defaultScope: protected }
  provides: []
  requires: {}
"#;
        let p = PassportSummary::from_passport_yaml(raw).unwrap();
        assert_eq!(p.id, "test-org/demo-web");
        assert_eq!(p.version, "1.0.0");
        assert!(!p.stateful);
        assert_eq!(p.endpoint_port("web"), Some(8080));
        assert_eq!(p.endpoint_port("admin"), Some(9090));
        assert_eq!(p.endpoint_port("missing"), None);
    }

    #[test]
    fn from_passport_yaml_rejects_missing_metadata() {
        assert!(PassportSummary::from_passport_yaml("kind: ComponentPassport\n").is_err());
        assert!(PassportSummary::from_passport_yaml(": : :").is_err());
    }
}
