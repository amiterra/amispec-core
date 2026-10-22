//! ComponentPassport structural rules (mirrors CUE `#ComponentPassport`).

use crate::patterns::{is_accent_color, is_sha256_digest, is_slug};
use crate::report::Finding;
use super::deep;
use crate::value::*;

const CATEGORIES: &[&str] = &[
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

const ARCHETYPES: &[&str] = &[
    "stateless-app",
    "stateful-service",
    "operator-cluster",
    "edge-gateway",
    "external-bridge",
    "scheduled-job",
];

const TIERS: &[&str] = &["open-core", "private-custom"];
const NODE_SHAPES: &[&str] = &[
    "standard-card",
    "database-cylinder",
    "queue-pipe",
    "gateway-shield",
    "external-cloud",
];
const ENGINES: &[&str] = &[
    "k8s-deployment",
    "k8s-statefulset",
    "k8s-daemonset",
    "k8s-cronjob",
    "flux-helm-release",
    "operator-crd",
];
const PRIORITY_CLASSES: &[&str] = &[
    "auto-by-archetype",
    "system-critical",
    "stateful-core",
    "stateless-web",
    "background-batch",
];
const PARAM_TYPES: &[&str] = &[
    "string",
    "int",
    "number",
    "bool",
    "enum",
    "string-list",
    "secret-ref",
];
const APPLY_IMPACTS: &[&str] = &["pod-restart", "hot-reload", "rolling-switchover", "immutable"];
const FORMULA_IMPACTS: &[&str] = &["hot-reload", "rolling-switchover", "pod-restart"];
const FORMULA_UNITS: &[&str] = &["MB", "GB", "bytes", "count", "string"];
const PROBE_TYPES: &[&str] = &["http", "tcp", "grpc", "exec"];
const PROBE_SCHEMES: &[&str] = &["HTTP", "HTTPS"];
const EGRESS_MODES: &[&str] = &["graph-only", "allow-public-internet", "allow-fqdn-whitelist"];
const TLS_MODES: &[&str] = &["none", "auto-internal-ca", "self-signed-upstream"];
const PROTOCOLS: &[&str] = &["http", "grpc", "tcp", "udp", "tcp-udp"];
const ENDPOINT_ROLES: &[&str] = &[
    "ui",
    "api",
    "management",
    "telemetry",
    "datastore",
    "event-stream",
    "generic",
];
const SCOPES: &[&str] = &["public", "protected", "cluster-private", "telemetry"];
const INJECTION_TARGETS: &[&str] = &["k8s-native-init-restart-always", "standard-container"];
const DEDUP_SCOPES: &[&str] = &["per-target-component", "per-binding"];
const PORT_STRATEGIES: &[&str] = &["deterministic-offset", "static"];
const TARGET_ROLES: &[&str] = &["primary-rw", "replicas-ro", "all-healthy"];
const DEP_STAGES: &[&str] = &["infrastructure-ready", "runtime-parallel"];
const SCALE_DOWN: &[&str] = &["safe-drain-required", "immediate"];
const UPDATE_STRATEGY: &[&str] = &["rolling", "primary-last", "recreate"];
const ANTI_AFFINITY: &[&str] = &[
    "soft",
    "spread-skew-1",
    "hard-per-node",
    "hard-per-zone",
    "hard-per-disk",
];
const CPU_LIMIT_POLICY: &[&str] = &["burstable-no-limit", "hard-cfs-limit"];
const NETWORK_QOS: &[&str] = &["realtime-interactive", "throughput-data", "background-bulk"];
const BACKUP_MODES: &[&str] = &[
    "operator-managed",
    "sidecar-stream",
    "volume-snapshot-job",
    "custom-job",
];
const DAY2_CATEGORIES: &[&str] = &["first-aid", "maintenance", "migration-cutover", "scaling"];
const EXEC_TYPES: &[&str] = &["gitops-patch", "k8s-job", "operator-annotation"];

pub fn check(root: &Map, out: &mut Vec<Finding>) {
    // --- metadata ---
    let Some(meta) = root.get("metadata") else {
        out.push(Finding::error("metadata", "required", "metadata is required"));
        return;
    };
    if as_map(meta).is_none() {
        out.push(Finding::error("metadata", "type-map", "metadata MUST be a mapping"));
        return;
    }

    if let Some(id) = req_str(meta, "id", "metadata", out) {
        if !is_slug(&id) {
            out.push(Finding::error(
                "metadata.id",
                "id-regex",
                format!("id `{id}` MUST match ^[a-z0-9-]+$"),
            ));
        }
    }
    req_str(meta, "name", "metadata", out);
    req_str(meta, "version", "metadata", out);

    match get(meta, "passportRev").and_then(as_i64) {
        Some(n) if n >= 1 => {}
        Some(n) => out.push(Finding::error(
            "metadata.passportRev",
            "passportRev-min",
            format!("passportRev {n} MUST be >= 1"),
        )),
        None => out.push(Finding::error(
            "metadata.passportRev",
            "required",
            "passportRev is required and MUST be an integer >= 1",
        )),
    }

    req_enum(meta, "category", "metadata", CATEGORIES, out, "category-enum");
    req_enum(meta, "archetype", "metadata", ARCHETYPES, out, "archetype-enum");

    // distribution
    if let Some(dist) = get(meta, "distribution") {
        check_enum(dist, "tier", "metadata.distribution", TIERS, out, "tier-enum");
        if let Some(lic) = opt_str(dist, "license") {
            if lic.is_empty() {
                out.push(Finding::error(
                    "metadata.distribution.license",
                    "required",
                    "license MUST be non-empty",
                ));
            }
        }
        if let Some(vendor) = get(dist, "vendor") {
            req_str(vendor, "name", "metadata.distribution.vendor", out);
        }
    } else {
        out.push(Finding::error(
            "metadata.distribution",
            "required",
            "distribution is required",
        ));
    }

    // canvasUI
    if let Some(ui) = get(meta, "canvasUI") {
        req_str(ui, "icon", "metadata.canvasUI", out);
        if let Some(c) = opt_str(ui, "accentColor") {
            if !is_accent_color(c) {
                out.push(Finding::error(
                    "metadata.canvasUI.accentColor",
                    "accent-color-regex",
                    format!("`{c}` MUST match ^#[0-9a-fA-F]{{6}}$"),
                ));
            }
        } else {
            out.push(Finding::error(
                "metadata.canvasUI.accentColor",
                "required",
                "accentColor is required",
            ));
        }
        req_enum(ui, "nodeShape", "metadata.canvasUI", NODE_SHAPES, out, "node-shape-enum");
    } else {
        out.push(Finding::error(
            "metadata.canvasUI",
            "required",
            "canvasUI is required",
        ));
    }


    // --- parameters ---
    if let Some(params) = root.get("parameters").and_then(as_map) {
        for (k, v) in params {
            let ppath = format!("parameters.{}", key_str(k));
            req_str(v, "label", &ppath, out);
            req_enum(v, "type", &ppath, PARAM_TYPES, out, "param-type-enum");
            req_enum(v, "applyImpact", &ppath, APPLY_IMPACTS, out, "apply-impact-enum");
            if opt_str(v, "type") == Some("enum") {
                match get(v, "enumValues").and_then(as_seq) {
                    Some(list) if !list.is_empty() => {}
                    _ => out.push(Finding::error(
                        format!("{ppath}.enumValues"),
                        "required",
                        "enum parameters MUST set non-empty enumValues",
                    )),
                }
            }
        }
    }

    // --- topologyModes (required non-empty mapping) ---
    match root.get("topologyModes").and_then(as_map) {
        Some(modes) if !modes.is_empty() => {
            for (k, v) in modes {
                let mpath = format!("topologyModes.{}", key_str(k));
                req_str(v, "description", &mpath, out);
                check_int_range(v, "minNodes", &mpath, 1, None, out, "min-nodes-min");
                if get(v, "replicas").is_none() {
                    out.push(Finding::error(
                        format!("{mpath}.replicas"),
                        "required",
                        "replicas is required (int or CEL string)",
                    ));
                }
                req_enum(v, "scaleDownPolicy", &mpath, SCALE_DOWN, out, "scale-down-enum");
                if let Some(budget) = get(v, "disruptionBudget") {
                    check_enum(
                        budget,
                        "updateStrategy",
                        &format!("{mpath}.disruptionBudget"),
                        UPDATE_STRATEGY,
                        out,
                        "update-strategy-enum",
                    );
                } else {
                    out.push(Finding::error(
                        format!("{mpath}.disruptionBudget"),
                        "required",
                        "disruptionBudget is required",
                    ));
                }
                req_enum(
                    v,
                    "podAntiAffinity",
                    &mpath,
                    ANTI_AFFINITY,
                    out,
                    "anti-affinity-enum",
                );
                if let Some(w) = get(v, "witnessComponent") {
                    check_int_range(
                        w,
                        "replicas",
                        &format!("{mpath}.witnessComponent"),
                        1,
                        None,
                        out,
                        "witness-replicas",
                    );
                    check_int_range(
                        w,
                        "cpuMillicores",
                        &format!("{mpath}.witnessComponent"),
                        0,
                        Some(1000),
                        out,
                        "witness-cpu",
                    );
                    check_int_range(
                        w,
                        "memoryMb",
                        &format!("{mpath}.witnessComponent"),
                        0,
                        Some(512),
                        out,
                        "witness-mem",
                    );
                }
            }
        }
        _ => out.push(Finding::error(
            "topologyModes",
            "required",
            "topologyModes MUST be a non-empty mapping",
        )),
    }

    // --- workload ---
    if let Some(wl) = root.get("workload") {
        req_enum(wl, "engine", "workload", ENGINES, out, "engine-enum");
        req_enum(
            wl,
            "priorityClass",
            "workload",
            PRIORITY_CLASSES,
            out,
            "priority-class-enum",
        );
        if let Some(c) = get(wl, "container") {
            req_str(c, "image", "workload.container", out);
            if let Some(d) = opt_str(c, "imageDigest") {
                if !is_sha256_digest(d) {
                    out.push(Finding::error(
                        "workload.container.imageDigest",
                        "image-digest-regex",
                        format!("`{d}` MUST match ^sha256:[a-f0-9]{{64}}$"),
                    ));
                }
            }
        }
        if let Some(probes) = get(wl, "probes").and_then(as_map) {
            for (k, p) in probes {
                let ppath = format!("workload.probes.{}", key_str(k));
                check_enum(p, "type", &ppath, PROBE_TYPES, out, "probe-type-enum");
                check_enum(p, "scheme", &ppath, PROBE_SCHEMES, out, "probe-scheme-enum");
                check_int_range(p, "failureThreshold", &ppath, 1, None, out, "probe-threshold");
                check_int_range(p, "periodSeconds", &ppath, 1, None, out, "probe-period");
                check_int_range(p, "timeoutSeconds", &ppath, 1, None, out, "probe-timeout");
                // CUE: liveness?: #ProbeSpec & {localProcessOnly: true}
                if key_str(k) == "liveness" {
                    match get(p, "localProcessOnly").and_then(as_bool) {
                        Some(true) | None => {} // absent is OK (default true in #ProbeSpec)
                        Some(false) => out.push(Finding::error(
                            format!("{ppath}.localProcessOnly"),
                            "liveness-local-only",
                            "liveness.localProcessOnly MUST be true",
                        )),
                    }
                }
            }
        }
        if let Some(formulas) = get(wl, "configFormulas").and_then(as_map) {
            for (k, f) in formulas {
                let fpath = format!("workload.configFormulas.{}", key_str(k));
                req_str(f, "cel", &fpath, out);
                req_str(f, "targetPath", &fpath, out);
                req_str(f, "description", &fpath, out);
                req_enum(f, "applyImpact", &fpath, FORMULA_IMPACTS, out, "formula-impact-enum");
                check_enum(f, "unit", &fpath, FORMULA_UNITS, out, "formula-unit-enum");
            }
        }
        if let Some(op) = get(wl, "operatorSpec") {
            deep::check_operator_spec(op, "workload.operatorSpec", out);
        }
        if let Some(helm) = get(wl, "helmSpec") {
            req_str(helm, "repository", "workload.helmSpec", out);
            req_str(helm, "chart", "workload.helmSpec", out);
            req_str(helm, "version", "workload.helmSpec", out);
            if let Some(d) = opt_str(helm, "chartDigest") {
                if !is_sha256_digest(d) {
                    out.push(Finding::error(
                        "workload.helmSpec.chartDigest",
                        "image-digest-regex",
                        format!("`{d}` MUST match ^sha256:[a-f0-9]{{64}}$"),
                    ));
                }
            }
        }
    } else {
        out.push(Finding::error("workload", "required", "workload is required"));
    }

    // --- interfaces ---
    if let Some(ifaces) = root.get("interfaces") {
        req_enum(
            ifaces,
            "egressDefaultMode",
            "interfaces",
            EGRESS_MODES,
            out,
            "egress-enum",
        );
        if let Some(eps) = get(ifaces, "endpoints").and_then(as_seq) {
            for (i, ep) in eps.iter().enumerate() {
                let epath = format!("interfaces.endpoints[{i}]");
                req_str(ep, "name", &epath, out);
                req_enum(ep, "protocol", &epath, PROTOCOLS, out, "protocol-enum");
                req_enum(ep, "role", &epath, ENDPOINT_ROLES, out, "endpoint-role-enum");
                req_enum(ep, "defaultScope", &epath, SCOPES, out, "scope-enum");
                check_enum(ep, "tlsMode", &epath, TLS_MODES, out, "tls-mode-enum");
                match get(ep, "containerPort").and_then(as_i64) {
                    Some(p) if (1..=65535).contains(&p) => {}
                    Some(p) => out.push(Finding::error(
                        format!("{epath}.containerPort"),
                        "port-range",
                        format!("port {p} MUST be in 1..=65535"),
                    )),
                    None => out.push(Finding::error(
                        format!("{epath}.containerPort"),
                        "required",
                        "containerPort is required",
                    )),
                }
            }
        }
        if let Some(provides) = get(ifaces, "provides").and_then(as_seq) {
            for (i, slot) in provides.iter().enumerate() {
                let spath = format!("interfaces.provides[{i}]");
                req_str(slot, "slot", &spath, out);
                req_str(slot, "capability", &spath, out);
                req_str(slot, "version", &spath, out);
                if let Some(cc) = get(slot, "clientContract") {
                    let cpath = format!("{spath}.clientContract");
                    if let Some(sq) = get(cc, "sharedQuotaFormula").or_else(|| get(get(cc, "sidecar").unwrap_or(&serde_yaml::Value::Null), "sharedQuotaFormula")) {
                        if let Some(s) = as_str(sq) {
                            if s.trim().is_empty() {
                                out.push(Finding::error(
                                    format!("{cpath}.sharedQuotaFormula"),
                                    "shared-quota",
                                    "sharedQuotaFormula MUST be a non-empty CEL expression",
                                ));
                            }
                        }
                    }
                    if let Some(side) = get(cc, "sidecar") {
                        if let Some(sq) = get(side, "sharedQuotaFormula") {
                            if let Some(s) = as_str(sq) {
                                if s.trim().is_empty() {
                                    out.push(Finding::error(
                                        format!("{cpath}.sidecar.sharedQuotaFormula"),
                                        "shared-quota",
                                        "sharedQuotaFormula MUST be a non-empty CEL expression",
                                    ));
                                }
                            }
                        }
                        let sp = format!("{cpath}.sidecar");
                        req_str(side, "name", &sp, out);
                        req_str(side, "image", &sp, out);
                        req_str(side, "configTemplate", &sp, out);
                        req_enum(
                            side,
                            "injectionTarget",
                            &sp,
                            INJECTION_TARGETS,
                            out,
                            "injection-target-enum",
                        );
                        req_enum(
                            side,
                            "deduplicationScope",
                            &sp,
                            DEDUP_SCOPES,
                            out,
                            "dedup-enum",
                        );
                        req_enum(
                            side,
                            "portAllocationStrategy",
                            &sp,
                            PORT_STRATEGIES,
                            out,
                            "port-strategy-enum",
                        );
                        check_int_range(side, "cpuMillicores", &sp, 0, Some(200), out, "sidecar-cpu");
                        check_int_range(side, "memoryMb", &sp, 0, Some(128), out, "sidecar-mem");
                        if let Some(listeners) = get(side, "listeners").and_then(as_seq) {
                            if listeners.is_empty() {
                                out.push(Finding::error(
                                    format!("{sp}.listeners"),
                                    "min-items",
                                    "listeners MUST be non-empty",
                                ));
                            }
                            for (li, ln) in listeners.iter().enumerate() {
                                let lpath = format!("{sp}.listeners[{li}]");
                                req_str(ln, "name", &lpath, out);
                                req_enum(
                                    ln,
                                    "targetRole",
                                    &lpath,
                                    TARGET_ROLES,
                                    out,
                                    "listener-role-enum",
                                );
                                match get(ln, "baseLocalPort").and_then(as_i64) {
                                    Some(p) if (1024..=65535).contains(&p) => {}
                                    Some(p) => out.push(Finding::error(
                                        format!("{lpath}.baseLocalPort"),
                                        "port-range",
                                        format!("baseLocalPort {p} MUST be in 1024..=65535"),
                                    )),
                                    None => out.push(Finding::error(
                                        format!("{lpath}.baseLocalPort"),
                                        "required",
                                        "baseLocalPort is required",
                                    )),
                                }
                            }
                        } else {
                            out.push(Finding::error(
                                format!("{sp}.listeners"),
                                "required",
                                "listeners is required",
                            ));
                        }
                    }
                }
                if let Some(prov) = get(slot, "provisioner") {
                    req_str(prov, "driver", &format!("{spath}.provisioner"), out);
                    req_str(prov, "image", &format!("{spath}.provisioner"), out);
                    if let Some(r) = opt_str(prov, "scriptRef") {
                        if !crate::patterns::is_script_ref(r) {
                            out.push(Finding::error(
                                format!("{spath}.provisioner.scriptRef"),
                                "script-ref-regex",
                                format!("`{r}` MUST match scriptRef pattern"),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(reqs) = get(ifaces, "requires").and_then(as_map) {
            for (k, v) in reqs {
                let rpath = format!("interfaces.requires.{}", key_str(k));
                req_str(v, "capability", &rpath, out);
                req_enum(v, "dependencyStage", &rpath, DEP_STAGES, out, "dependency-stage-enum");
                if get(v, "envMapping").and_then(as_map).is_none() {
                    out.push(Finding::error(
                        format!("{rpath}.envMapping"),
                        "required",
                        "envMapping is required",
                    ));
                }
            }
        }
    } else {
        out.push(Finding::error("interfaces", "required", "interfaces is required"));
    }

    // --- hardwareAndKernel ---
    if let Some(hw) = root.get("hardwareAndKernel") {
        if let Some(res) = get(hw, "resources") {
            let rpath = "hardwareAndKernel.resources";
            check_int_range(res, "minMemoryMb", rpath, 1, None, out, "mem-min");
            check_int_range(res, "recommendedMemoryMb", rpath, 1, None, out, "mem-rec");
            check_int_range(
                res,
                "oomSafetyMarginPercent",
                rpath,
                5,
                Some(50),
                out,
                "oom-range",
            );
            check_int_range(res, "ephemeralStorageMb", rpath, 0, None, out, "ephemeral");
            // networkQosClass and cpuLimitPolicy have CUE defaults — optional if omitted
            check_enum(res, "networkQosClass", rpath, NETWORK_QOS, out, "qos-enum");
            check_enum(res, "cpuLimitPolicy", rpath, CPU_LIMIT_POLICY, out, "cpu-limit-enum");
            if get(res, "minCpuCores").and_then(as_f64).is_none() {
                out.push(Finding::error(
                    format!("{rpath}.minCpuCores"),
                    "required",
                    "minCpuCores is required",
                ));
            }
        } else {
            out.push(Finding::error(
                "hardwareAndKernel.resources",
                "required",
                "resources is required",
            ));
        }
    } else {
        out.push(Finding::error(
            "hardwareAndKernel",
            "required",
            "hardwareAndKernel is required",
        ));
    }

    // --- operations ---
    if let Some(ops) = root.get("operations") {
        if let Some(obs) = get(ops, "observability") {
            if let Some(s) = opt_str(obs, "scrapeInterval") {
                if s.is_empty() {
                    out.push(Finding::error(
                        "operations.observability.scrapeInterval",
                        "required",
                        "scrapeInterval MUST be non-empty",
                    ));
                }
            }
            if let Some(rules) = get(obs, "localAnomalyRules").and_then(as_seq) {
                for (i, r) in rules.iter().enumerate() {
                    let rpath = format!("operations.observability.localAnomalyRules[{i}]");
                    req_str(r, "metric", &rpath, out);
                    req_str(r, "algorithm", &rpath, out);
                }
            }
        } else {
            out.push(Finding::error(
                "operations.observability",
                "required",
                "observability is required",
            ));
        }
        if let Some(bk) = get(ops, "backup") {
            req_enum(
                bk,
                "mode",
                "operations.backup",
                BACKUP_MODES,
                out,
                "backup-mode-enum",
            );
            req_str(bk, "driver", "operations.backup", out);
            check_int_range(
                bk,
                "retentionDays",
                "operations.backup",
                1,
                None,
                out,
                "retention-min",
            );
        }
        if let Some(actions) = get(ops, "day2Actions").and_then(as_seq) {
            for (i, a) in actions.iter().enumerate() {
                let apath = format!("operations.day2Actions[{i}]");
                req_str(a, "id", &apath, out);
                req_str(a, "title", &apath, out);
                req_enum(a, "category", &apath, DAY2_CATEGORIES, out, "day2-category-enum");
                req_enum(a, "executionType", &apath, EXEC_TYPES, out, "day2-exec-enum");
                // MVP: support-role ACL is out of scope (no support contour).
                check_int_range(a, "cooldownSeconds", &apath, 0, None, out, "cooldown");
                check_int_range(
                    a,
                    "ttlSecondsAfterFinished",
                    &apath,
                    0,
                    None,
                    out,
                    "ttl",
                );
                if let Some(r) = opt_str(a, "scriptRef") {
                    if !crate::patterns::is_script_ref(r) {
                        out.push(Finding::error(
                            format!("{apath}.scriptRef"),
                            "script-ref-regex",
                            format!("`{r}` MUST match scriptRef pattern"),
                        ));
                    }
                }
            }
        }
    } else {
        out.push(Finding::error("operations", "required", "operations is required"));
    }

    // ===== deep nested rules (full enum / range coverage) =====
    if let Some(params) = root.get("parameters").and_then(as_map) {
        for (k, v) in params {
            deep::check_parameter_extras(v, &format!("parameters.{}", key_str(k)), out);
        }
    }
    if let Some(modes) = root.get("topologyModes").and_then(as_map) {
        for (k, v) in modes {
            deep::check_topology_mode_extras(v, &format!("topologyModes.{}", key_str(k)), out);
        }
    }
    if let Some(wl) = root.get("workload") {
        deep::check_workload_extras(wl, "workload", out);
        if let Some(helm) = get(wl, "helmSpec") {
            deep::check_digest_field(helm, "chartDigest", "workload.helmSpec", out);
        }
        if let Some(container) = get(wl, "container") {
            deep::check_digest_field(container, "imageDigest", "workload.container", out);
        }
        if let Some(comps) = get(wl, "companions").and_then(as_seq) {
            for (i, c) in comps.iter().enumerate() {
                let cp = format!("workload.companions[{i}]");
                req_str(c, "name", &cp, out);
                req_str(c, "image", &cp, out);
                deep::check_digest_field(c, "imageDigest", &cp, out);
                check_int_range(c, "memoryMb", &cp, 1, None, out, "companion-mem");
                match get(c, "cpuCores").and_then(as_f64) {
                    Some(x) if x > 0.0 => {}
                    _ => out.push(Finding::error(format!("{cp}.cpuCores"), "cpu-positive", "cpuCores MUST be > 0")),
                }
            }
        }
        if let Some(helm) = get(wl, "helmSpec") {
            deep::check_script_ref_field(helm, "valuesTemplate", "workload.helmSpec", out);
        }
    }
    if let Some(ifaces) = root.get("interfaces") {
        if let Some(eps) = get(ifaces, "endpoints").and_then(as_seq) {
            for (i, ep) in eps.iter().enumerate() {
                if let Some(gt) = get(ep, "gatewayTuning") {
                    deep::check_gateway_tuning(gt, &format!("interfaces.endpoints[{i}].gatewayTuning"), out);
                }
            }
        }
        if let Some(provides) = get(ifaces, "provides").and_then(as_seq) {
            for (i, slot) in provides.iter().enumerate() {
                let spath = format!("interfaces.provides[{i}]");
                if let Some(cc) = get(slot, "clientContract") {
                    if let Some(side) = get(cc, "sidecar") {
                        deep::check_sidecar_extra(side, &format!("{spath}.clientContract.sidecar"), out);
                    }
                    if get(cc, "exportedTokens").is_none() {
                        out.push(Finding::error(
                            format!("{spath}.clientContract.exportedTokens"),
                            "required",
                            "exportedTokens is required when clientContract is present",
                        ));
                    }
                }
                if let Some(prov) = get(slot, "provisioner") {
                    deep::check_script_ref_field(prov, "scriptRef", &format!("{spath}.provisioner"), out);
                }
            }
        }
        if let Some(reqs) = get(ifaces, "requires").and_then(as_map) {
            for (k, v) in reqs {
                deep::check_script_ref_field(v, "mountAsFilesPath", &format!("interfaces.requires.{}", key_str(k)), out);
            }
        }
        if let Some(scripts) = get(ifaces, "scripts") {
            deep::check_scripts(scripts, "interfaces.scripts", out);
        }
    }
    if let Some(scripts) = root.get("scripts") {
        deep::check_scripts(scripts, "scripts", out);
    }
    if let Some(hw) = root.get("hardwareAndKernel") {
        if let Some(res) = get(hw, "resources") {
            deep::check_hardware_resources_extras(res, "hardwareAndKernel.resources", out);
        }
        if let Some(st) = get(hw, "storage") {
            deep::check_volume(st, "hardwareAndKernel.storage", out);
        }
        if let Some(vols) = get(hw, "volumes") {
            deep::check_volumes_map(vols, "hardwareAndKernel.volumes", out);
        }
        if let Some(kt) = get(hw, "kernelTuning") {
            deep::check_kernel_tuning(kt, "hardwareAndKernel.kernelTuning", out);
        }
        if let Some(c) = get(hw, "constraints") {
            if let Some(list) = get(c, "incompatiblePassportsOnSameNode").and_then(as_seq) {
                for (i, item) in list.iter().enumerate() {
                    if let Some(s) = as_str(item) {
                        if s.is_empty() {
                            out.push(Finding::error(
                                format!("hardwareAndKernel.constraints.incompatiblePassportsOnSameNode[{i}]"),
                                "min-items",
                                "passports MUST be non-empty strings",
                            ));
                        }
                    }
                }
            }
        }
    }
    if let Some(ops) = root.get("operations") {
        if let Some(obs) = get(ops, "observability") {
            if let Some(rules) = get(obs, "localAnomalyRules").and_then(as_seq) {
                for (i, r) in rules.iter().enumerate() {
                    deep::check_anomaly_rule(r, &format!("operations.observability.localAnomalyRules[{i}]"), out);
                }
            }
        }
        if let Some(bk) = get(ops, "backup") {
            deep::check_backup(bk, "operations.backup", out);
        }
        if let Some(lm) = get(ops, "liveMigration") {
            deep::check_live_migration(lm, "operations.liveMigration", out);
            deep::check_live_migration_sources(lm, "operations.liveMigration", out);
        }
        if let Some(actions) = get(ops, "day2Actions").and_then(as_seq) {
            for (i, a) in actions.iter().enumerate() {
                deep::check_script_ref_field(a, "scriptRef", &format!("operations.day2Actions[{i}]"), out);
            }
        }
    }
}

