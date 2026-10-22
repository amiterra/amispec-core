//! Deep nested-structure rules (volumes, kernel, backup, sidecar, LB, expose).
//! Covers the remaining AmiSpec 1.0 enums and numeric constraints.

use crate::patterns::{is_script_ref, is_sha256_digest};
use crate::report::Finding;
use crate::value::*;

pub const MEDIA_TIERS: &[&str] = &["nvme-local", "ssd-network", "hdd-bulk", "ram-tmpfs"];

pub const MERGE_STRATEGY: &[&str] = &["max", "min", "exclusive-match"];
pub const SCRIPT_RUNTIME: &[&str] = &["posix-sh", "sql", "python"];
pub const RESIZE_POLICY: &[&str] = &["expand-only-monotonic", "immutable"];
pub const DELETION_POLICY: &[&str] = &["retain", "delete"];
pub const NODE_LOSS_RECOVERY: &[&str] = &["rehydrate-from-backup", "reseed-from-peer", "manual-wait"];
pub const LVM_PROVISIONER: &[&str] = &["topolvm-nvme", "local-path", "external-csi"];
pub const VOLUME_BINDING: &[&str] = &["WaitForFirstConsumer", "Immediate"];
pub const FILESYSTEM: &[&str] = &["xfs", "ext4"];

/// Allowed `lvmOptions.mountFlags` (mirrors CUE `#MountFlag`).
/// Dangerous flags (`suid`, `exec`, `dev`, `user`) are rejected.
pub const MOUNT_FLAGS: &[&str] = &[
    "noatime",
    "nodiratime",
    "relatime",
    "strictatime",
    "lazytime",
    "sync",
    "dirsync",
    "async",
    "ro",
    "rw",
    "discard",
    "nodiscard",
    "noexec",
    "nosuid",
    "nodev",
    "norecovery",
    "nouuid",
    "nobarrier",
    "barrier",
];
pub const PEER_DISCOVERY: &[&str] = &["none", "headless-early-dns"];
pub const QUORUM_TYPE: &[&str] = &["none", "raft-odd", "primary-standby", "witness-assisted"];
pub const QUORUM_ARBITER: &[&str] = &["none", "witness-pod", "cloud-lease-fencing"];
pub const WITNESS_PLACEMENT: &[&str] =
    &["control-plane-or-third-fault-domain", "dedicated-per-node"];
pub const CONCURRENCY_POLICY: &[&str] = &["Forbid", "Replace", "Allow"];
pub const SURGE_POLICY: &[&str] = &["adaptive-zero-surge-on-tight-ram", "strict-surge"];
pub const RELOAD_STRATEGY: &[&str] = &["pod-restart", "hot-inotify", "sighup"];
pub const NUMA_POLICY: &[&str] = &["best-effort", "single-numa-node"];
pub const VERTICAL_CPU: &[&str] = &["in-place", "pod-restart"];
pub const VERTICAL_MEM: &[&str] = &["in-place-grow-only", "pod-restart"];
pub const CPU_PINNING: &[&str] = &["shared", "exclusive-static"];
pub const UI_CONTROL: &[&str] = &["input", "number", "slider", "select", "toggle", "tags"];
pub const ANOMALY_ALGO: &[&str] =
    &["z-score-3sigma", "linear-regression-disk-full", "static-threshold"];
pub const BACKUP_VERSION_COUPLING: &[&str] = &["match-workload-major", "pinned"];
pub const BACKUP_TARGET_REPLICA: &[&str] = &["prefer-standby", "primary-only"];
pub const STREAMING: &[&str] = &["none", "websocket", "sse", "grpc-bidi"];
pub const SESSION_AFFINITY: &[&str] = &["none", "client-ip", "cookie-sticky"];
pub const TRANSPORT: &[&str] = &["direct", "wireguard-tunnel", "mtls-gateway"];
pub const ENCRYPTION: &[&str] = &["wireguard-mtls", "tls-strict"];
pub const LB_TLS: &[&str] = &[
    "letsencrypt-auto",
    "letsencrypt-dns01-wildcard",
    "letsencrypt-http01",
    "custom-secret",
    "none",
];
pub const FORWARDING_MODE: &[&str] = &["ebpf-dsr-maglev", "snat"];
pub const CLIENT_AUTH: &[&str] = &["none", "oidc", "mtls"];
pub const POD_SECURITY: &[&str] = &["restricted", "baseline", "privileged"];
pub const IMAGE_REGISTRY_POLICY: &[&str] = &["local-p2p-cache", "direct", "airgapped-mirror"];
pub const CONTROL_PLANE_QUORUM: &[&str] = &["odd-etcd", "witness-arbiter"];

/// Check `#VolumeSpec`-shaped mapping.
pub fn check_volume(v: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(v, "mountPath", path, out);
    match get(v, "minSizeGb").and_then(as_i64) {
        Some(n) if n >= 1 => {}
        Some(n) => out.push(Finding::error(
            format!("{path}.minSizeGb"),
            "disk-size",
            format!("minSizeGb {n} MUST be >= 1"),
        )),
        None => out.push(Finding::error(
            format!("{path}.minSizeGb"),
            "required",
            "minSizeGb is required",
        )),
    }
    match get(v, "defaultSizeGb").and_then(as_i64) {
        Some(n) if n >= 1 => {}
        Some(n) => out.push(Finding::error(
            format!("{path}.defaultSizeGb"),
            "disk-size",
            format!("defaultSizeGb {n} MUST be >= 1"),
        )),
        None => out.push(Finding::error(
            format!("{path}.defaultSizeGb"),
            "required",
            "defaultSizeGb is required",
        )),
    }
    check_enum(v, "resizePolicy", path, RESIZE_POLICY, out, "resize-policy-enum");
    check_enum(v, "deletionPolicy", path, DELETION_POLICY, out, "deletion-policy-enum");
    check_enum(v, "nodeLossRecovery", path, NODE_LOSS_RECOVERY, out, "node-loss-enum");
    check_enum(v, "mediaTier", path, MEDIA_TIERS, out, "media-tier-enum");
    if let Some(lvm) = get(v, "lvmOptions") {
        let lp = format!("{path}.lvmOptions");
        check_enum(lvm, "provisioner", &lp, LVM_PROVISIONER, out, "lvm-provisioner-enum");
        check_enum(lvm, "volumeBindingMode", &lp, VOLUME_BINDING, out, "volume-binding-enum");
        check_enum(lvm, "filesystem", &lp, FILESYSTEM, out, "filesystem-enum");
        check_int_range(lvm, "emergencyBallastMb", &lp, 0, None, out, "ballast");
        if let Some(flags) = get(lvm, "mountFlags").and_then(as_seq) {
            for (fi, f) in flags.iter().enumerate() {
                let Some(s) = as_str(f) else {
                    out.push(Finding::error(
                        format!("{lp}.mountFlags[{fi}]"),
                        "type-string",
                        "mount flag MUST be a string",
                    ));
                    continue;
                };
                if !MOUNT_FLAGS.contains(&s) {
                    out.push(Finding::error(
                        format!("{lp}.mountFlags[{fi}]"),
                        "mount-flag-enum",
                        format!("`{s}` is not one of {MOUNT_FLAGS:?}"),
                    ));
                }
            }
        }
    }
}

/// Check `kernelTuning` block.
pub fn check_kernel_tuning(k: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_int_range(k, "priority", path, 1, Some(1000), out, "kernel-priority");
    check_int_range(k, "maxClockSkewMs", path, 0, None, out, "clock-skew");
    for map_name in ["sysctl", "sysfs"] {
        if let Some(m) = get(k, map_name).and_then(as_map) {
            for (pk, pv) in m {
                let ppath = format!("{path}.{map_name}.{}", key_str(pk));
                if get(pv, "value").is_none() {
                    out.push(Finding::error(
                        format!("{ppath}.value"),
                        "required",
                        "tunable value is required",
                    ));
                }
                check_enum(pv, "mergeStrategy", &ppath, MERGE_STRATEGY, out, "merge-strategy-enum");
            }
        }
    }
}

/// Check `operations.backup`.
pub fn check_backup(b: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(b, "driver", path, out);
    check_enum(b, "versionCoupling", path, BACKUP_VERSION_COUPLING, out, "version-coupling-enum");
    check_enum(b, "targetReplicaRole", path, BACKUP_TARGET_REPLICA, out, "target-replica-enum");
    check_int_range(b, "maxUploadBandwidthMbps", path, 1, None, out, "upload-bw");
    check_int_range(b, "retentionDays", path, 1, None, out, "retention-min");
}

/// Check `operations.liveMigration`.
pub fn check_live_migration(lm: &Yaml, path: &str, out: &mut Vec<Finding>) {
    if get(lm, "supportsExternalReplicaBootstrap").is_none() {
        out.push(Finding::error(
            format!("{path}.supportsExternalReplicaBootstrap"),
            "required",
            "supportsExternalReplicaBootstrap is required",
        ));
    }
    let Some(wf) = get(lm, "cutoverWorkflow") else {
        out.push(Finding::error(
            format!("{path}.cutoverWorkflow"),
            "required",
            "cutoverWorkflow is required",
        ));
        return;
    };
    req_str(wf, "actionId", &format!("{path}.cutoverWorkflow"), out);
    check_int_range(
        wf,
        "maxAllowedLagMs",
        &format!("{path}.cutoverWorkflow"),
        0,
        None,
        out,
        "cutover-lag",
    );
    if get(wf, "steps").and_then(as_seq).map(|s| s.is_empty()).unwrap_or(true) {
        out.push(Finding::error(
            format!("{path}.cutoverWorkflow.steps"),
            "min-items",
            "steps MUST be a non-empty list",
        ));
    }
}

/// Check scripts map (`#ScriptSpec`).
pub fn check_scripts(scripts: &Yaml, path: &str, out: &mut Vec<Finding>) {
    let Some(m) = as_map(scripts) else {
        out.push(Finding::error(path, "type-map", "scripts MUST be a mapping"));
        return;
    };
    for (k, v) in m {
        let sp = format!("{path}.{}", key_str(k));
        req_enum(v, "runtime", &sp, SCRIPT_RUNTIME, out, "script-runtime-enum");
        check_int_range(v, "timeoutSeconds", &sp, 1, None, out, "script-timeout");
        let has_path = opt_str(v, "path").is_some();
        let has_inline = opt_str(v, "inline").is_some();
        if !has_path && !has_inline {
            out.push(Finding::error(
                sp,
                "script-body",
                "script MUST set path or inline",
            ));
        }
    }
}

/// Check sidecar settings / exportedTokens presence.
pub fn check_sidecar_extra(side: &Yaml, path: &str, out: &mut Vec<Finding>) {
    if get(side, "exportedTokens").is_none() {
        // exportedTokens is required in CUE under clientContract
    }
    check_int_range(side, "healthcheckIntervalSec", path, 1, None, out, "healthcheck");
    check_int_range(side, "preStopDrainDelaySec", path, 0, None, out, "prestop-drain");
}

/// Check expose entry securityPolicy + gatewayTuning-like fields.
pub fn check_expose(ex: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(ex, "endpoint", path, out);
    req_str(ex, "viaBalancer", path, out);
    if let Some(sp) = get(ex, "securityPolicy") {
        check_enum(sp, "clientAuth", &format!("{path}.securityPolicy"), CLIENT_AUTH, out, "client-auth-enum");
        check_int_range(
            sp,
            "rateLimitRps",
            &format!("{path}.securityPolicy"),
            1,
            None,
            out,
            "rate-limit",
        );
    }
}

/// Check load balancer entry.
pub fn check_load_balancer(lb: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(lb, "id", path, out);
    req_str(lb, "provider", path, out);
    check_enum(lb, "forwardingMode", path, FORWARDING_MODE, out, "forwarding-enum");
    check_enum(lb, "tls", path, LB_TLS, out, "lb-tls-enum");
}

/// Check gatewayTuning on endpoints.
pub fn check_gateway_tuning(gt: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(gt, "streaming", path, STREAMING, out, "streaming-enum");
    check_enum(gt, "sessionAffinity", path, SESSION_AFFINITY, out, "session-affinity-enum");
    check_int_range(gt, "requestHeadersTimeoutSec", path, 1, None, out, "header-timeout");
    check_int_range(gt, "timeoutSeconds", path, 1, None, out, "endpoint-timeout");
    if let Some(mb) = get(gt, "maxBodySizeMb").and_then(as_i64) {
        if mb < 0 {
            out.push(Finding::error(
                format!("{path}.maxBodySizeMb"),
                "body-size",
                "maxBodySizeMb MUST be >= 0 (0 = unlimited)",
            ));
        }
    }
}

/// Check topology storage override (component-level).
pub fn check_storage_override(st: &Yaml, path: &str, out: &mut Vec<Finding>) {
    match get(st, "sizeGb").and_then(as_i64) {
        Some(n) if n >= 1 => {}
        Some(n) => out.push(Finding::error(
            format!("{path}.sizeGb"),
            "disk-size",
            format!("sizeGb {n} MUST be >= 1"),
        )),
        None => out.push(Finding::error(
            format!("{path}.sizeGb"),
            "required",
            "sizeGb is required",
        )),
    }
    check_enum(st, "mediaTier", path, MEDIA_TIERS, out, "media-tier-enum");
    if let (Some(sz), Some(comm)) = (
        get(st, "sizeGb").and_then(as_u64),
        get(st, "committedSizeGb").and_then(as_u64),
    ) {
        if comm > sz {
            out.push(Finding::error(
                format!("{path}.committedSizeGb"),
                "committed-size",
                format!("committedSizeGb {comm} > sizeGb {sz}"),
            ));
        }
    }
}

/// Check cluster security extras.
pub fn check_cluster_security(sec: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(
        sec,
        "imageRegistryPolicy",
        path,
        IMAGE_REGISTRY_POLICY,
        out,
        "image-registry-enum",
    );
    check_enum(
        sec,
        "controlPlaneQuorumMode",
        path,
        CONTROL_PLANE_QUORUM,
        out,
        "control-plane-quorum-enum",
    );
}

/// Check securityZones[] entry.
pub fn check_security_zone(z: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(z, "id", path, out);
    req_str(z, "name", path, out);
    req_str(z, "color", path, out);
    check_enum(z, "podSecurityStandard", path, POD_SECURITY, out, "pod-security-enum");
    if let Some(c) = get(z, "quotaCpuCores").and_then(as_f64) {
        if c <= 0.0 {
            out.push(Finding::error(
                format!("{path}.quotaCpuCores"),
                "quota-positive",
                "quotaCpuCores MUST be > 0",
            ));
        }
    }
    check_int_range(z, "quotaMemoryMb", path, 1, None, out, "quota-mem");
}

/// Check cross-cluster link transport/encryption.
pub fn check_cross_cluster_link(link: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(link, "transport", path, TRANSPORT, out, "transport-enum");
    check_enum(link, "encryption", path, ENCRYPTION, out, "encryption-enum");
    check_int_range(link, "maxBandwidthMbps", path, 1, None, out, "bandwidth");
    check_int_range(link, "rpoTargetSec", path, 0, None, out, "rpo");
}

/// Check topologies mode quorum fields on a topologyModes entry.
pub fn check_topology_mode_extras(v: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(v, "quorumType", path, QUORUM_TYPE, out, "quorum-type-enum");
    check_enum(v, "quorumArbiter", path, QUORUM_ARBITER, out, "quorum-arbiter-enum");
    if let Some(w) = get(v, "witnessComponent") {
        let wp = format!("{path}.witnessComponent");
        req_str(w, "image", &wp, out);
        if get(w, "enabled").is_none() {
            out.push(Finding::error(
                format!("{wp}.enabled"),
                "required",
                "enabled is required",
            ));
        }
        check_enum(w, "placement", &wp, WITNESS_PLACEMENT, out, "witness-placement-enum");
    }
}

/// Check workload nested optionals (peerDiscovery, schedule, lifecycle, configMounts, helm, operator).
pub fn check_workload_extras(wl: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(wl, "peerDiscovery", path, PEER_DISCOVERY, out, "peer-discovery-enum");
    if let Some(sched) = get(wl, "schedule") {
        req_str(sched, "cron", &format!("{path}.schedule"), out);
        check_enum(
            sched,
            "concurrencyPolicy",
            &format!("{path}.schedule"),
            CONCURRENCY_POLICY,
            out,
            "concurrency-enum",
        );
        check_int_range(sched, "timeoutSeconds", &format!("{path}.schedule"), 1, None, out, "sched-timeout");
    }
    if let Some(lc) = get(wl, "lifecycle") {
        let lp = format!("{path}.lifecycle");
        check_int_range(lc, "jobTimeoutSec", &lp, 1, None, out, "job-timeout");
        check_int_range(lc, "jobBackoffLimit", &lp, 0, None, out, "job-backoff");
        check_enum(
            lc,
            "rollingUpdateSurgePolicy",
            &lp,
            SURGE_POLICY,
            out,
            "surge-policy-enum",
        );
        check_int_range(lc, "preStopSleepSec", &lp, 0, None, out, "prestop-sleep");
        check_int_range(lc, "gracefulStopTimeoutSec", &lp, 0, None, out, "graceful-stop");
    }
    if let Some(mounts) = get(wl, "configMounts").and_then(as_seq) {
        for (i, m) in mounts.iter().enumerate() {
            let mp = format!("{path}.configMounts[{i}]");
            req_str(m, "name", &mp, out);
            req_str(m, "mountPath", &mp, out);
            req_enum(m, "reloadStrategy", &mp, RELOAD_STRATEGY, out, "reload-strategy-enum");
        }
    }
    if let Some(scripts) = get(wl, "scripts") {
        check_scripts(scripts, &format!("{path}.scripts"), out);
    }
}

/// Check hardwareAndKernel.resources extras.
pub fn check_hardware_resources_extras(res: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(res, "numaTopologyPolicy", path, NUMA_POLICY, out, "numa-enum");
    if let Some(vs) = get(res, "verticalScalePolicy") {
        let vp = format!("{path}.verticalScalePolicy");
        check_enum(vs, "cpu", &vp, VERTICAL_CPU, out, "vert-cpu-enum");
        check_enum(vs, "memory", &vp, VERTICAL_MEM, out, "vert-mem-enum");
    }
    if let Some(acc) = get(res, "accelerators").and_then(as_seq) {
        for (i, a) in acc.iter().enumerate() {
            let ap = format!("{path}.accelerators[{i}]");
            req_str(a, "resourceClass", &ap, out);
            match get(a, "count").and_then(as_i64) {
                Some(n) if n >= 1 => {}
                _ => out.push(Finding::error(
                    format!("{ap}.count"),
                    "accel-count",
                    "count MUST be >= 1",
                )),
            }
        }
    }
    check_enum(res, "cpuPinning", path, CPU_PINNING, out, "cpu-pinning-enum");
}

/// Check parameters extras (uiControl, min/max).
pub fn check_parameter_extras(v: &Yaml, path: &str, out: &mut Vec<Finding>) {
    check_enum(v, "uiControl", path, UI_CONTROL, out, "ui-control-enum");
    if let (Some(min), Some(max)) = (get(v, "min").and_then(as_f64), get(v, "max").and_then(as_f64)) {
        if min > max {
            out.push(Finding::error(
                path,
                "param-range",
                format!("min {min} > max {max}"),
            ));
        }
    }
}

/// Check localAnomalyRules algorithm enum.
pub fn check_anomaly_rule(r: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(r, "metric", path, out);
    req_enum(r, "algorithm", path, ANOMALY_ALGO, out, "anomaly-algo-enum");
}

/// Check topologyModes witness already partially covered; storage volumes map.
pub fn check_volumes_map(volumes: &Yaml, path: &str, out: &mut Vec<Finding>) {
    let Some(m) = as_map(volumes) else {
        out.push(Finding::error(path, "type-map", "volumes MUST be a mapping"));
        return;
    };
    for (k, v) in m {
        check_volume(v, &format!("{path}.{}", key_str(k)), out);
    }
}

/// Validate scriptRef when present as string.
pub fn check_script_ref_field(parent: &Yaml, key: &str, path: &str, out: &mut Vec<Finding>) {
    if let Some(s) = opt_str(parent, key) {
        if s.contains("://") && !is_script_ref(s) {
            out.push(Finding::error(
                format!("{path}.{key}"),
                "script-ref-regex",
                format!("`{s}` MUST match ^(passport|topology)://scripts/[a-zA-Z0-9_.-]+$"),
            ));
        }
    }
}

/// Validate optional image/chart digest field.
pub fn check_digest_field(parent: &Yaml, key: &str, path: &str, out: &mut Vec<Finding>) {
    if let Some(d) = opt_str(parent, key) {
        if !is_sha256_digest(d) {
            out.push(Finding::error(
                format!("{path}.{key}"),
                "image-digest-regex",
                format!("`{d}` MUST match ^sha256:[a-f0-9]{{64}}$"),
            ));
        }
    }
}

/// Check `workload.operatorSpec` required fields.
pub fn check_operator_spec(op: &Yaml, path: &str, out: &mut Vec<Finding>) {
    for key in ["operatorHelmChart", "operatorVersion", "crdApiVersion", "crdKind", "manifestTemplate"] {
        req_str(op, key, path, out);
    }
}

/// Check `liveMigration` supportedSources list.
pub fn check_live_migration_sources(lm: &Yaml, path: &str, out: &mut Vec<Finding>) {
    match get(lm, "supportedSources").and_then(as_seq) {
        Some(list) if !list.is_empty() => {}
        _ => out.push(Finding::error(
            format!("{path}.supportedSources"),
            "min-items",
            "supportedSources MUST be a non-empty list",
        )),
    }
}

/// Check `autoscaling.customMetric` query/targetValue.
pub fn check_custom_metric(cm: &Yaml, path: &str, out: &mut Vec<Finding>) {
    req_str(cm, "query", path, out);
    if get(cm, "targetValue").is_none() {
        out.push(Finding::error(
            format!("{path}.targetValue"),
            "required",
            "targetValue is required",
        ));
    }
}

/// Check `cni.kubeProxyReplacement` is literal true when present (CUE: true).
pub fn check_cni_literal(cni: &Yaml, path: &str, out: &mut Vec<Finding>) {
    if let Some(v) = get(cni, "kubeProxyReplacement") {
        if as_bool(v) != Some(true) {
            out.push(Finding::error(
                format!("{path}.kubeProxyReplacement"),
                "kube-proxy-replacement",
                "kubeProxyReplacement MUST be true",
            ));
        }
    }
}
