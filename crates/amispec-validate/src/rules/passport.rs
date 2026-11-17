//! ComponentPassport structural rules (mirrors CUE `#ComponentPassport`).

use super::deep;
use crate::patterns::{is_accent_color, is_sha256_digest};
use crate::report::Finding;
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
const QUICK_CONTROLS: &[&str] = &["select", "slider", "toggle", "number"];
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
const APPLY_IMPACTS: &[&str] = &[
    "pod-restart",
    "hot-reload",
    "rolling-switchover",
    "immutable",
];
const FORMULA_IMPACTS: &[&str] = &["hot-reload", "rolling-switchover", "pod-restart"];
const FORMULA_UNITS: &[&str] = &["MB", "GB", "bytes", "count", "string"];
const PROBE_TYPES: &[&str] = &["http", "tcp", "grpc", "exec"];
const PROBE_SCHEMES: &[&str] = &["HTTP", "HTTPS"];
const EGRESS_MODES: &[&str] = &[
    "graph-only",
    "allow-public-internet",
    "allow-fqdn-whitelist",
];
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
/// GR-IMG-002: registry allowlist — `(host, namespace-prefix)`; `None` allows
/// any namespace on the host. Entries live in the golden requirements doc and
/// are extended only by decision. The T1 preference ladder (canonical upstream
/// over vendor repacks) is a catalog-CI review policy on top of this.
pub const IMAGE_ALLOWLIST: &[(&str, Option<&str>)] = &[
    ("docker.io", Some("library")),
    ("docker.io", Some("nginxinc")),
    ("docker.io", Some("clickhouse")),
    ("registry.k8s.io", None),
    ("ghcr.io", Some("cloudnative-pg")),
    ("ghcr.io", Some("altinity")),
    ("quay.io", Some("clickhouse")),
];

/// GR-META-005: platform-reserved slugs (never claimable); `amiterra` is
/// reserved FOR the operator and therefore allowed in content.
pub const RESERVED_PLATFORM_SLUGS: &[&str] = &[
    "official", "library", "system", "test", "kubernetes", "kube", "docker", "aws", "amazon",
    "google",
];

/// GR-META-005: true when the slug is a platform-reserved word.
pub fn is_reserved_slug(s: &str) -> bool {
    RESERVED_PLATFORM_SLUGS.contains(&s)
}

/// GR-IMG-002: true when `image` (canonical ref with host) is allowlisted.
pub fn image_registry_allowed(image: &str) -> bool {
    let (host, rest) = match image.split_once('/') {
        Some((h, r)) => (h, r),
        None => return false, // bare refs are not canonical (GR-IMG-001)
    };
    let ns = rest.split('/').next().unwrap_or("");
    IMAGE_ALLOWLIST.iter().any(|(h, n)| {
        *h == host && match n {
            Some(prefix) => ns == *prefix,
            None => true,
        }
    })
}

const BACKUP_MODES: &[&str] = &[
    "operator-managed",
    "sidecar-stream",
    "volume-snapshot-job",
    "custom-job",
];
const DAY2_CATEGORIES: &[&str] = &["first-aid", "maintenance", "migration-cutover", "scaling"];
const EXEC_TYPES: &[&str] = &["gitops-patch", "k8s-job", "operator-annotation"];

/// GR-META-011: SPDX license id or expression (ids with OR/AND/WITH).
fn is_spdx_license(s: &str) -> bool {
    let id = |x: &str| {
        !x.is_empty()
            && x.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | '(' | ')'))
    };
    let mut expect_id = true;
    for tok in s.split_whitespace() {
        if expect_id {
            if !id(tok) {
                return false;
            }
            expect_id = false;
        } else if matches!(tok, "OR" | "AND" | "WITH") {
            expect_id = true;
        } else {
            return false;
        }
    }
    !expect_id
}

/// GR-META-002 slug for `publisher`/`id`: ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$
fn is_meta_slug(s: &str) -> bool {
    let mut chars = s.chars();
    let (Some(first), Some(last)) = (chars.next(), s.chars().last()) else {
        return false;
    };
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    edge(first)
        && edge(last)
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// GR-META-003: id must not end with a version-like suffix (`postgresql-17`).
fn id_has_version_suffix(id: &str) -> bool {
    match id.rsplit_once('-') {
        Some((_, tail)) => {
            !tail.is_empty()
                && tail.starts_with(|c: char| c.is_ascii_digit())
                && tail.chars().all(|c| c.is_ascii_digit() || c == '.')
        }
        None => false,
    }
}

/// GR-VER-002 version format: 2-4 numeric segments + optional `-suffix`.
fn is_version_format(s: &str) -> bool {
    let (core, suffix) = match s.split_once('-') {
        Some((c, rest)) => (c, Some(rest)),
        None => (s, None),
    };
    let segs: Vec<&str> = core.split('.').collect();
    if !(2..=4).contains(&segs.len()) {
        return false;
    }
    if !segs
        .iter()
        .all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    match suffix {
        None => true,
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
    }
}

/// Leading version core `v?N(.N){1,3}` of a tag/version string (GR-VER-002).
fn tag_version_core(s: &str) -> Option<String> {
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

/// Image tag from an `image` ref (part after the last `:` of the last path
/// segment); `None` when the ref carries no tag.
fn image_tag(image: &str) -> Option<&str> {
    let last = image.rsplit('/').next()?;
    match last.rsplit_once(':') {
        Some((_, tag)) if !tag.is_empty() => Some(tag),
        _ => None,
    }
}

/// Shared display-text rules for human-facing fields (GR-META-007/008):
/// length, single line, trimmed, no control chars, no bidi overrides.
fn check_display_text(path: &str, key: &str, value: &str, max_chars: usize, out: &mut Vec<Finding>) {
    if value.chars().count() > max_chars {
        out.push(Finding::error(
            path,
            format!("{key}-length"),
            format!("{key} is {} chars, MUST be <= {max_chars}", value.chars().count()),
        ));
    }
    if value.contains('\n') || value.contains('\r') {
        out.push(Finding::error(
            path,
            format!("{key}-single-line"),
            format!("{key} MUST be a single line"),
        ));
    }
    if value != value.trim() {
        out.push(Finding::error(
            path,
            format!("{key}-trimmed"),
            format!("{key} MUST NOT have leading/trailing whitespace"),
        ));
    }
    if value.chars().any(|c| c.is_control()) {
        out.push(Finding::error(
            path,
            format!("{key}-control-chars"),
            format!("{key} MUST NOT contain control characters"),
        ));
    }
    if value
        .chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    {
        out.push(Finding::error(
            path,
            format!("{key}-bidi"),
            format!("{key} MUST NOT contain bidi override characters"),
        ));
    }
}

pub fn check(root: &Map, out: &mut Vec<Finding>) {
    // --- metadata ---
    let Some(meta) = root.get("metadata") else {
        out.push(Finding::error(
            "metadata",
            "required",
            "metadata is required",
        ));
        return;
    };
    if as_map(meta).is_none() {
        out.push(Finding::error(
            "metadata",
            "type-map",
            "metadata MUST be a mapping",
        ));
        return;
    }

    // --- identity: publisher/id (GR-META-001/002) ---
    if let Some(publisher) = req_str(meta, "publisher", "metadata", out) {
        if !is_meta_slug(&publisher) {
            out.push(Finding::error(
                "metadata.publisher",
                "publisher-regex",
                format!(
                    "publisher `{publisher}` MUST match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ (GR-META-002)"
                ),
            ));
        }
        if publisher.chars().count() > 32 {
            out.push(Finding::error(
                "metadata.publisher",
                "publisher-length",
                format!("publisher is {} chars, MUST be <= 32", publisher.chars().count()),
            ));
        }
        if is_reserved_slug(&publisher) {
            out.push(Finding::error(
                "metadata.publisher",
                "publisher-registry-reserved",
                format!("publisher `{publisher}` is a reserved platform slug (GR-META-005)"),
            ));
        }
    }
    if let Some(id) = req_str(meta, "id", "metadata", out) {
        if !is_meta_slug(&id) {
            out.push(Finding::error(
                "metadata.id",
                "id-regex",
                format!("id `{id}` MUST match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ (GR-META-002)"),
            ));
        }
        if id.chars().count() > 40 {
            out.push(Finding::error(
                "metadata.id",
                "id-length",
                format!("id is {} chars, MUST be <= 40", id.chars().count()),
            ));
        }
        if is_reserved_slug(&id) {
            out.push(Finding::error(
                "metadata.id",
                "id-registry-reserved",
                format!("id `{id}` is a reserved platform slug (GR-META-005)"),
            ));
        }
        // GR-META-003: version in the id is forbidden (`postgresql-17`).
        if id_has_version_suffix(&id) {
            out.push(Finding::error(
                "metadata.id",
                "id-version-suffix",
                format!("id `{id}` MUST NOT embed a version suffix (GR-META-003)"),
            ));
        }
    }
    req_str(meta, "title", "metadata", out);
    if let Some(title) = get(meta, "title").and_then(as_str) {
        check_display_text("metadata.title", "title", title, 80, out);
    }
    req_str(meta, "description", "metadata", out);
    if let Some(desc) = get(meta, "description").and_then(as_str) {
        check_display_text("metadata.description", "description", desc, 300, out);
    }

    // --- version (GR-VER-001/002/004) ---
    let archetype = get(meta, "archetype").and_then(as_str).unwrap_or("");
    let image = root
        .get("workload")
        .and_then(as_map)
        .and_then(|w| w.get("container"))
        .and_then(as_map)
        .and_then(|c| c.get("image"))
        .and_then(as_str);
    let tag_core = image
        .and_then(image_tag)
        .and_then(tag_version_core);
    match get(meta, "version").and_then(as_str) {
        Some(version) => {
            if !is_version_format(version) {
                out.push(Finding::error(
                    "metadata.version",
                    "version-format",
                    format!(
                        "version `{version}` MUST match ^[0-9]+(\\.[0-9]+){{1,3}}(-[A-Za-z0-9.-]+)?$ (GR-VER-002)"
                    ),
                ));
            }
            // GR-VER-001/004: an explicit version MUST match a version-ful
            // image tag core (operator-cluster versions name the managed
            // software — tag comparison does not apply there).
            if let Some(core) = &tag_core {
                if archetype != "operator-cluster" {
                    let vcore = version.split('-').next().unwrap_or(version);
                    if vcore != core.as_str() {
                        out.push(Finding::error(
                            "metadata.version",
                            "version-tag-mismatch",
                            format!(
                                "version `{version}` does not match image tag core `{core}` (GR-VER-004)"
                            ),
                        ));
                    }
                }
            }
        }
        None => {
            // GR-VER-001: version may be derived from a version-ful tag;
            // otherwise it MUST be explicit.
            if tag_core.is_none() {
                out.push(Finding::error(
                    "metadata.version",
                    "version-required",
                    "version MUST be explicit when the image tag is not version-ful (GR-VER-001)",
                ));
            }
        }
    }

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

    // GR-PIN-002: the label-safe pin MUST fit a 63-char label value.
    if let (Some(publisher), Some(id), Some(rev)) = (
        get(meta, "publisher").and_then(as_str),
        get(meta, "id").and_then(as_str),
        get(meta, "passportRev").and_then(as_i64),
    ) {
        let eff_version = get(meta, "version")
            .and_then(as_str)
            .map(str::to_string)
            .or_else(|| tag_core.clone());
        if let Some(version) = eff_version {
            let safe: String = version
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let pin = format!("{publisher}.{id}.{safe}-rev{rev}");
            if pin.len() > 63 {
                out.push(Finding::error(
                    "metadata",
                    "pin-budget",
                    format!(
                        "label-safe pin `{pin}` is {} chars, MUST be <= 63 (GR-PIN-002)",
                        pin.len()
                    ),
                ));
            }
        }
    }

    req_enum(
        meta,
        "category",
        "metadata",
        CATEGORIES,
        out,
        "category-enum",
    );
    req_enum(
        meta,
        "archetype",
        "metadata",
        ARCHETYPES,
        out,
        "archetype-enum",
    );

    // distribution
    if let Some(dist) = get(meta, "distribution") {
        check_enum(
            dist,
            "tier",
            "metadata.distribution",
            TIERS,
            out,
            "tier-enum",
        );
        if let Some(lic) = opt_str(dist, "license") {
            if lic.is_empty() {
                out.push(Finding::error(
                    "metadata.distribution.license",
                    "required",
                    "license MUST be non-empty",
                ));
            } else if !is_spdx_license(lic) {
                out.push(Finding::error(
                    "metadata.distribution.license",
                    "license-spdx",
                    format!(
                        "license `{lic}` MUST be an SPDX id or expression                          (ids combined with OR/AND/WITH)"
                    ),
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
        if let Some(icon) = req_str(ui, "icon", "metadata.canvasUI", out) {
            if !is_meta_slug(&icon) {
                out.push(Finding::error(
                    "metadata.canvasUI.icon",
                    "icon-format",
                    format!(
                        "icon `{icon}` MUST be a kebab slug (the console icon set is                          keyed by slug)"
                    ),
                ));
            }
        }
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
        req_enum(
            ui,
            "nodeShape",
            "metadata.canvasUI",
            NODE_SHAPES,
            out,
            "node-shape-enum",
        );
        if let Some(qs) = get(ui, "quickControls").and_then(as_seq) {
            for (i, q) in qs.iter().enumerate() {
                let qpath = format!("metadata.canvasUI.quickControls[{i}]");
                req_str(q, "field", &qpath, out);
                req_str(q, "label", &qpath, out);
                req_enum(
                    q,
                    "control",
                    &qpath,
                    QUICK_CONTROLS,
                    out,
                    "quick-control-enum",
                );
            }
        }
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
            req_enum(
                v,
                "applyImpact",
                &ppath,
                APPLY_IMPACTS,
                out,
                "apply-impact-enum",
            );
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
                req_enum(
                    v,
                    "scaleDownPolicy",
                    &mpath,
                    SCALE_DOWN,
                    out,
                    "scale-down-enum",
                );
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
        // GR-IMG-001 / GR-VER-004: image + digest pair; chart-based workloads
        // (flux-helm-release) carry helmSpec instead of a container image.
        let engine = get(wl, "engine").and_then(as_str).unwrap_or("");
        // GR-META-010: archetype and engine must tell the same story.
        let arch = get(meta, "archetype").and_then(as_str).unwrap_or("");
        let mismatch = (arch == "operator-cluster" && engine != "operator-crd")
            || (arch == "scheduled-job" && engine != "k8s-cronjob");
        if mismatch {
            out.push(Finding::error(
                "workload.engine",
                "archetype-engine-mismatch",
                format!(
                    "archetype `{arch}` requires a matching engine (operator-cluster →                      operator-crd, scheduled-job → k8s-cronjob), got `{engine}` (GR-META-010)"
                ),
            ));
        }
        if arch == "stateful-service"
            && !matches!(engine, "k8s-statefulset" | "operator-crd" | "flux-helm-release")
        {
            out.push(Finding::warning(
                "workload.engine",
                "archetype-engine-advisory",
                format!(
                    "stateful-service on engine `{engine}` is unusual — expected \
                     k8s-statefulset / operator-crd / flux-helm-release (GR-META-010)"
                ),
            ));
        }
        match get(wl, "container") {
            Some(c) => {
                if let Some(img) = req_str(c, "image", "workload.container", out) {
                    if !image_registry_allowed(&img) {
                        out.push(Finding::error(
                            "workload.container.image",
                            "image-registry-not-allowed",
                            format!("image `{img}` is outside the GR-IMG-002 allowlist"),
                        ));
                    }
                }
                if let Some(d) = req_str(c, "imageDigest", "workload.container", out) {
                    if !is_sha256_digest(&d) {
                        out.push(Finding::error(
                            "workload.container.imageDigest",
                            "image-digest-regex",
                            format!("`{d}` MUST match ^sha256:[a-f0-9]{{64}}$"),
                        ));
                    }
                }
            }
            // Chart- and operator-template based workloads carry their product
            // outside workload.container (chart values / CR template).
            None if matches!(engine, "flux-helm-release" | "operator-crd") => {}
            None => out.push(Finding::error(
                "workload.container",
                "image-required",
                "workload.container (image + imageDigest) is required (GR-IMG-001)",
            )),
        }
        if let Some(probes) = get(wl, "probes").and_then(as_map) {
            for (k, p) in probes {
                let ppath = format!("workload.probes.{}", key_str(k));
                check_enum(p, "type", &ppath, PROBE_TYPES, out, "probe-type-enum");
                check_enum(p, "scheme", &ppath, PROBE_SCHEMES, out, "probe-scheme-enum");
                check_int_range(
                    p,
                    "failureThreshold",
                    &ppath,
                    1,
                    None,
                    out,
                    "probe-threshold",
                );
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
                req_enum(
                    f,
                    "applyImpact",
                    &fpath,
                    FORMULA_IMPACTS,
                    out,
                    "formula-impact-enum",
                );
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
        out.push(Finding::error(
            "workload",
            "required",
            "workload is required",
        ));
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
                req_enum(
                    ep,
                    "role",
                    &epath,
                    ENDPOINT_ROLES,
                    out,
                    "endpoint-role-enum",
                );
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
                    if let Some(sq) = get(cc, "sharedQuotaFormula").or_else(|| {
                        get(
                            get(cc, "sidecar").unwrap_or(&serde_yaml::Value::Null),
                            "sharedQuotaFormula",
                        )
                    }) {
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
                        check_int_range(
                            side,
                            "cpuMillicores",
                            &sp,
                            0,
                            Some(200),
                            out,
                            "sidecar-cpu",
                        );
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
                // GR-VER-003: version on a requirement is a comparator range.
                if let Some(range) = get(v, "version").and_then(as_str) {
                    if amispec_schema::parse_version_range(range).is_none() {
                        out.push(Finding::error(
                            format!("{rpath}.version"),
                            "version-range-format",
                            format!(
                                "range `{range}` MUST be comparators `= != > >= < <=`                                  AND-ed by spaces, or `*` (GR-VER-003)"
                            ),
                        ));
                    }
                }
                req_str(v, "capability", &rpath, out);
                req_enum(
                    v,
                    "dependencyStage",
                    &rpath,
                    DEP_STAGES,
                    out,
                    "dependency-stage-enum",
                );
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
        out.push(Finding::error(
            "interfaces",
            "required",
            "interfaces is required",
        ));
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
            check_enum(
                res,
                "cpuLimitPolicy",
                rpath,
                CPU_LIMIT_POLICY,
                out,
                "cpu-limit-enum",
            );
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
                req_enum(
                    a,
                    "category",
                    &apath,
                    DAY2_CATEGORIES,
                    out,
                    "day2-category-enum",
                );
                req_enum(
                    a,
                    "executionType",
                    &apath,
                    EXEC_TYPES,
                    out,
                    "day2-exec-enum",
                );
                // MVP: support-role ACL is out of scope (no support contour).
                check_int_range(a, "cooldownSeconds", &apath, 0, None, out, "cooldown");
                check_int_range(a, "ttlSecondsAfterFinished", &apath, 0, None, out, "ttl");
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
        out.push(Finding::error(
            "operations",
            "required",
            "operations is required",
        ));
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
                if let Some(img) = req_str(c, "image", &cp, out) {
                    if !image_registry_allowed(&img) {
                        out.push(Finding::error(
                            format!("{cp}.image"),
                            "image-registry-not-allowed",
                            format!("image `{img}` is outside the GR-IMG-002 allowlist"),
                        ));
                    }
                }
                req_str(c, "imageDigest", &cp, out); // GR-IMG-001
                deep::check_digest_field(c, "imageDigest", &cp, out);
                check_int_range(c, "memoryMb", &cp, 1, None, out, "companion-mem");
                match get(c, "cpuCores").and_then(as_f64) {
                    Some(x) if x > 0.0 => {}
                    _ => out.push(Finding::error(
                        format!("{cp}.cpuCores"),
                        "cpu-positive",
                        "cpuCores MUST be > 0",
                    )),
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
                    deep::check_gateway_tuning(
                        gt,
                        &format!("interfaces.endpoints[{i}].gatewayTuning"),
                        out,
                    );
                }
            }
        }
        if let Some(provides) = get(ifaces, "provides").and_then(as_seq) {
            for (i, slot) in provides.iter().enumerate() {
                let spath = format!("interfaces.provides[{i}]");
                if let Some(cc) = get(slot, "clientContract") {
                    if let Some(side) = get(cc, "sidecar") {
                        deep::check_sidecar_extra(
                            side,
                            &format!("{spath}.clientContract.sidecar"),
                            out,
                        );
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
                    deep::check_script_ref_field(
                        prov,
                        "scriptRef",
                        &format!("{spath}.provisioner"),
                        out,
                    );
                }
            }
        }
        if let Some(reqs) = get(ifaces, "requires").and_then(as_map) {
            for (k, v) in reqs {
                deep::check_script_ref_field(
                    v,
                    "mountAsFilesPath",
                    &format!("interfaces.requires.{}", key_str(k)),
                    out,
                );
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
                    deep::check_anomaly_rule(
                        r,
                        &format!("operations.observability.localAnomalyRules[{i}]"),
                        out,
                    );
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
                deep::check_script_ref_field(
                    a,
                    "scriptRef",
                    &format!("operations.day2Actions[{i}]"),
                    out,
                );
            }
        }
    }


    // --- credential processes (GR-CRED-001..005) ---
    if let Some(procs) = root.get("processes").and_then(as_map) {
        for (name, proc) in procs {
            let pname = key_str(name);
            let ppath = format!("processes.{pname}");
            let role = get(proc, "role").and_then(as_str).unwrap_or("runtime");
            if !matches!(role, "deploy" | "runtime") {
                out.push(Finding::error(
                    format!("{ppath}.role"),
                    "process-role-enum",
                    format!("role `{role}` MUST be deploy | runtime"),
                ));
            }
            match get(proc, "uses").and_then(as_seq) {
                Some(uses) if !uses.is_empty() => {
                    for (i, u) in uses.iter().enumerate() {
                        let upath = format!("{ppath}.uses[{i}]");
                        req_str(u, "slot", &upath, out);
                        match get(u, "grants").and_then(as_seq) {
                            Some(grants) if !grants.is_empty() => {
                                for (gi, g) in grants.iter().enumerate() {
                                    let gpath = format!("{upath}.grants[{gi}]");
                                    let mut verbs: Vec<String> = Vec::new();
                                    match get(g, "verbs").and_then(as_seq) {
                                        Some(vs) if !vs.is_empty() => {
                                            for v in vs {
                                                if let Some(v) = as_str(v) {
                                                    verbs.push(v.to_string());
                                                }
                                            }
                                        }
                                        _ => out.push(Finding::error(
                                            format!("{gpath}.verbs"),
                                            "grants-verbs-required",
                                            "grants.verbs MUST be a non-empty list",
                                        )),
                                    }
                                    match get(g, "resources").and_then(as_seq) {
                                        Some(rs) if !rs.is_empty() => {}
                                        _ => out.push(Finding::error(
                                            format!("{gpath}.resources"),
                                            "grants-resources-required",
                                            "grants.resources MUST be a non-empty list",
                                        )),
                                    }
                                    // GR-CRED-003: dangerous escalations are never granted.
                                    for v in &verbs {
                                        if matches!(
                                            v.to_ascii_lowercase().as_str(),
                                            "superuser" | "createrole" | "replication"
                                        ) {
                                            out.push(Finding::error(
                                                format!("{gpath}.verbs"),
                                                "dangerous-verb",
                                                format!("verb `{v}` MUST NOT be granted (GR-CRED-003)"),
                                            ));
                                        }
                                        // GR-CRED-003: `ddl` only in an explicitly deploy process.
                                        if v.eq_ignore_ascii_case("ddl") && role != "deploy" {
                                            out.push(Finding::error(
                                                format!("{gpath}.verbs"),
                                                "ddl-requires-deploy-role",
                                                format!(
                                                    "verb `ddl` in process `{pname}` requires role: deploy (GR-CRED-003)"
                                                ),
                                            ));
                                        }
                                    }
                                }
                            }
                            _ => out.push(Finding::error(
                                format!("{upath}.grants"),
                                "grants-required",
                                "uses[].grants MUST be a non-empty list",
                            )),
                        }
                    }
                }
                _ => out.push(Finding::error(
                    format!("{ppath}.uses"),
                    "uses-required",
                    "processes[].uses MUST be a non-empty list",
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Finding;

    fn meta_findings(meta_yaml: &str) -> Vec<Finding> {
        let raw = format!("metadata:\n{meta_yaml}");
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let mut out = Vec::new();
        check(doc.as_mapping().unwrap(), &mut out);
        out
    }

    const BASE: &str = "  publisher: test-org\n  id: demo\n  title: Demo App\n  description: Demo application fixture\n  version: \"1.0.0\"\n  passportRev: 1\n  category: application\n  archetype: stateless-app\n";

    #[test]
    fn title_rules_accept_plain_display() {
        let out = meta_findings(BASE);
        assert!(out.iter().all(|f| !f.rule.starts_with("title-")), "{out:?}");
    }

    #[test]
    fn title_rules_reject_length_line_ws_control_bidi() {
        let long_title = "x".repeat(81);
        let long_meta = format!("  publisher: test-org\n  id: demo\n  title: {long_title}\n");
        let long_desc_val = "y".repeat(301);
        let long_desc = format!("  publisher: test-org\n  id: demo\n  description: {long_desc_val}\n");
        let cases: Vec<(&str, &str)> = vec![
            (&long_meta, "title-length"),
            ("  publisher: test-org\n  id: demo\n  title: \"a\\nb\"\n", "title-single-line"),
            ("  publisher: test-org\n  id: demo\n  title: \" padded\"\n", "title-trimmed"),
            ("  publisher: test-org\n  id: demo\n  title: \"a\\u0007b\"\n", "title-control-chars"),
            ("  publisher: test-org\n  id: demo\n  title: \"a\\u202Eb\"\n", "title-bidi"),
            (&long_desc, "description-length"),
            ("  publisher: test-org\n  id: demo\n  description: \"a\\nb\"\n", "description-single-line"),
            ("  publisher: test-org\n  id: demo\n  description: \"x\\u202Ey\"\n", "description-bidi"),
        ];
        for (meta, rule) in cases {
            let raw = format!("metadata:\n{meta}  version: \"1.0.0\"\n  passportRev: 1\n  category: application\n  archetype: stateless-app\n");
            let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
            let mut out = Vec::new();
            check(doc.as_mapping().unwrap(), &mut out);
            assert!(
                out.iter().any(|f| f.rule == rule),
                "expected {rule} for {meta:?}, got {out:?}"
            );
        }
    }


    fn doc_findings(yaml: &str) -> Vec<Finding> {
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let mut out = Vec::new();
        check(doc.as_mapping().unwrap(), &mut out);
        out
    }

    fn meta_doc() -> String {
        "metadata:\n  publisher: test-org\n  id: demo\n  title: Demo\n  description: Demo app\n  version: \"1.0.0\"\n  passportRev: 1\n  category: application\n  archetype: stateless-app\n".to_string()
    }

    fn patched(pairs: &[(&str, &str)]) -> String {
        let mut s = meta_doc();
        for (from, to) in pairs {
            assert!(s.contains(from), "patch source missing: {from:?}");
            s = s.replace(from, to);
        }
        s
    }

    #[test]
    fn publisher_and_id_follow_meta_slug_grammar() {
        for (from, to, rule) in [
            ("publisher: test-org", "publisher: -org", "publisher-regex"),
            ("id: demo", "id: has_underscore", "id-regex"),
            ("id: demo", "id: -lead", "id-regex"),
            ("id: demo", "id: Upper", "id-regex"),
            ("publisher: test-org", "publisher: org-", "publisher-regex"),
        ] {
            let out = doc_findings(&patched(&[(from, to)]));
            assert!(out.iter().any(|f| f.rule == rule), "expected {rule} for {from:?}->{to:?}, got {out:?}");
        }
    }

    #[test]
    fn id_lengths_and_version_suffix_are_enforced() {
        let out = doc_findings(&patched(&[("id: demo", &format!("id: {}", "a".repeat(41)))]));
        assert!(out.iter().any(|f| f.rule == "id-length"), "{out:?}");
        let out = doc_findings(&patched(&[("publisher: test-org", &format!("publisher: {}", "b".repeat(33)))]));
        assert!(out.iter().any(|f| f.rule == "publisher-length"), "{out:?}");
        let out = doc_findings(&patched(&[("id: demo", "id: postgresql-17")]));
        assert!(out.iter().any(|f| f.rule == "id-version-suffix"), "{out:?}");
    }

    #[test]
    fn version_format_and_derivation_rules() {
        for v in ["1", "17.0.0.0.0", "v17.0", "1.2.3+build"] {
            let out = doc_findings(&patched(&[("version: \"1.0.0\"", &format!("version: \"{v}\""))]));
            assert!(out.iter().any(|f| f.rule == "version-format"), "expected version-format for {v}, got {out:?}");
        }
        for v in ["17.11", "24.3.1.2672", "1.2.3-rc.1"] {
            let out = doc_findings(&patched(&[("version: \"1.0.0\"", &format!("version: \"{v}\""))]));
            assert!(!out.iter().any(|f| f.rule == "version-format"), "unexpected version-format for {v}: {out:?}");
        }
        // explicit version MUST match a version-ful image tag core (GR-VER-004)
        let base = patched(&[("version: \"1.0.0\"", "version: \"18.0.0\"")]);
        let yaml = format!("{base}workload:\n  container:\n    image: docker.io/library/postgres:17.11-alpine\n");
        let out = doc_findings(&yaml);
        assert!(out.iter().any(|f| f.rule == "version-tag-mismatch"), "{out:?}");
        // operator-cluster is exempt (managed software version)
        let out = doc_findings(&yaml.replace("archetype: stateless-app", "archetype: operator-cluster"));
        assert!(!out.iter().any(|f| f.rule == "version-tag-mismatch"), "{out:?}");
        // match passes
        let yaml = format!("{}workload:\n  container:\n    image: docker.io/library/postgres:17.11-alpine\n", patched(&[("version: \"1.0.0\"", "version: \"17.11\"")]));
        let out = doc_findings(&yaml);
        assert!(!out.iter().any(|f| f.rule == "version-tag-mismatch"), "{out:?}");
    }

    #[test]
    fn version_derivable_from_tag_or_required() {
        // absent version + version-ful tag: derived, no version errors
        let yaml = patched(&[("  version: \"1.0.0\"\n", "")]);
        let yaml = format!("{yaml}workload:\n  container:\n    image: docker.io/library/postgres:17.11-alpine\n");
        let out = doc_findings(&yaml);
        assert!(!out.iter().any(|f| f.rule.starts_with("version-")), "{out:?}");
        // absent version + non-version-ful tag: explicit required
        let out = doc_findings(&yaml.replace("postgres:17.11-alpine", "postgres:alpine"));
        assert!(out.iter().any(|f| f.rule == "version-required"), "{out:?}");
    }

    #[test]
    fn pin_budget_is_enforced() {
        let yaml = patched(&[
            ("publisher: test-org", &format!("publisher: {}", "p".repeat(32))),
            ("id: demo", &format!("id: {}", "i".repeat(40))),
        ]);
        let out = doc_findings(&yaml);
        assert!(out.iter().any(|f| f.rule == "pin-budget"), "{out:?}");
        let out = doc_findings(&meta_doc());
        assert!(!out.iter().any(|f| f.rule == "pin-budget"), "{out:?}");
    }


    #[test]
    fn image_allowlist_rejects_unknown_registries() {
        let good = format!(
            "{}workload:\n  container:\n    image: 'docker.io/library/busybox:stable'\n    imageDigest: 'sha256:{}'\n",
            meta_doc(),
            "a".repeat(64)
        );
        let out = doc_findings(&good);
        assert!(!out.iter().any(|f| f.rule == "image-registry-not-allowed"), "{out:?}");
        let bad = good.replace("docker.io/library/busybox:stable", "evil.example/app:1.0.0");
        let out = doc_findings(&bad);
        assert!(out.iter().any(|f| f.rule == "image-registry-not-allowed"), "{out:?}");
    }

    #[test]
    fn quorum_profiles_need_odd_votes_at_least_three() {
        let ok = format!(
            "{}topologyModes:\n  degraded-ha:\n    description: d\n    minNodes: 3\n    replicas: 2\n    quorumType: witness-assisted\n    witnessComponent: {{ enabled: true, image: 'docker.io/library/busybox:stable', replicas: 1, placement: control-plane-or-third-fault-domain }}\n",
            meta_doc()
        );
        let out = doc_findings(&ok);
        assert!(!out.iter().any(|f| f.rule == "quorum-votes"), "{out:?}");
        let bad = ok.replace("witnessComponent: { enabled: true", "witnessComponent: { enabled: false");
        let out = doc_findings(&bad);
        assert!(out.iter().any(|f| f.rule == "quorum-votes"), "{out:?}");
    }


    #[test]
    fn requires_version_range_format_is_checked() {
        let yaml = patched(&[("archetype: stateless-app", "archetype: stateless-app")])
            + "interfaces:\n  egressDefaultMode: graph-only\n  endpoints: []\n  provides: []\n  requires:\n    database: { capability: postgres-sql, version: \">=16.0 <18.0\" }\n";
        let out = doc_findings(&yaml);
        assert!(!out.iter().any(|f| f.rule == "version-range-format"), "{out:?}");
        let bad = yaml.replace("\">=16.0 <18.0\"", "\">=bogus\"");
        let out = doc_findings(&bad);
        assert!(out.iter().any(|f| f.rule == "version-range-format"), "{out:?}");
    }

    #[test]
    fn reserved_platform_slugs_are_rejected() {
        let out = doc_findings(&patched(&[("publisher: test-org", "publisher: google")]));
        assert!(out.iter().any(|f| f.rule == "publisher-registry-reserved"), "{out:?}");
        let out = doc_findings(&patched(&[("id: demo", "id: kubernetes")]));
        assert!(out.iter().any(|f| f.rule == "id-registry-reserved"), "{out:?}");
        // operator-owned slug is fine
        let out = doc_findings(&patched(&[("publisher: test-org", "publisher: amiterra")]));
        assert!(!out.iter().any(|f| f.rule.contains("reserved")), "{out:?}");
    }


    #[test]
    fn license_must_be_spdx() {
        for (lic, expected) in [
            ("Apache-2.0", true),
            ("MIT OR Apache-2.0", true),
            ("GPL-2.0-only WITH Classpath-exception-2.0", true),
            ("do what you want", false),
            ("Apache-2.0 OR", false),
        ] {
            let yaml = patched(&[(
                "  archetype: stateless-app",
                &format!("  archetype: stateless-app\n  distribution: {{ tier: open-core, license: \"{lic}\" }}\n  canvasUI: {{ icon: web, accentColor: \"#2563EB\", nodeShape: standard-card }}"),
            )]);
            let out = doc_findings(&yaml);
            let bad = out.iter().any(|f| f.rule == "license-spdx");
            assert_eq!(!bad, expected, "license {lic:?}: {out:?}");
        }
    }

    #[test]
    fn icon_slug_and_quick_controls() {
        let extra = "  distribution: { tier: open-core, license: \"Apache-2.0\" }\n  canvasUI: { icon: web, accentColor: \"#2563EB\", nodeShape: standard-card, quickControls: [{ field: replicas, label: Replicas, control: slider }] }";
        let base = patched(&[("  archetype: stateless-app", &format!("  archetype: stateless-app\n{extra}"))]);
        let out = doc_findings(&base);
        assert!(
            !out.iter().any(|f| f.rule.starts_with("icon-") || f.rule.starts_with("quick-")),
            "{out:?}"
        );
        let bad = base.replace("icon: web", "icon: Web Icon");
        let out = doc_findings(&bad);
        assert!(out.iter().any(|f| f.rule == "icon-format"), "{out:?}");
        let bad = base.replace("control: slider", "control: dropdown");
        let out = doc_findings(&bad);
        assert!(out.iter().any(|f| f.rule == "quick-control-enum"), "{out:?}");
    }

    #[test]
    fn archetype_and_engine_must_agree() {
        let make = |arch: &str, engine: &str| -> String {
            let yaml = patched(&[(
                "  archetype: stateless-app",
                &format!("  archetype: {arch}"),
            )]);
            format!("{yaml}workload:\n  engine: {engine}\n")
        };
        let out = doc_findings(&make("operator-cluster", "k8s-statefulset"));
        assert!(out.iter().any(|f| f.rule == "archetype-engine-mismatch"), "{out:?}");
        let out = doc_findings(&make("scheduled-job", "k8s-deployment"));
        assert!(out.iter().any(|f| f.rule == "archetype-engine-mismatch"), "{out:?}");
        let out = doc_findings(&make("operator-cluster", "operator-crd"));
        assert!(!out.iter().any(|f| f.rule == "archetype-engine-mismatch"), "{out:?}");
        let out = doc_findings(&make("stateful-service", "k8s-deployment"));
        assert!(out.iter().any(|f| f.rule == "archetype-engine-advisory"), "{out:?}");
    }

    #[test]
    fn title_is_required() {
        let out = meta_findings("  publisher: test-org\n  id: demo\n  version: \"1.0.0\"\n  passportRev: 1\n  category: application\n  archetype: stateless-app\n");
        assert!(out.iter().any(|f| f.rule == "required"), "{out:?}");
    }
}
