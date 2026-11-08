//! Provenance labels written on generated manifests (AmiSpec §Provenance).
//!
//! These labels make compilation reversible: `decompile` reconstructs
//! `TopologyBlueprint` from a FluxCD tree without loss.

/// Instance identifier (`id` in topology).
pub const LABEL_COMPONENT_ID: &str = "amispec.io/component-id";
/// `id@version-rev` of the passport used for this object.
pub const LABEL_PASSPORT: &str = "amispec.io/passport";
/// Security zone / K8s namespace group.
pub const LABEL_ZONE: &str = "amispec.io/zone";
/// Comma-separated injected sidecar names (KEP-753).
pub const LABEL_INJECTED_SIDECARS: &str = "amispec.io/injected-sidecars";
/// Binding edge provenance: `from->to:slot`.
pub const LABEL_BINDING_EDGE: &str = "amispec.io/binding-edge";
/// JSON delta of user-level values (config / topology / resources / storage).
pub const LABEL_USER_SPEC_DELTA: &str = "amispec.io/user-spec-delta";
/// Cluster id that produced this object.
pub const LABEL_CLUSTER_ID: &str = "amispec.io/cluster-id";
/// Node tuning profile hash label (`tuned.amispec.io/<hash>: ready` is separate).
pub const LABEL_NODE_ID: &str = "amispec.io/node-id";
/// Stage directory name (01-node-tuning, …).
pub const LABEL_STAGE: &str = "amispec.io/stage";

// --- exposure / balancer provenance (Design Doc 0025 §2.2) ---

/// Marker on the cluster-scoped Cilium activation (`HelmChartConfig`).
pub const LABEL_EXPOSURE: &str = "amispec.io/exposure";
/// `loadBalancers[].id` that produced this object.
pub const LABEL_LB_ID: &str = "amispec.io/lb-id";
/// `loadBalancers[].layer`.
pub const LABEL_LB_LAYER: &str = "amispec.io/lb-layer";
/// `loadBalancers[].provider`.
pub const LABEL_LB_PROVIDER: &str = "amispec.io/lb-provider";
/// `loadBalancers[].tls` as authored.
pub const LABEL_LB_TLS: &str = "amispec.io/tls";
/// Concrete tls mode after `letsencrypt-auto` resolution.
pub const LABEL_TLS_MODE_RESOLVED: &str = "amispec.io/tls-mode-resolved";
/// `loadBalancers[].upstreamEdge`.
pub const LABEL_UPSTREAM_EDGE: &str = "amispec.io/upstream-edge";
/// `loadBalancers[].trustedProxySource` (JSON string-or-list).
pub const LABEL_TRUSTED_PROXY_SOURCE: &str = "amispec.io/trusted-proxy-source";
/// `loadBalancers[].forwardingMode`.
pub const LABEL_FORWARDING_MODE: &str = "amispec.io/forwarding-mode";
/// `loadBalancers[].floatingIpRef`.
pub const LABEL_FLOATING_IP_REF: &str = "amispec.io/floating-ip-ref";
/// `loadBalancers[].proxyProtocolV2`.
pub const LABEL_PROXY_PROTOCOL_V2: &str = "amispec.io/proxy-protocol-v2";
/// `loadBalancers[].http3Quic`.
pub const LABEL_HTTP3_QUIC: &str = "amispec.io/http3-quic";
/// `expose[].endpoint` (passport endpoint contract name).
pub const LABEL_ENDPOINT: &str = "amispec.io/endpoint";
/// `expose[].viaBalancer`.
pub const LABEL_VIA_BALANCER: &str = "amispec.io/via-balancer";
/// `expose[].scope` (public | protected).
pub const LABEL_SCOPE: &str = "amispec.io/scope";
/// Effective route host.
pub const LABEL_HOST: &str = "amispec.io/host";
/// How the host was derived: hostname | subdomain | default.
pub const LABEL_HOST_SOURCE: &str = "amispec.io/host-source";
/// Raw `expose[].hostname` / `expose[].subdomain` as authored.
pub const LABEL_HOST_VALUE: &str = "amispec.io/host-value";
/// Effective route path prefix.
pub const LABEL_PATH_PREFIX: &str = "amispec.io/path-prefix";
/// JSON `securityPolicy` contract of the exposure.
pub const LABEL_SECURITY_POLICY: &str = "amispec.io/security-policy";
/// Marker for artifacts that leave the headless baseline (k3s-servicelb).
pub const LABEL_HEADLESS_BASE_EXIT: &str = "amispec.io/headless-base-exit";

/// Prefix for readiness gate labels.
pub const TUNED_PREFIX: &str = "tuned.amispec.io";

/// Canonical passport pin `id.version-rev{N}` — **label-safe**.
///
/// The human shorthand is `id@rev`, but the pin is also a Kubernetes label
/// value (`amispec.io/passport`), where `@` is illegal
/// (`[A-Za-z0-9_.-]` only). The separator is `.` — passport ids are slugs
/// without dots, so the first dot splits id from version unambiguously.
pub fn passport_pin(id: &str, version: &str, rev: u32) -> String {
    let safe_version: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{id}.{safe_version}-rev{rev}")
}

/// Parse `id.version-rev{N}` back into `(id, version, rev)`.
pub fn parse_passport_pin(pin: &str) -> Option<(String, String, u32)> {
    let (left, rev) = pin.rsplit_once("-rev")?;
    let rev: u32 = rev.parse().ok()?;
    let (id, version) = left.split_once('.')?;
    Some((id.to_string(), version.to_string(), rev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passport_pin_roundtrip() {
        let pin = passport_pin("postgresql", "18.0.0", 6);
        assert_eq!(pin, "postgresql.18.0.0-rev6");
        let (id, ver, rev) = parse_passport_pin(&pin).unwrap();
        assert_eq!(
            (id.as_str(), ver.as_str(), rev),
            ("postgresql", "18.0.0", 6)
        );
    }

    #[test]
    fn passport_pin_is_label_safe() {
        // Kubernetes label values: [A-Za-z0-9_.-], start/end alphanumeric.
        let pin = passport_pin("stateless-app", "1.0.0", 1);
        assert_eq!(pin, "stateless-app.1.0.0-rev1");
        let ok = pin
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            && pin
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && pin
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric());
        assert!(ok, "pin `{pin}` must be a valid label value");
        // exotic versions collapse to '_' but stay reversible as a whole
        let weird = passport_pin("app", "1.0.0+x", 2);
        assert_eq!(weird, "app.1.0.0_x-rev2");
        assert_eq!(parse_passport_pin(&weird).unwrap().1, "1.0.0_x");
    }

    #[test]
    fn parse_passport_pin_rejects_malformed() {
        assert!(parse_passport_pin("").is_none());
        assert!(parse_passport_pin("no-separator").is_none());
        assert!(parse_passport_pin("id.ver").is_none());
        assert!(parse_passport_pin("id.ver-revX").is_none());
        assert!(parse_passport_pin(".ver-rev1").is_some()); // empty id allowed
    }
}
