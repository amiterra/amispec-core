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

/// Prefix for readiness gate labels.
pub const TUNED_PREFIX: &str = "tuned.amispec.io";

/// Build `id@version-rev` passport pin.
pub fn passport_pin(id: &str, version: &str, rev: u32) -> String {
    format!("{id}@{version}-rev{rev}")
}

/// Parse `id@version-rev` back into parts.
pub fn parse_passport_pin(pin: &str) -> Option<(String, String, u32)> {
    let (left, rev) = pin.rsplit_once("-rev")?;
    let rev: u32 = rev.parse().ok()?;
    let (id, version) = left.split_once('@')?;
    Some((id.to_string(), version.to_string(), rev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passport_pin_roundtrip() {
        let pin = passport_pin("postgresql", "18.0.0", 6);
        assert_eq!(pin, "postgresql@18.0.0-rev6");
        let (id, ver, rev) = parse_passport_pin(&pin).unwrap();
        assert_eq!((id.as_str(), ver.as_str(), rev), ("postgresql", "18.0.0", 6));
    }

    #[test]
    fn parse_passport_pin_rejects_malformed() {
        assert!(parse_passport_pin("").is_none());
        assert!(parse_passport_pin("no-separator").is_none());
        assert!(parse_passport_pin("id@ver").is_none());
        assert!(parse_passport_pin("id@ver-revX").is_none());
        assert!(parse_passport_pin("@ver-rev1").is_some()); // empty id allowed
    }
}
