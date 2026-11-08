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
        Ok(Self {
            id,
            version,
            passport_rev,
            stateful,
            client_sidecars: Vec::new(),
            endpoints,
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
            id: "postgresql".into(),
            version: "18.0.0".into(),
            passport_rev: 6,
            stateful: true,
            client_sidecars: vec![
                sidecar("pgbouncer", vec!["degraded-ha", "strict-ha"]),
                sidecar("always", vec![]),
            ],
            endpoints: Vec::new(),
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
            id: "stateless-app".into(),
            version: "1.0.0".into(),
            passport_rev: 1,
            stateful: false,
            client_sidecars: vec![],
            endpoints: Vec::new(),
        });
        assert_eq!(idx.len(), 1);
        assert!(idx.get("stateless-app").is_some());
        assert!(idx.get("missing").is_none());
        let collected: PassportIndex = vec![].into_iter().collect();
        assert!(collected.is_empty());
    }

    #[test]
    fn endpoint_contract_resolves_port() {
        let raw = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: demo-web, name: Web, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: web, protocol: http, containerPort: 8080, role: ui, defaultScope: public }
    - { name: admin, protocol: http, containerPort: 9090, role: management, defaultScope: protected }
  provides: []
  requires: {}
"#;
        let p = PassportSummary::from_passport_yaml(raw).unwrap();
        assert_eq!(p.id, "demo-web");
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
