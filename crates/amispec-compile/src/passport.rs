//! Passport view used by the compiler (sidecar injection, statefulness).
//!
//! Full passports live in the AmiSpec catalog; the compiler only needs the
//! subset that affects generated manifests.

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
}

/// Catalog lookup by passport id (or path).
#[derive(Debug, Default, Clone)]
pub struct PassportIndex {
    inner: BTreeMap<String, PassportSummary>,
}

impl PassportIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: PassportSummary) {
        self.inner.insert(summary.id.clone(), summary);
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
        });
        assert_eq!(idx.len(), 1);
        assert!(idx.get("stateless-app").is_some());
        assert!(idx.get("missing").is_none());
        let collected: PassportIndex = vec![].into_iter().collect();
        assert!(collected.is_empty());
    }
}
