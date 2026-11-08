//! Cross-document `requires` closure (Design Doc 0026 §1.2, §3.1).
//!
//! Topology assembly from the catalog must be an honest graph closure: every
//! `requires` slot of a component's passport has to be closed by a binding
//! (`asRequirement`) to a provider whose `provides` slot offers the required
//! capability. Unclosed dependencies are errors **before** apply — a half-wired
//! topology never reaches the compiler.

use crate::report::Finding;
use crate::value::*;
use amispec_schema::PassportSlots;
use std::collections::{BTreeMap, BTreeSet};

/// Run `requires` closure rules over a topology with a passport catalog.
///
/// `catalog` maps passport id → slot contract. Rules are silent when the
/// catalog is empty (pure structural validation stays dependency-free).
pub fn check(root: &Map, catalog: &BTreeMap<String, PassportSlots>, out: &mut Vec<Finding>) {
    if catalog.is_empty() {
        return;
    }
    let Some(clusters) = root.get("clusters").and_then(as_seq) else {
        return;
    };

    for (ci, cluster) in clusters.iter().enumerate() {
        let cpath = format!("clusters[{ci}]");

        // Every passport referenced by a component must be in the catalog —
        // the bundle pins it and the compiler resolves ports from it.
        let mut reported_missing: BTreeSet<String> = BTreeSet::new();
        let Some(comps) = cluster.get("components").and_then(as_seq) else {
            continue;
        };

        // Bindings visible in this cluster: inline (from = owner) + cluster-level.
        struct Edge {
            from: String,
            to: String,
            to_slot: Option<String>,
            as_requirement: Option<String>,
            location: String,
        }
        let mut edges: Vec<Edge> = Vec::new();
        for (pi, comp) in comps.iter().enumerate() {
            let ppath = format!("{cpath}.components[{pi}]");
            let comp_id = opt_str(comp, "id").unwrap_or_default().to_string();
            for (bi, b) in comp
                .get("bindings")
                .and_then(as_seq)
                .unwrap_or(&Vec::new())
                .iter()
                .enumerate()
            {
                edges.push(Edge {
                    from: comp_id.clone(),
                    to: opt_str(b, "to").unwrap_or_default().to_string(),
                    to_slot: opt_str(b, "toSlot").map(|s| s.to_string()),
                    as_requirement: opt_str(b, "asRequirement").map(|s| s.to_string()),
                    location: format!("{ppath}.bindings[{bi}]"),
                });
            }
        }
        for (bi, b) in cluster
            .get("bindings")
            .and_then(as_seq)
            .unwrap_or(&Vec::new())
            .iter()
            .enumerate()
        {
            edges.push(Edge {
                from: opt_str(b, "from").unwrap_or_default().to_string(),
                to: opt_str(b, "to").unwrap_or_default().to_string(),
                to_slot: opt_str(b, "toSlot").map(|s| s.to_string()),
                as_requirement: opt_str(b, "asRequirement").map(|s| s.to_string()),
                location: format!("{cpath}.bindings[{bi}]"),
            });
        }

        let external_ids: BTreeSet<String> = root
            .get("externalResources")
            .and_then(as_seq)
            .map(|list| {
                list.iter()
                    .filter_map(|e| opt_str(e, "id").map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let comp_ids: BTreeSet<String> = comps
            .iter()
            .filter_map(|c| opt_str(c, "id").map(|s| s.to_string()))
            .collect();

        for (pi, comp) in comps.iter().enumerate() {
            let ppath = format!("{cpath}.components[{pi}]");
            let comp_id = opt_str(comp, "id").unwrap_or_default().to_string();
            let Some(passport) = opt_str(comp, "passport") else {
                continue;
            };
            let Some(slots) = catalog.get(passport) else {
                if reported_missing.insert(passport.to_string()) {
                    out.push(Finding::error(
                        format!("{ppath}.passport"),
                        "passport-not-in-catalog",
                        format!(
                            "passport `{passport}` is not in the catalog — \
                             the delivery bundle cannot pin or compile it"
                        ),
                    ));
                }
                continue;
            };

            for (slot, capability) in &slots.requires {
                let closing: Vec<&Edge> = edges
                    .iter()
                    .filter(|e| {
                        e.from == comp_id && e.as_requirement.as_deref() == Some(slot.as_str())
                    })
                    .collect();
                let Some(edge) = closing.first() else {
                    out.push(Finding::error(
                        format!("{ppath}.bindings"),
                        "requires-unclosed",
                        format!(
                            "component `{comp_id}` (passport `{passport}`) requires \
                             `{slot}` ({capability}) — no binding closes it \
                             (expected asRequirement: {slot})"
                        ),
                    ));
                    continue;
                };

                // Target must exist inside the cluster (or be an external resource).
                if !comp_ids.contains(&edge.to) && !external_ids.contains(&edge.to) {
                    out.push(Finding::error(
                        edge.location.clone(),
                        "requires-target",
                        format!(
                            "binding target `{}` of requirement `{slot}` is neither \
                             a component nor an externalResource of this cluster",
                            edge.to
                        ),
                    ));
                    continue;
                }
                if external_ids.contains(&edge.to) {
                    continue; // external bridge: slot contract lives outside the blueprint
                }

                let target_passport = comps
                    .iter()
                    .find(|c| opt_str(c, "id") == Some(edge.to.as_str()))
                    .and_then(|c| opt_str(c, "passport"))
                    .unwrap_or_default();
                let Some(target_slots) = catalog.get(target_passport) else {
                    if reported_missing.insert(target_passport.to_string()) {
                        out.push(Finding::error(
                            edge.location.clone(),
                            "passport-not-in-catalog",
                            format!("target passport `{target_passport}` is not in the catalog"),
                        ));
                    }
                    continue;
                };

                match &edge.to_slot {
                    Some(to_slot) => match target_slots.provides.get(to_slot) {
                        Some(provided) if provided == capability => {}
                        Some(provided) => {
                            out.push(Finding::error(
                                edge.location.clone(),
                                "requires-capability",
                                format!(
                                    "slot `{to_slot}` of `{}` provides `{provided}`, \
                                     but `{slot}` requires `{capability}`",
                                    edge.to
                                ),
                            ));
                        }
                        None => {
                            out.push(Finding::error(
                                edge.location.clone(),
                                "requires-slot-missing",
                                format!(
                                    "target `{}` (passport `{target_passport}`) has no \
                                     provides slot `{to_slot}`",
                                    edge.to
                                ),
                            ));
                        }
                    },
                    None => {
                        if !target_slots.provides.values().any(|c| c == capability) {
                            out.push(Finding::error(
                                edge.location.clone(),
                                "requires-capability",
                                format!(
                                    "target `{}` (passport `{target_passport}`) provides \
                                     no capability `{capability}` required by `{slot}`",
                                    edge.to
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;
    use crate::validate_str_with_catalog;
    use amispec_schema::parse_passport_slots;

    fn catalog() -> BTreeMap<String, PassportSlots> {
        let docs = [
            r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: youtrack, name: YouTrack, version: "1.0.0", passportRev: 3 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides: []
  requires:
    edge: { capability: http-l7-gateway }
    database: { capability: postgres-sql }
"#,
            r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: balancer-cilium-l7, name: Balancer, version: "1.0.0", passportRev: 1 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - { slot: l7, capability: http-l7-gateway }
  requires: {}
"#,
            r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: postgresql, name: PG, version: "18.0.0", passportRev: 6 }
interfaces:
  egressDefaultMode: graph-only
  endpoints: []
  provides:
    - { slot: sql-cluster, capability: postgres-sql }
  requires: {}
"#,
        ];
        docs.iter()
            .map(|raw| {
                let s = parse_passport_slots(raw).unwrap();
                (s.id.clone(), s)
            })
            .collect()
    }

    const PREFIX: &str = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
clusters:
  - id: c0
    name: Demo
    domain: example.io
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        pricingTier: standard-node
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    components:
      - id: yt
        passport: youtrack
        version: "1.0.0"
        passportRev: 3
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
      - id: bal
        passport: balancer-cilium-l7
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
      - id: pg
        passport: postgresql
        version: "18.0.0"
        passportRev: 6
        topology: { mode: standalone }
        resources: { cpuCores: 2, memoryMb: 2048 }
"#;

    fn report(yaml: &str) -> crate::Report {
        validate_str_with_catalog("t", yaml, &Options::default(), &catalog())
    }

    #[test]
    fn accepts_closed_requirements() {
        let yaml = format!(
            "{PREFIX}    bindings:\n      - {{ from: yt, to: bal, toSlot: l7, asRequirement: edge }}\n      - {{ from: yt, to: pg, toSlot: sql-cluster, asRequirement: database }}\n"
        );
        let r = report(&yaml);
        assert!(r.is_ok(), "{:?}", r.findings);
    }

    #[test]
    fn rejects_unclosed_requirement() {
        let yaml = format!(
            "{PREFIX}    bindings:\n      - {{ from: yt, to: pg, toSlot: sql-cluster, asRequirement: database }}\n"
        );
        let r = report(&yaml);
        let hits: Vec<_> = r
            .errors()
            .filter(|e| e.rule == "requires-unclosed")
            .collect();
        assert_eq!(hits.len(), 1, "{:?}", r.findings);
        assert!(hits[0].message.contains("`edge`"), "{}", hits[0].message);
    }

    #[test]
    fn rejects_capability_mismatch() {
        let yaml = format!(
            "{PREFIX}    bindings:\n      - {{ from: yt, to: bal, toSlot: l7, asRequirement: database }}\n      - {{ from: yt, to: pg, toSlot: sql-cluster, asRequirement: edge }}\n"
        );
        let r = report(&yaml);
        assert!(
            r.errors().any(|e| e.rule == "requires-capability"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn rejects_missing_provides_slot() {
        let yaml = format!(
            "{PREFIX}    bindings:\n      - {{ from: yt, to: bal, toSlot: nope, asRequirement: edge }}\n      - {{ from: yt, to: pg, toSlot: sql-cluster, asRequirement: database }}\n"
        );
        let r = report(&yaml);
        assert!(
            r.errors().any(|e| e.rule == "requires-slot-missing"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn rejects_unknown_target() {
        let yaml = format!(
            "{PREFIX}    bindings:\n      - {{ from: yt, to: ghost, toSlot: l7, asRequirement: edge }}\n      - {{ from: yt, to: pg, toSlot: sql-cluster, asRequirement: database }}\n"
        );
        let r = report(&yaml);
        assert!(
            r.errors().any(|e| e.rule == "requires-target"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn rejects_passport_missing_from_catalog() {
        let yaml = PREFIX.replace("passport: youtrack", "passport: mystery-app");
        let r = report(&yaml);
        assert!(
            r.errors().any(|e| e.rule == "passport-not-in-catalog"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn silent_without_catalog() {
        let yaml = format!("{PREFIX}    bindings: []\n");
        let r = crate::validate_str("t", &yaml, &Options::default());
        assert!(
            !r.findings.iter().any(|f| f.rule.starts_with("requires-")),
            "{:?}",
            r.findings
        );
    }
}
