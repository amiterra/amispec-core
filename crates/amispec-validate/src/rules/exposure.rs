//! Cross-reference exposure rules (Design Doc 0025 §2.3).
//!
//! `expose[]` / `loadBalancers[]` are a graph across one cluster: these rules
//! resolve `viaBalancer` / `upstreamEdge`, enforce `(layer, provider)`
//! compatibility, host/path uniqueness, scope/auth policy, OIDC binding, TLS
//! prerequisites and air-gap warnings. Structural field checks live in
//! [`super::deep`]; this module is the semantic layer.

use super::deep::LB_TLS;
use crate::report::Finding;
use crate::value::*;

/// Recommended provider dictionary. The schema keeps `provider` an open
/// string (new providers are registry entries, not schema changes), so this
/// list — mirrored by the `amispec-compile` registry — is the fail-fast gate.
pub const LB_PROVIDERS: &[&str] = &[
    "cilium-envoy",
    "cilium-ingress",
    "cilium-l4-bgp",
    "k3s-servicelb",
    "cloudflare",
    "fastly",
];

/// Allowed `layer` values per known provider.
fn provider_layers(provider: &str) -> Option<&'static [&'static str]> {
    match provider {
        "cilium-envoy" | "cilium-ingress" => Some(&["l7-gateway"]),
        "cilium-l4-bgp" | "k3s-servicelb" => Some(&["l4-balancer"]),
        "cloudflare" | "fastly" => Some(&["edge-proxy"]),
        _ => None,
    }
}

/// Provider is a known registry entry.
pub fn is_known_provider(provider: &str) -> bool {
    LB_PROVIDERS.contains(&provider)
}

/// Resolve the effective host of an `expose[]` entry (Design Doc 0025 §1.5):
/// `hostname` as-is (takes precedence), else `<subdomain>.<cluster.domain>`,
/// else `<component-id>.<cluster.domain>` (ADR 0009 virtual-host convention).
pub fn effective_host(component_id: &str, cluster_domain: &str, ex: &Yaml) -> String {
    if let Some(h) = opt_str(ex, "hostname") {
        return h.to_string();
    }
    if let Some(s) = opt_str(ex, "subdomain") {
        return format!("{s}.{cluster_domain}");
    }
    format!("{component_id}.{cluster_domain}")
}

/// Effective path prefix (`/` by default).
pub fn effective_path(ex: &Yaml) -> String {
    opt_str(ex, "pathPrefix").unwrap_or("/").to_string()
}

/// True when the entry carries HTTP-level routing fields (L7 semantics).
fn is_http_expose(ex: &Yaml) -> bool {
    get(ex, "hostname").is_some()
        || get(ex, "subdomain").is_some()
        || get(ex, "pathPrefix").is_some()
        || get(ex, "securityPolicy").is_some()
}

/// Run all exposure rules over a parsed TopologyBlueprint root.
pub fn check(root: &Map, out: &mut Vec<Finding>) {
    let Some(clusters) = root.get("clusters").and_then(as_seq) else {
        return;
    };

    for (ci, cluster) in clusters.iter().enumerate() {
        let cpath = format!("clusters[{ci}]");
        let domain = opt_str(cluster, "domain").unwrap_or("").to_string();

        // ---- load balancers: provider dictionary + (layer, provider) ----
        let mut lbs: Vec<(String, String, String, Option<String>)> = Vec::new();
        if let Some(list) = cluster.get("loadBalancers").and_then(as_seq) {
            for (li, lb) in list.iter().enumerate() {
                let lpath = format!("{cpath}.loadBalancers[{li}]");
                let id = opt_str(lb, "id").unwrap_or_default().to_string();
                let layer = opt_str(lb, "layer").unwrap_or_default().to_string();
                let provider = opt_str(lb, "provider").unwrap_or_default().to_string();
                let upstream = opt_str(lb, "upstreamEdge").map(|s| s.to_string());

                if !provider.is_empty() {
                    if !is_known_provider(&provider) {
                        out.push(Finding::error(
                            format!("{lpath}.provider"),
                            "lb-provider-unknown",
                            format!(
                                "provider `{provider}` is not implemented \
                                 (known: {LB_PROVIDERS:?}); fix the provider or extend the registry"
                            ),
                        ));
                    } else if let Some(allowed) = provider_layers(&provider) {
                        if !layer.is_empty() && !allowed.contains(&layer.as_str()) {
                            out.push(Finding::error(
                                format!("{lpath}.layer"),
                                "lb-provider-layer",
                                format!(
                                    "provider `{provider}` does not support layer `{layer}` \
                                     (allowed: {allowed:?})"
                                ),
                            ));
                        }
                    }
                }

                // tls enum lives in deep::check_load_balancer; prerequisites here.
                check_tls_prereqs(lb, &lpath, upstream.as_deref(), out);

                lbs.push((id, layer, provider, upstream));
            }
        }
        // upstreamEdge resolution
        for (li, (_, _, _, upstream)) in lbs.iter().enumerate() {
            if let Some(up) = upstream {
                if !lbs.iter().any(|(id, ..)| id == up) {
                    out.push(Finding::error(
                        format!("{cpath}.loadBalancers[{li}].upstreamEdge"),
                        "lb-upstream-edge",
                        format!("upstreamEdge `{up}` is not a loadBalancers[].id of this cluster"),
                    ));
                }
            }
        }

        let lb_by_id = |id: &str| lbs.iter().find(|(i, ..)| i == id);

        // ---- bindings graph (for OIDC) ----
        let mut oidc_targets: Vec<String> = Vec::new();
        if let Some(list) = cluster.get("bindings").and_then(as_seq) {
            for b in list {
                if opt_str(b, "type") == Some("oidc-protection") {
                    if let Some(to) = opt_str(b, "to") {
                        oidc_targets.push(to.to_string());
                    }
                }
            }
        }

        // ---- components: expose[] semantics ----
        let Some(comps) = cluster.get("components").and_then(as_seq) else {
            continue;
        };
        for comp in comps {
            for b in comp.get("bindings").and_then(as_seq).unwrap_or(&vec![]) {
                if opt_str(b, "type") == Some("oidc-protection") {
                    if let Some(to) = opt_str(b, "to") {
                        oidc_targets.push(to.to_string());
                    }
                }
            }
        }

        // referenced balancers: viaBalancer targets + upstreamEdge chain heads
        let empty_list: Vec<Yaml> = Vec::new();
        let mut referenced: Vec<&str> = Vec::new();
        for comp in comps {
            for ex in comp.get("expose").and_then(as_seq).unwrap_or(&empty_list) {
                if let Some(via) = opt_str(ex, "viaBalancer") {
                    if !referenced.contains(&via) {
                        referenced.push(via);
                    }
                }
            }
        }
        for (_, _, _, upstream) in &lbs {
            if let Some(up) = upstream {
                if !referenced.contains(&up.as_str()) {
                    referenced.push(up);
                }
            }
        }
        for (li, (id, _, _, _)) in lbs.iter().enumerate() {
            if !id.is_empty() && !referenced.contains(&id.as_str()) {
                out.push(Finding::warning(
                    format!("{cpath}.loadBalancers[{li}]"),
                    "lb-unreferenced",
                    format!(
                        "loadBalancer `{id}` is declared but referenced by no \
                         expose[]/upstreamEdge — nothing is materialized for it"
                    ),
                ));
            }
        }

        // host/path uniqueness needs every exposure of the cluster first
        struct RouteKey {
            host: String,
            path: String,
            location: String,
        }
        let mut routes: Vec<RouteKey> = Vec::new();
        let mut seen_endpoints: Vec<(String, String, String)> = Vec::new();
        let mut l7_balancers_used: Vec<String> = Vec::new();

        for (pi, comp) in comps.iter().enumerate() {
            let ppath = format!("{cpath}.components[{pi}]");
            let comp_id = opt_str(comp, "id").unwrap_or_default().to_string();

            // inline bindings of this component
            for b in comp.get("bindings").and_then(as_seq).unwrap_or(&vec![]) {
                if opt_str(b, "type") == Some("oidc-protection") {
                    if let Some(to) = opt_str(b, "to") {
                        oidc_targets.push(to.to_string());
                    }
                }
            }

            let Some(expose) = comp.get("expose").and_then(as_seq) else {
                continue;
            };
            for (ei, ex) in expose.iter().enumerate() {
                let epath = format!("{ppath}.expose[{ei}]");
                let Some(via) = opt_str(ex, "viaBalancer") else {
                    continue; // missing field reported by structural rules
                };

                // (component, endpoint) must stay unique — route object names
                // are `<component>-<endpoint>` (Design Doc 0025 §2.4).
                if let Some(ep) = opt_str(ex, "endpoint") {
                    let key = (comp_id.clone(), ep.to_string());
                    if seen_endpoints
                        .iter()
                        .any(|(c, e, _)| (c, e) == (&key.0, &key.1))
                    {
                        out.push(Finding::error(
                            epath.clone(),
                            "expose-duplicate-endpoint",
                            format!(
                                "duplicate expose endpoint `{ep}` of component `{}` — \
                                 (component, endpoint) MUST be unique within a cluster",
                                comp_id
                            ),
                        ));
                    } else {
                        seen_endpoints.push((key.0, key.1, epath.clone()));
                    }
                }

                // 1. viaBalancer resolution
                let Some((_, layer, _, _)) = lb_by_id(via) else {
                    out.push(Finding::error(
                        format!("{epath}.viaBalancer"),
                        "expose-via-balancer",
                        format!("viaBalancer `{via}` is not a loadBalancers[].id of this cluster"),
                    ));
                    continue;
                };

                // 2. (layer, provider) compatibility of the exposure
                let http = is_http_expose(ex);
                match layer.as_str() {
                    "l7-gateway" => {
                        if l7_balancers_used.iter().all(|b| b != via) {
                            l7_balancers_used.push(via.to_string());
                        }
                    }
                    "l4-balancer" => {
                        if http {
                            out.push(Finding::error(
                                format!("{epath}.viaBalancer"),
                                "expose-layer",
                                format!(
                                    "HTTP expose (hostname/subdomain/pathPrefix/securityPolicy) \
                                     cannot reference l4-balancer `{via}`"
                                ),
                            ));
                        }
                    }
                    "edge-proxy" => {
                        out.push(Finding::error(
                            format!("{epath}.viaBalancer"),
                            "expose-layer",
                            format!(
                                "edge-proxy `{via}` does not accept expose[] directly; \
                                 chain it via upstreamEdge of an l7-gateway balancer"
                            ),
                        ));
                    }
                    _ => {}
                }

                if layer == "l7-gateway" {
                    let host = effective_host(&comp_id, &domain, ex);
                    let path = effective_path(ex);
                    routes.push(RouteKey {
                        host,
                        path,
                        location: epath.clone(),
                    });

                    // hostname + subdomain both set
                    if get(ex, "hostname").is_some() && get(ex, "subdomain").is_some() {
                        out.push(Finding::warning(
                            epath.clone(),
                            "expose-host-override",
                            "both hostname and subdomain set; hostname takes precedence",
                        ));
                    }
                }

                // 3. scope / authentication policy
                let scope = opt_str(ex, "scope").unwrap_or_default();
                let sp = get(ex, "securityPolicy");
                let client_auth = sp.and_then(|s| opt_str(s, "clientAuth")).unwrap_or("none");
                let allow_anonymous = sp
                    .and_then(|s| get(s, "allowAnonymous"))
                    .and_then(as_bool)
                    .unwrap_or(false);

                if scope == "protected" {
                    if client_auth == "none" {
                        if allow_anonymous {
                            out.push(Finding::warning(
                                epath.clone(),
                                "expose-protected-auth",
                                "scope `protected` without clientAuth — \
                                 allowAnonymous: true explicitly acknowledges the open edge",
                            ));
                        } else {
                            out.push(Finding::error(
                                epath.clone(),
                                "expose-protected-auth",
                                "scope `protected` requires securityPolicy.clientAuth != none \
                                 (or explicit securityPolicy.allowAnonymous: true)",
                            ));
                        }
                    }
                    // 4. OIDC binding
                    if client_auth == "oidc" && !oidc_targets.contains(&comp_id) {
                        out.push(Finding::error(
                            epath.clone(),
                            "expose-oidc-binding",
                            format!(
                                "clientAuth `oidc` requires a binding with \
                                 type: oidc-protection to component `{comp_id}`"
                            ),
                        ));
                    }
                }

                // TLS prerequisite: protected edge without TLS
                if scope == "protected" {
                    if let Some((_, _, _, _)) = lb_by_id(via) {
                        let tls = lb_tls(cluster, via);
                        if tls.as_deref() == Some("none") || tls.is_none() {
                            out.push(Finding::warning(
                                epath.clone(),
                                "expose-protected-no-tls",
                                "scope `protected` behind tls: none — open edge without TLS \
                                 (acceptable for *.localhost / lab domains)",
                            ));
                        }
                    }
                }
            }
        }

        // 5. duplicate (host, path) across the cluster
        for i in 0..routes.len() {
            for j in (i + 1)..routes.len() {
                if routes[i].host == routes[j].host && routes[i].path == routes[j].path {
                    out.push(Finding::error(
                        routes[j].location.clone(),
                        "expose-duplicate-host-path",
                        format!(
                            "duplicate (host `{}`, path `{}`) — also declared at {}",
                            routes[i].host, routes[i].path, routes[i].location
                        ),
                    ));
                }
            }
        }

        // 6. air-gap + L7 exposure
        let airgapped = cluster
            .get("security")
            .and_then(|s| opt_str(s, "imageRegistryPolicy"))
            == Some("airgapped-mirror");
        if airgapped && !l7_balancers_used.is_empty() {
            out.push(Finding::warning(
                format!("{cpath}.security.imageRegistryPolicy"),
                "airgap-l7-images",
                "L7 exposure in an air-gapped cluster requires mirrored images \
                 (Cilium Envoy, Gateway API CRDs, cert-manager when tls != none) — \
                 see os/scripts/download_airgap.sh",
            ));
        }
    }
}

/// Read `loadBalancers[].tls` of the balancer `via` (default `none`).
fn lb_tls(cluster: &Yaml, via: &str) -> Option<String> {
    cluster
        .get("loadBalancers")
        .and_then(as_seq)?
        .iter()
        .find(|lb| opt_str(lb, "id") == Some(via))
        .and_then(|lb| opt_str(lb, "tls"))
        .map(|s| s.to_string())
}

/// TLS-mode prerequisites on the balancer itself (Design Doc 0025 §2.3 rule 6).
fn check_tls_prereqs(lb: &Yaml, lpath: &str, upstream_edge: Option<&str>, out: &mut Vec<Finding>) {
    let Some(tls) = opt_str(lb, "tls") else {
        return;
    };
    if !LB_TLS.contains(&tls) {
        return; // structural enum error already reported
    }
    // HTTP-01 behind an external edge proxy: the ACME challenge may never
    // reach the cluster — recommend DNS-01 wildcard (Design Doc 0025 §3).
    if tls == "letsencrypt-http01" && upstream_edge.is_some() {
        out.push(Finding::warning(
            format!("{lpath}.tls"),
            "expose-tls-http01-edge",
            format!(
                "tls `letsencrypt-http01` behind external edge `{}` — the ACME HTTP-01 \
                 challenge may be blocked; prefer `letsencrypt-dns01-wildcard`",
                upstream_edge.unwrap_or_default()
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;
    use crate::Severity;
    use crate::validate_str;

    fn report(yaml: &str) -> crate::Report {
        validate_str("t", yaml, &Options::default())
    }

    const PREFIX: &str = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
clusters:
  - id: local
    name: Local
    domain: example.local
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
"#;

    fn with(content: &str) -> String {
        format!("{PREFIX}{content}")
    }

    fn assert_rule(yaml: &str, rule: &str, want_error: bool) -> Vec<Finding> {
        let r = report(yaml);
        let hits: Vec<Finding> = r
            .findings
            .iter()
            .filter(|f| f.rule == rule)
            .cloned()
            .collect();
        if want_error {
            assert!(
                hits.iter().any(|f| f.severity == Severity::Error),
                "expected error `{rule}`, got {:?}",
                r.findings
            );
        } else {
            assert!(hits.is_empty(), "unexpected `{rule}` findings: {hits:?}");
        }
        hits
    }

    #[test]
    fn effective_host_resolution() {
        let ex: Yaml =
            serde_yaml::from_str("{ endpoint: web, viaBalancer: l7, scope: public }").unwrap();
        assert_eq!(
            effective_host("web", "example.local", &ex),
            "web.example.local"
        );
        let ex: Yaml = serde_yaml::from_str(
            "{ endpoint: web, viaBalancer: l7, scope: public, subdomain: api }",
        )
        .unwrap();
        assert_eq!(effective_host("web", "example.io", &ex), "api.example.io");
        let ex: Yaml = serde_yaml::from_str(
            "{ endpoint: web, viaBalancer: l7, scope: public, hostname: apex.io, subdomain: x }",
        )
        .unwrap();
        assert_eq!(effective_host("web", "example.io", &ex), "apex.io");
    }

    #[test]
    fn rejects_unknown_provider() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: nginx-custom }
    components: []
"#,
        );
        assert_rule(&yaml, "lb-provider-unknown", true);
    }

    #[test]
    fn rejects_provider_layer_mismatch() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l4-balancer, provider: cilium-envoy }
    components: []
"#,
        );
        assert_rule(&yaml, "lb-provider-layer", true);
    }

    #[test]
    fn rejects_unresolved_via_balancer() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: ghost, scope: public, hostname: app.example.io }
"#,
        );
        assert_rule(&yaml, "expose-via-balancer", true);
    }

    #[test]
    fn rejects_http_expose_on_l4_balancer() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l4, layer: l4-balancer, provider: cilium-l4-bgp }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l4, scope: public, subdomain: app }
"#,
        );
        assert_rule(&yaml, "expose-layer", true);
    }

    #[test]
    fn rejects_expose_on_edge_proxy() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: edge, layer: edge-proxy, provider: cloudflare }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: edge, scope: public, hostname: app.example.io }
"#,
        );
        assert_rule(&yaml, "expose-layer", true);
    }

    #[test]
    fn rejects_duplicate_host_path() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l7, scope: public, hostname: app.example.io, pathPrefix: /api }
      - id: api
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l7, scope: public, hostname: app.example.io, pathPrefix: /api }
"#,
        );
        assert_rule(&yaml, "expose-duplicate-host-path", true);
    }

    #[test]
    fn rejects_protected_without_auth() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l7, scope: protected, subdomain: admin }
"#,
        );
        assert_rule(&yaml, "expose-protected-auth", true);
    }

    #[test]
    fn warns_protected_allow_anonymous() {
        let yaml = with(
            r#"    loadBalancers:
      - id: l7
        layer: l7-gateway
        provider: cilium-envoy
        tls: none
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - endpoint: web
            viaBalancer: l7
            scope: protected
            subdomain: admin
            securityPolicy: { allowAnonymous: true }
"#,
        );
        let r = report(&yaml);
        assert!(
            !r.errors().any(|f| f.rule == "expose-protected-auth"),
            "allowAnonymous must not be an error: {:?}",
            r.findings
        );
        assert!(
            r.warnings().any(|f| f.rule == "expose-protected-auth"),
            "{:?}",
            r.findings
        );
        assert!(r.is_ok(), "allowAnonymous must not fail validation");
    }

    #[test]
    fn rejects_oidc_without_binding() {
        let yaml = with(
            r#"    loadBalancers:
      - id: l7
        layer: l7-gateway
        provider: cilium-envoy
        tls: letsencrypt-http01
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - endpoint: web
            viaBalancer: l7
            scope: protected
            subdomain: admin
            securityPolicy: { clientAuth: oidc }
"#,
        );
        assert_rule(&yaml, "expose-oidc-binding", true);
    }

    #[test]
    fn accepts_oidc_with_binding() {
        let yaml = with(
            r#"    loadBalancers:
      - id: l7
        layer: l7-gateway
        provider: cilium-envoy
        tls: letsencrypt-http01
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - endpoint: web
            viaBalancer: l7
            scope: protected
            subdomain: admin
            securityPolicy: { clientAuth: oidc }
      - id: keycloak
        passport: keycloak
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings:
      - { from: keycloak, to: web, type: oidc-protection }
"#,
        );
        assert_rule(&yaml, "expose-oidc-binding", false);
        assert_rule(&yaml, "expose-protected-auth", false);
    }

    #[test]
    fn warns_http01_behind_edge() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: edge, layer: edge-proxy, provider: cloudflare }
      - id: l7
        layer: l7-gateway
        provider: cilium-envoy
        upstreamEdge: edge
        tls: letsencrypt-http01
    components: []
"#,
        );
        let r = report(&yaml);
        assert!(
            r.warnings().any(|f| f.rule == "expose-tls-http01-edge"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn warns_airgap_l7_images() {
        let yaml = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: demo, organization: ex }
clusters:
  - id: local
    name: Local
    domain: example.local
    security:
      sopsRecipients: [age1abc123]
      imageRegistryPolicy: airgapped-mirror
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - { endpoint: web, viaBalancer: l7, scope: public, subdomain: app }
"#;
        let r = report(yaml);
        assert!(
            r.warnings().any(|f| f.rule == "airgap-l7-images"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn zero_expose_has_no_exposure_findings() {
        let yaml = with(
            r#"    loadBalancers:
      - { id: l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
"#,
        );
        let r = report(&yaml);
        assert!(r.is_ok(), "{:?}", r.findings);
        for rule in [
            "expose-via-balancer",
            "expose-layer",
            "expose-duplicate-host-path",
            "expose-protected-auth",
            "expose-oidc-binding",
            "airgap-l7-images",
        ] {
            assert!(
                !r.findings.iter().any(|f| f.rule == rule),
                "unexpected {rule}"
            );
        }
        // declared-but-unreferenced balancer gets a warning (§1.3), not an error
        assert!(
            r.warnings().any(|f| f.rule == "lb-unreferenced"),
            "{:?}",
            r.findings
        );
    }
}
