//! Exposure conformance suite (Task 0005 V1–V3, V5 compile-side):
//! golden trees, zero-footprint invariant and compile/decompile round-trip.
//!
//! Golden regeneration: `AMISPEC_UPDATE_GOLDENS=1 cargo test -p amispec-compile`.

use amispec_compile::{
    compile, decompile_dir, CompileError, GeneratedFile, Options, PassportIndex, PassportSummary,
};
use amispec_schema::parse_topology;
use std::path::{Path, PathBuf};

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
}

/// Deterministic golden rendering of a compiled tree.
fn render_tree(files: &[GeneratedFile]) -> String {
    let mut out = String::new();
    for f in files {
        out.push_str(&format!("=== {} ===\n", f.relative_path));
        out.push_str(&f.contents);
        if !f.contents.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn check_golden(name: &str, actual: &str) {
    let path = goldens_dir().join(name);
    if std::env::var("AMISPEC_UPDATE_GOLDENS").is_ok() {
        std::fs::create_dir_all(goldens_dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing golden {name} ({e}); run with AMISPEC_UPDATE_GOLDENS=1")
    });
    assert_eq!(
        expected, actual,
        "golden drift for {name}; regenerate with AMISPEC_UPDATE_GOLDENS=1 if intentional"
    );
}

fn passports() -> PassportIndex {
    let raw = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: stateless-app, name: App, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: web, protocol: http, containerPort: 8080, role: ui, defaultScope: public }
    - { name: admin, protocol: http, containerPort: 9090, role: management, defaultScope: protected }
    - { name: mqtt, protocol: tcp, containerPort: 1883, role: datastore, defaultScope: public }
  provides: []
  requires: {}
"#;
    let mut idx = PassportIndex::new();
    idx.insert(PassportSummary::from_passport_yaml(raw).unwrap());
    idx
}

/// V3 topology: TLS + protected + OIDC + CORS + rate limit + subdomain,
/// hostname apex and an L4 exposure.
const V3_TOPOLOGY: &str = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: exposure-demo, organization: example-org }
clusters:
  - id: local
    name: Demo
    domain: example.io
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        pricingTier: standard-node
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    loadBalancers:
      - id: main-l7
        layer: l7-gateway
        provider: cilium-envoy
        tls: letsencrypt-http01
      - id: mqtt-l4
        layer: l4-balancer
        provider: cilium-l4-bgp
        forwardingMode: ebpf-dsr-maglev
        floatingIpRef: fip-01
        proxyProtocolV2: true
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        zone: dmz-public
        topology: { mode: standalone, replicas: 2 }
        resources: { cpuCores: 1, memoryMb: 256 }
        expose:
          - endpoint: web
            viaBalancer: main-l7
            scope: public
            hostname: example.io
            pathPrefix: /api/v2
            securityPolicy: { corsAllowedOrigins: ["https://app.example.io"], rateLimitRps: 500 }
          - endpoint: admin
            viaBalancer: main-l7
            scope: protected
            subdomain: admin
            securityPolicy: { clientAuth: oidc }
          - endpoint: mqtt
            viaBalancer: mqtt-l4
            scope: public
      - id: keycloak
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings:
      - { from: keycloak, to: web, type: oidc-protection }
"#;

/// V1 topology: balancer declared but nothing exposed.
const ZERO_TOPOLOGY: &str = r#"
apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: { projectId: headless, organization: example-org }
clusters:
  - id: local
    name: Demo
    domain: example.io
    security: { sopsRecipients: [age1abc123] }
    cni: { engine: cilium-ebpf, clusterMeshId: 1 }
    nodes:
      - id: n1
        role: control-plane-worker
        pricingTier: standard-node
        hardware: { cpuCores: 2, memoryMb: 4096, disks: [] }
    loadBalancers:
      - { id: main-l7, layer: l7-gateway, provider: cilium-envoy }
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        topology: { mode: standalone }
        resources: { cpuCores: 1, memoryMb: 256 }
    bindings: []
"#;

fn compile_yaml(yaml: &str) -> amispec_compile::CompileResult {
    let topo = parse_topology(yaml).expect("parse");
    compile(&topo, &passports(), &Options::dry()).expect("compile")
}

#[test]
fn golden_v3_exposure_tree() {
    let out = compile_yaml(V3_TOPOLOGY);
    check_golden("v3-exposure-tree.golden", &render_tree(&out.files));
}

#[test]
fn golden_zero_exposure_tree() {
    let out = compile_yaml(ZERO_TOPOLOGY);
    check_golden("zero-exposure-tree.golden", &render_tree(&out.files));
}

#[test]
fn v1_zero_balancing_objects() {
    let out = compile_yaml(ZERO_TOPOLOGY);
    for f in &out.files {
        for kind in [
            "GatewayClass",
            "Gateway",
            "HTTPRoute",
            "Ingress",
            "HelmChartConfig",
            "HelmRelease",
            "ClusterIssuer",
            "Certificate",
            "CiliumLoadBalancerIPPool",
        ] {
            assert!(
                !f.contents.contains(&format!("kind: {kind}")),
                "V1 violated: {kind} in {}",
                f.relative_path
            );
        }
    }
}

#[test]
fn v2_route_contract() {
    let out = compile_yaml(V3_TOPOLOGY);
    let render = render_tree(&out.files);
    let routes = out
        .files
        .iter()
        .find(|f| f.relative_path.ends_with("05-applications/routes.yaml"))
        .expect("routes.yaml")
        .contents
        .clone();
    // real controller, resolved parentRefs, contract port (not 80)
    assert!(render.contains("controllerName: io.cilium/gateway-controller"));
    assert!(render.contains("kind: HTTPRoute"));
    assert!(render.contains("port: 8080"));
    assert!(render.contains("port: 9090"));
    assert!(
        !routes.contains("port: 80\n"),
        "hardcoded backend port 80 must be gone:\n{routes}"
    );
    // subdomain expansion + hostname as-is
    assert!(render.contains("admin.example.io"));
    assert!(render.contains("example.io"));
    // L4 exposure becomes a LoadBalancer Service with DSR annotations
    assert!(render.contains("kind: CiliumLoadBalancerIPPool"));
    assert!(render.contains("service.cilium.io/lb-mode"));
    assert!(render.contains("dsr"));
}

#[test]
fn v3_tls_and_policy_artifacts() {
    let out = compile_yaml(V3_TOPOLOGY);
    let render = render_tree(&out.files);
    // cert-manager chain + issuer + certificates
    assert!(render.contains("kind: HelmRelease"));
    assert!(render.contains("cert-manager"));
    assert!(render.contains("kind: ClusterIssuer"));
    assert!(render.contains("kind: Certificate"));
    // stage 06 guard for scope: protected
    assert!(render.contains("kind: CiliumNetworkPolicy"));
    assert!(render.contains("edge-guard"));
    // CORS filter on the public route
    assert!(render.contains("Access-Control-Allow-Origin"));
}

#[test]
fn v3_roundtrip_restores_all_exposure_fields() {
    let topo = parse_topology(V3_TOPOLOGY).unwrap();
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("exposure-roundtrip");
    let _ = std::fs::remove_dir_all(&out);
    compile(
        &topo,
        &passports(),
        &Options {
            out_dir: out.clone(),
            provenance: true,
            dry_run: false,
        },
    )
    .unwrap();
    let report = decompile_dir(&out).expect("decompile");
    let rebuilt = report.topology.expect("topology");
    let cluster = &rebuilt.clusters[0];

    // loadBalancers restored
    let l7 = cluster
        .load_balancers
        .iter()
        .find(|l| l.id == "main-l7")
        .expect("l7");
    assert_eq!(l7.layer, "l7-gateway");
    assert_eq!(l7.provider, "cilium-envoy");
    assert_eq!(l7.tls.as_deref(), Some("letsencrypt-http01"));
    let l4 = cluster
        .load_balancers
        .iter()
        .find(|l| l.id == "mqtt-l4")
        .expect("l4");
    assert_eq!(l4.layer, "l4-balancer");
    assert_eq!(l4.provider, "cilium-l4-bgp");
    assert_eq!(l4.forwarding_mode.as_deref(), Some("ebpf-dsr-maglev"));
    assert_eq!(l4.floating_ip_ref.as_deref(), Some("fip-01"));
    assert_eq!(l4.proxy_protocol_v2, Some(true));

    // expose[] restored on web
    let web = cluster
        .components
        .iter()
        .find(|c| c.id == "web")
        .expect("web");
    assert_eq!(web.expose.len(), 3, "{:?}", web.expose);

    let api = web
        .expose
        .iter()
        .find(|e| e.endpoint == "web" && e.via_balancer == "main-l7")
        .expect("api expose");
    assert_eq!(api.hostname.as_deref(), Some("example.io"));
    assert_eq!(api.path_prefix.as_deref(), Some("/api/v2"));
    assert_eq!(api.scope, "public");
    let sp = api.security_policy.as_ref().expect("securityPolicy");
    assert_eq!(
        sp.cors_allowed_origins.as_deref(),
        Some(&["https://app.example.io".to_string()][..])
    );
    assert_eq!(sp.rate_limit_rps, Some(500));

    let admin = web
        .expose
        .iter()
        .find(|e| e.endpoint == "admin")
        .expect("admin expose");
    assert_eq!(admin.via_balancer, "main-l7");
    assert_eq!(admin.subdomain.as_deref(), Some("admin"));
    assert_eq!(admin.scope, "protected");
    let sp = admin.security_policy.as_ref().expect("admin policy");
    assert_eq!(sp.client_auth.as_deref(), Some("oidc"));

    let l4e = web
        .expose
        .iter()
        .find(|e| e.via_balancer == "mqtt-l4")
        .expect("l4 expose");
    assert!(l4e.hostname.is_none() && l4e.subdomain.is_none());
}

#[test]
fn every_namespaced_object_declares_a_namespace() {
    // Flux applies with server-side dry-run: a namespaced object without
    // metadata.namespace aborts the whole Kustomization ("namespace not
    // specified"), and an invalid label value aborts it just as hard (these
    // only surface at the API). This is the regression guard for both.
    const NAMESPACED: &[&str] = &[
        "ConfigMap",
        "Secret",
        "Service",
        "Deployment",
        "StatefulSet",
        "Job",
        "PodDisruptionBudget",
        "HorizontalPodAutoscaler",
        "HTTPRoute",
        "Ingress",
        "CiliumNetworkPolicy",
        "Gateway",
        "HelmRelease",
        "HelmRepository",
        "Certificate",
    ];
    let out = compile_yaml(V3_TOPOLOGY);
    for f in &out.files {
        for doc in f.contents.split("\n---\n") {
            let v: serde_yaml::Value = match serde_yaml::from_str(doc) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(kind) = v.get("kind").and_then(|k| k.as_str()) {
                if NAMESPACED.contains(&kind) {
                    assert!(
                        v.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .is_some(),
                        "{kind} in {} has no metadata.namespace:\n{doc}",
                        f.relative_path
                    );
                }
            }
            // label values must satisfy the Kubernetes label grammar
            if let Some(labels) = v
                .get("metadata")
                .and_then(|m| m.get("labels"))
                .and_then(|l| l.as_mapping())
            {
                for (k, val) in labels {
                    let k = k.as_str().unwrap_or("?");
                    let val = val.as_str().unwrap_or_default();
                    let ok = val.is_empty()
                        || (val
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                            && val
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_alphanumeric())
                            && val
                                .chars()
                                .last()
                                .is_some_and(|c| c.is_ascii_alphanumeric()));
                    assert!(ok, "invalid label {k}={val} in {}:\n{doc}", f.relative_path);
                }
            }
        }
    }
}

#[test]
fn listeners_attach_only_declared_namespaces() {
    // Security invariant: the edge Gateway must not accept routes from
    // arbitrary namespaces (`from: All` is a content-hijack hole with our
    // wildcard certs). Attachment is limited to the namespaces the
    // balancer's exposures actually live in.
    let out = compile_yaml(V3_TOPOLOGY);
    let render = render_tree(&out.files);
    assert!(
        !render.contains("\"from\": \"All\""),
        "from: All is forbidden"
    );
    assert!(
        render.contains("from: Selector"),
        "selector-based attachment"
    );
    assert!(
        render.contains("kubernetes.io/metadata.name"),
        "namespace-name selector (works for any namespace incl. default)"
    );
    // V3 topology routes live in zone dmz-public — exactly one allowed value
    assert!(render.contains("dmz-public"), "declared zone allowed");
    assert!(
        !render.contains("sandbox"),
        "undeclared namespaces never allowed"
    );
}

#[test]
fn gateway_nodeport_path_is_closed() {
    // Security invariant: reachability must match the declared model —
    // no accidental `<node>:<nodePort>` entry for gateway/L4 services.
    let out = compile_yaml(V3_TOPOLOGY);
    let render = render_tree(&out.files);
    assert!(
        render.contains("allocateLoadBalancerNodePorts: false"),
        "gateway + L4 services must not allocate NodePorts"
    );
    assert!(render.contains("kind: CiliumGatewayClassConfig"));
    assert!(
        render.contains("parametersRef"),
        "GatewayClass references the config"
    );
    // The CGCC CRD must ship with the tree: the Cilium chart installs no CRDs
    // and cilium-operator skips this one — without it Flux dry-run aborts the
    // whole kustomization with "no matches for kind".
    assert!(
        render.contains("name: ciliumgatewayclassconfigs.cilium.io"),
        "vendored CiliumGatewayClassConfig CRD present"
    );
}

#[test]
fn vendored_crd_emitted_once_across_balancers() {
    // The vendored CRD is a cluster-level prerequisite — N L7 balancers must
    // not produce N copies (duplicate-apply noise / inventory conflicts).
    let yaml = V3_TOPOLOGY
        .replace(
            "      - id: mqtt-l4",
            "      - id: standby-l7\n        layer: l7-gateway\n        provider: cilium-envoy\n        tls: letsencrypt-http01\n      - id: mqtt-l4",
        )
        .replace(
            "          - endpoint: mqtt",
            "          - endpoint: web\n            viaBalancer: standby-l7\n            scope: public\n            subdomain: api2\n          - endpoint: mqtt",
        );
    let out = compile_yaml(&yaml);
    let render = render_tree(&out.files);
    assert_eq!(
        render
            .matches("name: ciliumgatewayclassconfigs.cilium.io")
            .count(),
        1,
        "exactly one vendored CRD for two L7 balancers"
    );
    assert!(
        render.contains("name: main-l7-config") && render.contains("name: standby-l7-config"),
        "each balancer keeps its own GatewayClass config object"
    );
}

#[test]
fn cors_single_origin_emits_and_multi_origin_honestly_skips() {
    // Single origin → enforced header; several origins → a joined
    // Access-Control-Allow-Origin is REJECTED by browsers, so we emit
    // nothing and warn instead of shipping declared-but-broken CORS.
    let single = compile_yaml(&V3_TOPOLOGY.replace(
        "corsAllowedOrigins: [\"https://app.example.io\"]",
        "corsAllowedOrigins: [\"https://one.example.io\"]",
    ));
    let render = render_tree(&single.files);
    assert!(render.contains("Access-Control-Allow-Origin"));
    assert!(render.contains("https://one.example.io"));
    assert!(
        !render.contains("https://one.example.io,"),
        "no joined list"
    );

    let multi = compile_yaml(&V3_TOPOLOGY.replace(
        "corsAllowedOrigins: [\"https://app.example.io\"]",
        "corsAllowedOrigins: [\"https://a.example.io\", \"https://b.example.io\"]",
    ));
    let render = render_tree(&multi.files);
    assert!(
        !render.contains("Access-Control-Allow-Origin"),
        "multi-origin must not emit a broken CORS header"
    );
}

#[test]
fn trust_borders_and_limits_are_marked_declared_not_enforced() {
    // Enforcement honesty: fields that the datapath does not enforce must be
    // impossible to mistake for enforced ones.
    let yaml = V3_TOPOLOGY.replace(
        "tls: letsencrypt-http01",
        "tls: letsencrypt-http01\n        trustedProxySource: cloudflare",
    );
    let out = compile_yaml(&yaml);
    let render = render_tree(&out.files);
    assert!(
        render.contains("DECLARED, NOT ENFORCED"),
        "XFF trust border must be honest"
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("DECLARED, not enforced")
                || w.contains("DECLARED")
                || w.contains("not enforced")),
        "trust-border warning expected: {:?}",
        out.warnings
    );
}

#[test]
fn letsencrypt_auto_announces_its_resolution() {
    let out =
        compile_yaml(&V3_TOPOLOGY.replace("tls: letsencrypt-http01", "tls: letsencrypt-auto"));
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("letsencrypt-auto") && w.contains("resolved")),
        "auto tls resolution must be visible: {:?}",
        out.warnings
    );
}

#[test]
fn compile_is_byte_deterministic() {
    let a = compile_yaml(V3_TOPOLOGY);
    let b = compile_yaml(V3_TOPOLOGY);
    assert_eq!(render_tree(&a.files), render_tree(&b.files));
}

#[test]
fn v5_unresolved_via_balancer_fails_fast() {
    let yaml = V3_TOPOLOGY.replace("viaBalancer: mqtt-l4", "viaBalancer: ghost");
    let topo = parse_topology(&yaml).unwrap();
    let err = compile(&topo, &passports(), &Options::dry()).unwrap_err();
    assert!(
        matches!(err, CompileError::UnresolvedBalancer { .. }),
        "{err}"
    );
}

#[test]
fn v5_unknown_provider_fails_fast() {
    let yaml = V3_TOPOLOGY.replace("provider: cilium-envoy", "provider: nginx-custom");
    let topo = parse_topology(&yaml).unwrap();
    let err = compile(&topo, &passports(), &Options::dry()).unwrap_err();
    assert!(
        matches!(err, CompileError::ProviderNotImplemented { .. }),
        "{err}"
    );
}

#[test]
fn v5_unresolved_endpoint_fails_fast() {
    let topo = parse_topology(V3_TOPOLOGY).unwrap();
    let err = compile(&topo, &PassportIndex::default(), &Options::dry()).unwrap_err();
    assert!(
        matches!(err, CompileError::UnresolvedEndpoint { .. }),
        "{err}"
    );
}
