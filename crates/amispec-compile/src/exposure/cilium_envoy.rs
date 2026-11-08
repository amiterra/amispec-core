//! `cilium-envoy` — default L7 provider: Cilium Envoy + Gateway API
//! (Design Doc 0025 §1.3). Zero new dependencies: the materialization runs on
//! the same eBPF datapath as the headless baseline.

use super::registry::{BalancerMaterializer, Materialized};
use super::*;
use crate::CompileError;
use amispec_schema::LoadBalancer;
use serde_json::json;

pub struct CiliumEnvoy;

/// Gateway API `controllerName` of the Cilium Gateway controller (canonical
/// form `domain/path` — the Gateway API CRD rejects bare domains).
const CONTROLLER_NAME: &str = "io.cilium/gateway-controller";

/// Vendored `CiliumGatewayClassConfig` CRD, one per cluster (deduped in
/// [`super::materialize`]). Schema is the official Cilium one (see the asset
/// header for source and why it is vendored at all).
pub(crate) fn cilium_gateway_class_config_crd() -> Value {
    let raw = include_str!("../../assets/ciliumgatewayclassconfigs-crd.yaml");
    let mut crd: Value =
        serde_yaml::from_str(raw).expect("vendored CiliumGatewayClassConfig CRD is valid YAML");
    let meta = crd
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .expect("CRD has metadata");
    meta.insert("labels".into(), json!({ LABEL_STAGE: STAGE_OPS }));
    meta.insert(
        "annotations".into(),
        json!({
            "amispec.io/crd-vendored":
                "cilium chart ships no CRDs and cilium-operator does not install \
                 this one; vendored so Flux dry-run can pass"
        }),
    );
    crd
}

impl BalancerMaterializer for CiliumEnvoy {
    fn activate(&self, ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError> {
        let mut act = Activation {
            helm_flags: HelmActivationFlags {
                envoy: true,
                gateway_api: true,
                ingress_controller: false,
                // L2 announcements are decided centrally from the DECLARED
                // `vipReachability` (Design Doc 0025 §3.11) — never here.
                l2_announcements: false,
            },
            ..Default::default()
        };
        let tls = ctx.resolved_tls();
        if ctx.lb.tls.as_deref() == Some("letsencrypt-auto") {
            act.warnings.push(format!(
                "balancer `{}`: tls `letsencrypt-auto` resolved to `{tls}` \
                 (recorded in amispec.io/tls-mode-resolved) — set tls explicitly \
                 to avoid silent mode changes when exposures grow",
                ctx.lb.id
            ));
        }
        let labels = lb_labels(&ctx.cluster.id, ctx.lb, STAGE_OPS, ctx.provenance);
        let annotations = lb_annotations(ctx.lb, ctx.provenance, &tls);

        // NodePort closure: the generated gateway Service must not open a
        // NodePort on every node — otherwise the VIP story ("reachable via the
        // announced address / the edge") is a lie and any LAN client can enter
        // via <node>:<nodePort> (zero-step security review).
        //
        // Prerequisite first: the Cilium chart ships no CRDs and cilium-operator
        // does not install this one, so without the vendored CRD the whole
        // Flux kustomization dies in dry-run ("no matches for kind") —
        // see assets/ciliumgatewayclassconfigs-crd.yaml. `materialize` dedupes
        // the CRD across balancers.
        act.objects.push(cilium_gateway_class_config_crd());
        act.objects.push(json!({
            "apiVersion": "cilium.io/v2alpha1",
            "kind": "CiliumGatewayClassConfig",
            "metadata": {
                "name": format!("{}-config", ctx.lb.id),
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels.clone()),
            },
            "spec": {
                "service": { "allocateLoadBalancerNodePorts": false },
            },
        }));

        // GatewayClass: the real Cilium controller (not a stub), parameterised
        // by the config above.
        act.objects.push(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayClass",
            "metadata": {
                "name": ctx.lb.id,
                "labels": Value::Object(labels.clone()),
                "annotations": Value::Object(annotations.clone()),
            },
            "spec": {
                "controllerName": CONTROLLER_NAME,
                "parametersRef": {
                    "group": "cilium.io",
                    "kind": "CiliumGatewayClassConfig",
                    "name": format!("{}-config", ctx.lb.id),
                    "namespace": GATEWAY_NAMESPACE,
                },
            },
        }));

        // Gateway with listeners derived from hostname/subdomain (§1.5).
        // Routes live in component zone namespaces (dmz, …) while the Gateway
        // is centralized in flux-system; attachment is limited to EXACTLY the
        // namespaces this balancer serves (never `All`): a compromised workload
        // in any other namespace must not be able to claim hostnames on the
        // edge — especially with our wildcard certificate in play.
        let allowed = json!({
            "allowedRoutes": allowed_routes_for(ctx)
        });
        let mut listeners: Vec<Value> = Vec::new();
        for plan in ctx.listener_plans() {
            let hostname = listener_hostname(&plan.host);
            let mut http = json!({
                "name": listener_name(&plan.host, "http"),
                "protocol": "HTTP",
                "port": 80,
                "hostname": hostname,
            });
            http.as_object_mut().unwrap().insert(
                "allowedRoutes".into(),
                allowed.get("allowedRoutes").unwrap().clone(),
            );
            listeners.push(http);
            if let Some(secret) = &plan.secret {
                let mut https = json!({
                    "name": listener_name(&plan.host, "https"),
                    "protocol": "HTTPS",
                    "port": 443,
                    "hostname": hostname,
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "kind": "Secret", "name": secret }],
                    },
                });
                https.as_object_mut().unwrap().insert(
                    "allowedRoutes".into(),
                    allowed.get("allowedRoutes").unwrap().clone(),
                );
                listeners.push(https);
            }
        }
        act.objects.push(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {
                "name": ctx.lb.id,
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels.clone()),
                "annotations": Value::Object(annotations.clone()),
            },
            "spec": {
                "gatewayClassName": ctx.lb.id,
                "listeners": listeners,
            },
        }));

        // TLS chain: ClusterIssuer + Certificates (cert-manager chain itself
        // is cluster-shared and emitted by the orchestrator).
        if ctx.strategy.uses_cert_manager() {
            act.objects.push(cluster_issuer(
                ctx,
                &annotations,
                &labels,
                &mut act.warnings,
            ));
            for plan in ctx.listener_plans() {
                let Some(secret) = &plan.secret else { continue };
                let (name, dns_names) = match &plan.host {
                    ListenerHost::Wildcard(_) => (
                        format!("{}-wildcard", ctx.lb.id),
                        vec![listener_hostname(&plan.host)],
                    ),
                    ListenerHost::Host(h) => {
                        (format!("{}-{}", ctx.lb.id, host_slug(h)), vec![h.clone()])
                    }
                };
                if ctx.strategy == TlsStrategy::Custom {
                    continue; // pre-provisioned Secret, never compiled (ADR 0009)
                }
                act.objects.push(json!({
                    "apiVersion": "cert-manager.io/v1",
                    "kind": "Certificate",
                    "metadata": {
                        "name": name,
                        "namespace": GATEWAY_NAMESPACE,
                        "labels": Value::Object(labels.clone()),
                        "annotations": Value::Object(annotations.clone()),
                    },
                    "spec": {
                        "secretName": secret,
                        "dnsNames": dns_names,
                        "issuerRef": { "kind": "ClusterIssuer", "name": ctx.lb.id },
                    },
                }));
            }
        }
        Ok(act)
    }

    fn routes(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        let mut out = Materialized::empty();
        for ex in &ctx.exposures {
            let Some(host) = &ex.host else {
                continue; // L7 routes need a host
            };
            let mut labels = route_labels(ex, STAGE_APPS, ctx.provenance);
            if ctx.provenance {
                labels.insert(LABEL_LB_LAYER.into(), json!("l7-gateway"));
            }
            let annotations = route_annotations(ex, ctx.provenance);

            let mut rule = serde_json::Map::new();
            rule.insert(
                "matches".into(),
                json!([{ "path": { "type": "PathPrefix", "value": ex.path } }]),
            );
            let (filters, warnings) = cors_filters(ex);
            out.warnings.extend(warnings);
            if !filters.is_empty() {
                rule.insert("filters".into(), Value::Array(filters));
            }
            rule.insert(
                "backendRefs".into(),
                json!([{ "name": ex.component.id, "port": ex.backend_port }]),
            );

            // Multi-via exposes compile one route per balancer — suffix keeps
            // object names unique across those routes.
            let route_name = if ex.expose.via_balancer.ids().len() > 1 {
                format!("{}-{}-{}", ex.component.id, ex.expose.endpoint, ctx.lb.id)
            } else {
                format!("{}-{}", ex.component.id, ex.expose.endpoint)
            };
            out.objects.push(json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "HTTPRoute",
                "metadata": {
                    "name": route_name,
                    "namespace": ex.component.zone.clone().unwrap_or_else(|| "default".into()),
                    "labels": Value::Object(labels),
                    "annotations": Value::Object(annotations),
                },
                "spec": {
                    "hostnames": [host],
                    "parentRefs": [{ "name": ctx.lb.id, "namespace": GATEWAY_NAMESPACE }],
                    "rules": [Value::Object(rule)],
                },
            }));

            out.warnings
                .extend(security_policy_gaps(ex, "cilium-envoy"));
        }
        Ok(out)
    }

    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        edge_guard_policies(ctx, "cilium-envoy")
    }

    fn validate(&self, lb: &LoadBalancer) -> Result<(), CompileError> {
        if lb.layer != "l7-gateway" {
            return Err(CompileError::ProviderLayerMismatch {
                provider: lb.provider.clone(),
                layer: lb.layer.clone(),
                lb_id: lb.id.clone(),
            });
        }
        Ok(())
    }
}

/// `allowedRoutes` for the balancer's listeners: only the namespaces its
/// exposures live in may attach routes (`kubernetes.io/metadata.name` is an
/// auto-label present on every namespace, incl. `default`).
pub fn allowed_routes_for(ctx: &MaterializeCtx<'_>) -> Value {
    let mut namespaces: Vec<String> = ctx
        .exposures
        .iter()
        .map(|e| {
            e.component
                .zone
                .clone()
                .unwrap_or_else(|| "default".to_string())
        })
        .collect();
    namespaces.sort();
    namespaces.dedup();
    json!({
        "namespaces": {
            "from": "Selector",
            "selector": {
                "matchExpressions": [{
                    "key": "kubernetes.io/metadata.name",
                    "operator": "In",
                    "values": namespaces,
                }]
            }
        }
    })
}

/// Listener display hostname (`*.<domain>` or the host itself).
pub fn listener_hostname(host: &ListenerHost) -> String {
    match host {
        ListenerHost::Wildcard(w) => w.clone(),
        ListenerHost::Host(h) => h.clone(),
    }
}

/// Gateway listener name: DNS label, unique per listener pair.
pub fn listener_name(host: &ListenerHost, proto: &str) -> String {
    let base = match host {
        ListenerHost::Wildcard(_) => "wildcard".to_string(),
        ListenerHost::Host(h) => {
            let s = host_slug(h);
            s.chars().take(48).collect::<String>()
        }
    };
    format!("{base}-{proto}")
}

/// ACME ClusterIssuer for the balancer (per-host HTTP-01 or DNS-01 wildcard).
fn cluster_issuer(
    ctx: &MaterializeCtx<'_>,
    annotations: &Map<String, Value>,
    labels: &Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Value {
    let solver = match ctx.strategy {
        TlsStrategy::WildcardDns01 => {
            // DNS-01 needs provider credentials: Secret reference only — the
            // compiler never emits secret values (ADR 0009). Provider type is
            // not modeled in the schema yet; Cloudflare-shaped solver is the
            // documented default (Design Doc 0025 decisions).
            warnings.push(format!(
                "balancer `{}`: DNS-01 solver assumes a Cloudflare API token in \
                 Secret `{lb}-dns01-credentials` (SOPS-managed); patch the \
                 ClusterIssuer solver for other DNS providers (documented gap)",
                ctx.lb.id,
                lb = ctx.lb.id
            ));
            json!({
                "dns01": {
                    "cloudflare": {
                        "apiTokenSecretRef": {
                            "name": format!("{}-dns01-credentials", ctx.lb.id),
                            "key": "api-token",
                        }
                    }
                }
            })
        }
        _ => json!({
            "http01": {
                "gatewayHTTPRoute": {
                    "parentRefs": [{
                        "name": ctx.lb.id,
                        "namespace": GATEWAY_NAMESPACE,
                        "kind": "Gateway",
                    }]
                }
            }
        }),
    };
    json!({
        "apiVersion": "cert-manager.io/v1",
        "kind": "ClusterIssuer",
        "metadata": {
            "name": ctx.lb.id,
            "labels": Value::Object(labels.clone()),
            "annotations": Value::Object(annotations.clone()),
        },
        "spec": {
            "acme": {
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "privateKeySecretRef": { "name": format!("{}-acme-account", ctx.lb.id) },
                "solvers": [solver],
            }
        }
    })
}

/// CORS → Gateway API `ResponseHeaderModifier` filters (§1.5).
pub fn cors_filters(ex: &ResolvedExposure<'_>) -> (Vec<Value>, Vec<String>) {
    let mut warnings = Vec::new();
    let Some(sp) = &ex.expose.security_policy else {
        return (Vec::new(), warnings);
    };
    let Some(origins) = &sp.cors_allowed_origins else {
        return (Vec::new(), warnings);
    };
    if origins.is_empty() {
        return (Vec::new(), warnings);
    }
    if origins.len() > 1 {
        // A static Access-Control-Allow-Origin may carry exactly one origin;
        // a joined list is REJECTED by browsers — emitting it would be a
        // declared-but-broken CORS. Skip the header and say so (enforcement
        // honesty: nothing is claimed that does not work).
        warnings.push(format!(
            "expose {}/{}: corsAllowedOrigins has {} origins — static CORS headers \
             support exactly one (browsers reject joined values); emit nothing and              enforce multi-origin CORS in the application (documented gap)",
            ex.component.id,
            ex.expose.endpoint,
            origins.len()
        ));
        return (Vec::new(), warnings);
    }
    let filter = json!({
        "type": "ResponseHeaderModifier",
        "responseHeaderModifier": {
            "set": [
                { "name": "Access-Control-Allow-Origin", "value": origins[0].clone() },
                { "name": "Access-Control-Allow-Methods", "value": "GET, POST, PUT, PATCH, DELETE, OPTIONS" },
                { "name": "Access-Control-Allow-Headers", "value": "Authorization, Content-Type" },
            ]
        }
    });
    (vec![filter], warnings)
}

/// Documented enforcement gaps of `securityPolicy` fields (§1.5).
pub fn security_policy_gaps(ex: &ResolvedExposure<'_>, provider: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(sp) = &ex.expose.security_policy else {
        return warnings;
    };
    if sp.rate_limit_rps.is_some() {
        warnings.push(format!(
            "expose {}/{}: rateLimitRps is carried as contract annotation only — \
             `{provider}` exposes no stable rate-limit API on standard Gateway \
             CRDs (documented gap; see Design Doc 0025 §1.5)",
            ex.component.id, ex.expose.endpoint
        ));
    }
    if sp.client_auth.as_deref() == Some("mtls") {
        warnings.push(format!(
            "expose {}/{}: clientAuth `mtls` requires listener frontendValidation \
             (experimental Gateway API channel) — carried as contract annotation \
             only (documented gap)",
            ex.component.id, ex.expose.endpoint
        ));
    }
    warnings
}

/// Shared stage-06 artifacts: `scope: protected` ingress guards + trust
/// borders for `trustedProxySource` (§1.5).
pub fn edge_guard_policies(
    ctx: &MaterializeCtx<'_>,
    provider: &str,
) -> Result<Materialized, CompileError> {
    let mut out = Materialized::empty();
    let mut guarded: Vec<&str> = Vec::new();
    for ex in &ctx.exposures {
        if ex.expose.scope != "protected" {
            continue;
        }
        if guarded.contains(&ex.component.id.as_str()) {
            continue;
        }
        guarded.push(&ex.component.id);
        let mut labels = route_labels(ex, STAGE_TRUST, ctx.provenance);
        if ctx.provenance {
            labels.insert(LABEL_SCOPE.into(), json!("protected"));
        }
        // Top-level guard: external traffic may only arrive through the
        // balancer dataplane (`ingress` entity); east-west stays on `cluster`.
        out.objects.push(json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": format!("{}-{}-edge-guard", ctx.cluster.id, ex.component.id),
                "namespace": ex.component.zone.clone().unwrap_or_else(|| "default".into()),
                "labels": Value::Object(labels),
            },
            "spec": {
                "endpointSelector": {
                    "matchLabels": { "app.kubernetes.io/name": ex.component.id.clone() }
                },
                "ingress": [{ "fromEntities": ["cluster", "ingress"] }],
            },
        }));
        out.warnings.extend(security_policy_gaps(ex, provider));
    }

    // Trust border for external edge proxies in front of this balancer.
    if ctx.lb.trusted_proxy_source.is_some() {
        out.warnings.push(format!(
            "balancer `{}`: trustedProxySource is a DECLARED trust border — \
             X-Forwarded-For acceptance is not enforced by the compiled datapath \
             (see {}-trust contract); spoofed XFF is not filtered yet",
            ctx.lb.id, ctx.lb.id
        ));
    }
    if let Some(tp) = &ctx.lb.trusted_proxy_source {
        let labels = lb_labels(&ctx.cluster.id, ctx.lb, STAGE_TRUST, ctx.provenance);
        let annotations = lb_annotations(ctx.lb, ctx.provenance, &ctx.resolved_tls());
        let hosts = ctx.hosts();
        out.objects.push(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": format!("{}-trust", ctx.lb.id),
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels),
                "annotations": Value::Object(annotations),
            },
            "data": {
                "provider": provider,
                "trustedProxySource": serde_json::to_string(tp).unwrap_or_else(|_| "null".into()),
                "xffPolicy": "DECLARED, NOT ENFORCED: X-Forwarded-For trust is not \
                              compiled into the datapath; enforce it at the edge \
                              provider or via gatewayAPI xffNumTrustedHops (Day-2) \
                              before relying on client IPs (Design Doc 0025 §1.5)",
                "dnsExpectations": hosts.join("\n"),
            },
        }));
    }

    // DNS expectations of an `upstreamEdge` chain (external edge in front).
    if let Some(upstream) = &ctx.lb.upstream_edge {
        let labels = lb_labels(&ctx.cluster.id, ctx.lb, STAGE_TRUST, ctx.provenance);
        let annotations = lb_annotations(ctx.lb, ctx.provenance, &ctx.resolved_tls());
        let hosts = ctx.hosts();
        out.objects.push(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": format!("{}-edge-dns", ctx.lb.id),
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels),
                "annotations": Value::Object(annotations),
            },
            "data": {
                "upstreamEdge": upstream,
                "hosts": hosts.join("\n"),
                "expectation": "each host MUST resolve through the edge provider \
                                to the cluster entrypoint; ACME HTTP-01 must reach \
                                the cluster (prefer letsencrypt-dns01-wildcard \
                                behind an edge)",
            },
        }));
    }
    Ok(out)
}
