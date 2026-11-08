//! `cilium-ingress` — Ingress API variant of the Cilium L7 provider (Day-1
//! pattern from `configs/uc1/manifests/bootstrap/00-cilium-ingress-config.yaml`).
//!
//! The IngressClass itself is owned by the Cilium chart (`ingressController`
//! activation in the `HelmChartConfig`); compiled Ingresses reference
//! `ingressClassName: cilium` to avoid dual ownership of the class object.

use super::cilium_envoy::{
    cors_filters, edge_guard_policies, listener_hostname, security_policy_gaps,
};
use super::registry::{BalancerMaterializer, Materialized};
use super::*;
use crate::CompileError;
use amispec_schema::LoadBalancer;
use serde_json::{json, Map, Value};

pub struct CiliumIngress;

/// IngressClass managed by the Cilium chart when `ingressController.enabled`.
const INGRESS_CLASS: &str = "cilium";

impl BalancerMaterializer for CiliumIngress {
    fn activate(&self, ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError> {
        let mut act = Activation {
            helm_flags: HelmActivationFlags {
                envoy: true,
                gateway_api: false,
                ingress_controller: true,
                l2_announcements: true,
            },
            ..Default::default()
        };
        let tls = ctx.resolved_tls();
        let labels = lb_labels(&ctx.cluster.id, ctx.lb, STAGE_OPS, ctx.provenance);
        let annotations = lb_annotations(ctx.lb, ctx.provenance, &tls);

        // Class declaration marker (the class object itself is chart-owned).
        act.objects.push(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": format!("{}-ingress-class", ctx.lb.id),
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels.clone()),
                "annotations": Value::Object(annotations.clone()),
            },
            "data": {
                "ingressClassName": INGRESS_CLASS,
                "controllerName": "cilium.io/ingress",
                "note": "IngressClass `cilium` is created by the Cilium chart \
                         (ingressController.enabled via HelmChartConfig)",
            },
        }));

        // cert-manager chain: HTTP-01 solver targets the Ingress class.
        if ctx.strategy.uses_cert_manager() {
            act.objects
                .push(ingress_cluster_issuer(ctx, &annotations, &labels));
            for plan in ctx.listener_plans() {
                let Some(secret) = &plan.secret else { continue };
                if ctx.strategy == TlsStrategy::Custom {
                    continue;
                }
                let (name, dns_names) = match &plan.host {
                    ListenerHost::Wildcard(_) => (
                        format!("{}-wildcard", ctx.lb.id),
                        vec![listener_hostname(&plan.host)],
                    ),
                    ListenerHost::Host(h) => {
                        (format!("{}-{}", ctx.lb.id, host_slug(h)), vec![h.clone()])
                    }
                };
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
                continue;
            };
            let mut labels = route_labels(ex, STAGE_APPS, ctx.provenance);
            if ctx.provenance {
                labels.insert(LABEL_LB_LAYER.into(), json!("l7-gateway"));
            }
            let mut annotations = route_annotations(ex, ctx.provenance);

            // CORS → documented annotation mapping for the Ingress variant.
            let (filters, warnings) = cors_filters(ex);
            if !filters.is_empty() {
                annotations.insert(
                    "amispec.io/cors".into(),
                    json!(ex
                        .expose
                        .security_policy
                        .as_ref()
                        .and_then(|sp| sp.cors_allowed_origins.as_ref())
                        .map(|o| o.join(", "))
                        .unwrap_or_default()),
                );
            }
            out.warnings.extend(warnings);

            let mut rule = Map::new();
            rule.insert("host".into(), json!(host));
            rule.insert(
                "http".into(),
                json!({
                    "paths": [{
                        "path": ex.path,
                        "pathType": "Prefix",
                        "backend": {
                            "service": {
                                "name": ex.component.id,
                                "port": { "number": ex.backend_port },
                            }
                        }
                    }]
                }),
            );

            let mut spec = Map::new();
            spec.insert("ingressClassName".into(), json!(INGRESS_CLASS));
            spec.insert("rules".into(), json!([Value::Object(rule)]));
            if let Some(secret) = tls_secret_for(ctx, &ex.host.clone().unwrap_or_default()) {
                spec.insert(
                    "tls".into(),
                    json!([{ "hosts": [host], "secretName": secret }]),
                );
            }

            out.objects.push(json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": format!("{}-{}", ex.component.id, ex.expose.endpoint),
                    "namespace": ex.component.zone.clone().unwrap_or_else(|| "default".into()),
                    "labels": Value::Object(labels),
                    "annotations": Value::Object(annotations),
                },
                "spec": Value::Object(spec),
            }));
            out.warnings
                .extend(security_policy_gaps(ex, "cilium-ingress"));
        }
        Ok(out)
    }

    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        edge_guard_policies(ctx, "cilium-ingress")
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

/// Secret name backing `spec.tls` of one Ingress host.
fn tls_secret_for(ctx: &MaterializeCtx<'_>, host: &str) -> Option<String> {
    if ctx.strategy == TlsStrategy::None {
        return None;
    }
    let hosts = ctx.hosts();
    let plan = super::listener_plan(&ctx.lb.id, &hosts, &ctx.cluster.domain, ctx.strategy);
    plan.into_iter()
        .find(|p| match &p.host {
            ListenerHost::Host(h) => h == host,
            ListenerHost::Wildcard(w) => {
                let suffix = &w[1..]; // "*.domain" → ".domain"
                host.ends_with(suffix) && host != &suffix[1..]
            }
        })
        .and_then(|p| p.secret)
}

fn ingress_cluster_issuer(
    ctx: &MaterializeCtx<'_>,
    annotations: &Map<String, Value>,
    labels: &Map<String, Value>,
) -> Value {
    let solver = match ctx.strategy {
        TlsStrategy::WildcardDns01 => json!({
            "dns01": {
                "cloudflare": {
                    "apiTokenSecretRef": {
                        "name": format!("{}-dns01-credentials", ctx.lb.id),
                        "key": "api-token",
                    }
                }
            }
        }),
        _ => json!({
            "http01": {
                "ingress": { "class": INGRESS_CLASS }
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
