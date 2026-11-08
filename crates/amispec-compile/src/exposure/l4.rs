//! L4 balancers: `cilium-l4-bgp` (Cilium DSR/Maglev + IP pool) and
//! `k3s-servicelb` (klipper-lb emergency path).
//!
//! L4 exposure entries carry no HTTP fields — the materialized route is a
//! `Service type: LoadBalancer`. Network prereqs (floating IPs, BGP) are
//! **not** applied automatically (Design Doc 0025 §3): the compiler emits a
//! prereq checklist and a warning until node inventory confirms readiness.

use super::cilium_envoy::edge_guard_policies;
use super::registry::{BalancerMaterializer, Materialized};
use super::*;
use crate::CompileError;
use amispec_schema::LoadBalancer;
use serde_json::{Map, Value, json};

pub struct CiliumL4Bgp;
pub struct K3sServiceLb;

/// Cilium Service annotations for DSR + Maglev (`forwardingMode`).
fn forwarding_annotations(ctx: &MaterializeCtx<'_>) -> Map<String, Value> {
    let mut ann = Map::new();
    match ctx
        .lb
        .forwarding_mode
        .as_deref()
        .unwrap_or("ebpf-dsr-maglev")
    {
        "ebpf-dsr-maglev" => {
            ann.insert("service.cilium.io/lb-mode".into(), json!("dsr"));
            ann.insert("service.cilium.io/lb-algorithm".into(), json!("maglev"));
        }
        _ => {
            ann.insert("service.cilium.io/lb-mode".into(), json!("snat"));
        }
    }
    if ctx.lb.proxy_protocol_v2.unwrap_or(false) {
        ann.insert("service.cilium.io/lb-proxy-protocol".into(), json!("v2"));
    }
    if ctx.provenance {
        if let Some(ip) = &ctx.lb.floating_ip_ref {
            ann.insert(LABEL_FLOATING_IP_REF.into(), json!(ip));
        }
    }
    ann
}

impl BalancerMaterializer for CiliumL4Bgp {
    fn activate(&self, ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError> {
        let mut act = Activation::default();
        let labels = lb_labels(&ctx.cluster.id, ctx.lb, STAGE_OPS, ctx.provenance);
        let annotations = lb_annotations(ctx.lb, ctx.provenance, &ctx.resolved_tls());

        // IP pool: selector bound to this balancer's Services. Address blocks
        // come from Day-2 host configuration (`floatingIpRef`, Design Doc 0022)
        // — emitted without blocks plus a prereq checklist (§3).
        let mut pool_spec = Map::new();
        pool_spec.insert(
            "serviceSelector".into(),
            json!({
                "matchLabels": { LABEL_LB_ID: ctx.lb.id }
            }),
        );
        if let Some(ip) = &ctx.lb.floating_ip_ref {
            if ip.contains('/') {
                // floatingIpRef holds a CIDR → usable pool blocks directly.
                pool_spec.insert("cidrs".into(), json!([ip]));
            }
        }
        act.objects.push(json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumLoadBalancerIPPool",
            "metadata": {
                "name": ctx.lb.id,
                "labels": Value::Object(labels.clone()),
                "annotations": Value::Object(annotations.clone()),
            },
            "spec": Value::Object(pool_spec),
        }));

        let mut data = Map::new();
        data.insert(
            "floatingIpRef".into(),
            json!(ctx.lb.floating_ip_ref.clone().unwrap_or_default()),
        );
        data.insert(
            "forwardingMode".into(),
            json!(ctx.lb.forwarding_mode.clone().unwrap_or_default()),
        );
        data.insert(
            "checklist".into(),
            json!(
                "- populate CiliumLoadBalancerIPPool address blocks from floatingIpRef \
                 via Day-2 node inventory (Design Doc 0022)\n\
                 - configure BGP peering on nodes (Design Doc 0022)\n\
                 - confirm Proxy Protocol v2 termination at the upstream path when enabled"
            ),
        );
        act.objects.push(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": format!("{}-l4-prereqs", ctx.lb.id),
                "namespace": GATEWAY_NAMESPACE,
                "labels": Value::Object(labels.clone()),
                "annotations": Value::Object(annotations.clone()),
            },
            "data": data,
        }));

        act.warnings.push(format!(
            "balancer `{}`: L4 network prereqs (floatingIpRef `{}`, BGP) are not \
             applied automatically — see {}-l4-prereqs checklist",
            ctx.lb.id,
            ctx.lb.floating_ip_ref.clone().unwrap_or_default(),
            ctx.lb.id
        ));
        Ok(act)
    }

    fn routes(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        l4_services(ctx, false)
    }

    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        edge_guard_policies(ctx, "cilium-l4-bgp")
    }

    fn validate(&self, lb: &LoadBalancer) -> Result<(), CompileError> {
        if lb.layer != "l4-balancer" {
            return Err(CompileError::ProviderLayerMismatch {
                provider: lb.provider.clone(),
                layer: lb.layer.clone(),
                lb_id: lb.id.clone(),
            });
        }
        Ok(())
    }
}

impl BalancerMaterializer for K3sServiceLb {
    fn activate(&self, _ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError> {
        // Emergency path: no in-cluster activation objects (klipper-lb is
        // provided by k3s when servicelb is enabled).
        Ok(Activation::default())
    }

    fn routes(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        let mut out = l4_services(ctx, true)?;
        out.warnings.push(format!(
            "balancer `{}`: k3s-servicelb (klipper-lb) leaves the headless \
             baseline AND requires ServiceLB to be enabled — the `ami init` \
             baseline disables it, so LoadBalancer IPs stay <pending> until it \
             is re-enabled; emergency/lab path only",
            ctx.lb.id
        ));
        Ok(out)
    }

    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        edge_guard_policies(ctx, "k3s-servicelb")
    }

    fn validate(&self, lb: &LoadBalancer) -> Result<(), CompileError> {
        if lb.layer != "l4-balancer" {
            return Err(CompileError::ProviderLayerMismatch {
                provider: lb.provider.clone(),
                layer: lb.layer.clone(),
                lb_id: lb.id.clone(),
            });
        }
        Ok(())
    }
}

/// L4 route = `Service type: LoadBalancer` per exposure entry.
fn l4_services(
    ctx: &MaterializeCtx<'_>,
    headless_exit: bool,
) -> Result<Materialized, CompileError> {
    let mut out = Materialized::empty();
    for ex in &ctx.exposures {
        let mut labels = route_labels(ex, STAGE_APPS, ctx.provenance);
        if ctx.provenance {
            labels.insert(LABEL_LB_LAYER.into(), json!("l4-balancer"));
            if headless_exit {
                labels.insert(LABEL_HEADLESS_BASE_EXIT.into(), json!("true"));
            }
        }
        let mut annotations = route_annotations(ex, ctx.provenance);
        for (k, v) in forwarding_annotations(ctx) {
            annotations.insert(k, v);
        }
        if headless_exit && ctx.provenance {
            annotations.insert(LABEL_HEADLESS_BASE_EXIT.into(), json!("true"));
        }

        let mut spec = Map::new();
        spec.insert("type".into(), json!("LoadBalancer"));
        // VIP-only reachability: no NodePort leak on every node (zero-step
        // security review — the announced/allocated address is the only path).
        spec.insert("allocateLoadBalancerNodePorts".into(), json!(false));
        spec.insert(
            "selector".into(),
            json!({ "app.kubernetes.io/name": ex.component.id.clone() }),
        );
        spec.insert(
            "ports".into(),
            json!([{
                "name": "data",
                "port": ex.backend_port,
                "targetPort": ex.backend_port,
                "protocol": "TCP",
            }]),
        );

        out.objects.push(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": format!("{}-{}", ex.component.id, ex.expose.endpoint),
                "namespace": ex.component.zone.clone().unwrap_or_else(|| "default".into()),
                "labels": Value::Object(labels),
                "annotations": Value::Object(annotations),
            },
            "spec": Value::Object(spec),
        }));
    }
    Ok(out)
}
