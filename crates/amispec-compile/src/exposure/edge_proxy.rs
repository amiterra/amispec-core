//! External `edge-proxy` providers (`cloudflare`, `fastly`): balancer runs
//! outside the cluster — **no in-cluster balancing objects**. Compiled output
//! is the trust border (`trustedProxySource` → X-Forwarded-For policy) and the
//! documented DNS expectations (Design Doc 0025 §1.3).

use super::cilium_envoy::edge_guard_policies;
use super::registry::{BalancerMaterializer, Materialized};
use super::*;
use crate::CompileError;
use amispec_schema::LoadBalancer;
pub struct EdgeProxy;

impl BalancerMaterializer for EdgeProxy {
    fn activate(&self, ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError> {
        // Balancing happens outside the cluster: nothing to activate in-tree.
        // DNS expectations + trust border are compiled by `edge_policies`.
        Ok(Activation {
            warnings: vec![format!(
                "balancer `{}` ({}) is an external edge proxy — DNS records must \
                 point to the provider; only trust borders are compiled",
                ctx.lb.id, ctx.lb.provider
            )],
            ..Default::default()
        })
    }

    fn routes(&self, _ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        // expose[] never references edge-proxy directly (validator enforces
        // upstreamEdge chaining) — no routes here.
        Ok(Materialized::empty())
    }

    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError> {
        edge_guard_policies(ctx, &ctx.lb.provider)
    }

    fn validate(&self, lb: &LoadBalancer) -> Result<(), CompileError> {
        if lb.layer != "edge-proxy" {
            return Err(CompileError::ProviderLayerMismatch {
                provider: lb.provider.clone(),
                layer: lb.layer.clone(),
                lb_id: lb.id.clone(),
            });
        }
        Ok(())
    }
}
