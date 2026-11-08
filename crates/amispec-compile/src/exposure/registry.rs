//! `BalancerMaterializer` registry: dispatch by `(layer, provider)`
//! (Design Doc 0025 §1.4).
//!
//! New balancers plug in as a new registry entry — the topology schema never
//! changes. Unknown providers fail fast (`provider not implemented`), never a
//! silent stub.

use super::{Activation, MaterializeCtx};
use crate::CompileError;
use crate::exposure::cilium_envoy::CiliumEnvoy;
use crate::exposure::cilium_ingress::CiliumIngress;
use crate::exposure::edge_proxy::EdgeProxy;
use crate::exposure::l4::{CiliumL4Bgp, K3sServiceLb};
use amispec_schema::LoadBalancer;
use serde_json::Value;

/// Compiled objects of one stage plus non-fatal warnings.
#[derive(Debug, Default)]
pub struct Materialized {
    pub objects: Vec<Value>,
    pub warnings: Vec<String>,
}

impl Materialized {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// A balancer provider: turns `loadBalancers[]` + resolved `expose[]` into
/// cluster objects (Design Doc 0025 §1.3–1.6).
pub trait BalancerMaterializer {
    /// Stage 02: activation (Helm flags), Gateway/TLS chain, L4 prereqs.
    fn activate(&self, ctx: &MaterializeCtx<'_>) -> Result<Activation, CompileError>;

    /// Stage 05: routes and their backend Services.
    fn routes(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError>;

    /// Stage 06: edge policies (scope guards, trust borders).
    fn edge_policies(&self, ctx: &MaterializeCtx<'_>) -> Result<Materialized, CompileError>;

    /// Provider-level fail-fast checks on the balancer declaration.
    fn validate(&self, lb: &LoadBalancer) -> Result<(), CompileError>;
}

/// Registry lookup by `(layer, provider)`.
///
/// Implemented pairs:
/// `cilium-envoy`@`l7-gateway`, `cilium-ingress`@`l7-gateway`,
/// `cilium-l4-bgp`@`l4-balancer`, `k3s-servicelb`@`l4-balancer`,
/// `cloudflare`/`fastly`@`edge-proxy`.
pub fn materializer_for(
    lb: &LoadBalancer,
) -> Result<&'static dyn BalancerMaterializer, CompileError> {
    match (lb.layer.as_str(), lb.provider.as_str()) {
        ("l7-gateway", "cilium-envoy") => Ok(&CiliumEnvoy),
        ("l7-gateway", "cilium-ingress") => Ok(&CiliumIngress),
        ("l4-balancer", "cilium-l4-bgp") => Ok(&CiliumL4Bgp),
        ("l4-balancer", "k3s-servicelb") => Ok(&K3sServiceLb),
        ("edge-proxy", "cloudflare") | ("edge-proxy", "fastly") => Ok(&EdgeProxy),
        (layer, provider) => {
            let known_provider = matches!(
                provider,
                "cilium-envoy"
                    | "cilium-ingress"
                    | "cilium-l4-bgp"
                    | "k3s-servicelb"
                    | "cloudflare"
                    | "fastly"
            );
            if !known_provider {
                Err(CompileError::ProviderNotImplemented {
                    provider: provider.to_string(),
                    layer: layer.to_string(),
                    lb_id: lb.id.clone(),
                })
            } else {
                Err(CompileError::ProviderLayerMismatch {
                    provider: provider.to_string(),
                    layer: layer.to_string(),
                    lb_id: lb.id.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::registry::materializer_for;

    fn lb(layer: &str, provider: &str) -> LoadBalancer {
        LoadBalancer {
            id: "test-lb".into(),
            layer: layer.into(),
            provider: provider.into(),
            upstream_edge: None,
            trusted_proxy_source: None,
            forwarding_mode: None,
            floating_ip_ref: None,
            proxy_protocol_v2: None,
            http3_quic: None,
            tls: None,
            vip_reachability: None,
        }
    }

    #[test]
    fn dispatches_known_pairs() {
        assert!(materializer_for(&lb("l7-gateway", "cilium-envoy")).is_ok());
        assert!(materializer_for(&lb("l7-gateway", "cilium-ingress")).is_ok());
        assert!(materializer_for(&lb("l4-balancer", "cilium-l4-bgp")).is_ok());
        assert!(materializer_for(&lb("l4-balancer", "k3s-servicelb")).is_ok());
        assert!(materializer_for(&lb("edge-proxy", "cloudflare")).is_ok());
        assert!(materializer_for(&lb("edge-proxy", "fastly")).is_ok());
    }

    #[test]
    fn unknown_provider_fails_fast() {
        let err = match materializer_for(&lb("l7-gateway", "nginx-custom")) {
            Err(e) => e,
            Ok(_) => panic!("unknown provider must fail fast"),
        };
        assert!(
            matches!(err, CompileError::ProviderNotImplemented { .. }),
            "{err}"
        );
    }

    #[test]
    fn layer_mismatch_fails_fast() {
        let err = match materializer_for(&lb("l4-balancer", "cilium-envoy")) {
            Err(e) => e,
            Ok(_) => panic!("layer mismatch must fail fast"),
        };
        assert!(
            matches!(err, CompileError::ProviderLayerMismatch { .. }),
            "{err}"
        );
    }
}
