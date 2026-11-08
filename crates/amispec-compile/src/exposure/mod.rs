//! Topology-driven external exposure: provider registry and materialization
//! (Design Doc 0025 §1.3–1.7).
//!
//! `expose[]` / `loadBalancers[]` entries resolve to a *materialization
//! package* per referenced balancer:
//!
//! * [`registry::BalancerMaterializer::activate`] → stage 02 (Cilium L7
//!   activation, Gateway/TLS chain, L4 prereqs),
//! * [`registry::BalancerMaterializer::routes`] → stage 05 (HTTPRoute /
//!   Ingress / L4 Service + backend Services),
//! * [`registry::BalancerMaterializer::edge_policies`] → stage 06 (scope
//!   guards, trust borders).
//!
//! Trigger invariant: with `Σ expose[] == 0` nothing here runs and the tree
//! contains **zero** balancing objects (headless baseline preserved).

pub mod registry;

mod cilium_envoy;
mod cilium_ingress;
mod edge_proxy;
mod l4;

use amispec_schema::{Cluster, ComponentInstance, Expose, LoadBalancer};
use registry::materializer_for;

pub use registry::BalancerMaterializer;

use crate::CompileError;
use crate::passport::{PassportIndex, PassportSummary};
use crate::provenance::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Namespace of the compiled Gateway objects (Flux control plane).
pub const GATEWAY_NAMESPACE: &str = "flux-system";
/// Namespace of cert-manager (only materialized when `tls != none`).
pub const CERT_MANAGER_NAMESPACE: &str = "cert-manager";
/// Secret name suffix for TLS secrets (`<lb-id>-tls`).
pub const TLS_SECRET_SUFFIX: &str = "tls";
/// Pinned cert-manager chart version compiled into the HelmRelease.
pub const CERT_MANAGER_CHART_VERSION: &str = "v1.16.2";

/// Stage directory: operators & networking (activation, gateways, TLS chain).
pub const STAGE_OPS: &str = "02-operators-and-networking";
/// Stage directory: applications (routes, backend Services).
pub const STAGE_APPS: &str = "05-applications";
/// Stage directory: zero-trust & observability (edge policies).
pub const STAGE_TRUST: &str = "06-zero-trust-and-observability";

/// One `expose[]` entry after resolution (host/port contract closed).
#[derive(Debug, Clone)]
pub struct ResolvedExposure<'a> {
    pub cluster: &'a Cluster,
    pub component: &'a ComponentInstance,
    pub expose: &'a Expose,
    pub balancer: &'a LoadBalancer,
    /// Effective host for L7 routes (`None` for L4 exposure).
    pub host: Option<String>,
    /// How the host was derived (provenance for round-trip).
    pub host_source: &'static str,
    /// Effective path prefix (`/` by default).
    pub path: String,
    /// Backend port from the passport endpoint contract (ADR 0009).
    pub backend_port: u16,
    /// `id@version-rev` passport pin of the component.
    pub pin: String,
}

/// TLS certificate strategy actually compiled for a balancer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsStrategy {
    /// `tls: none` — plaintext listeners.
    None,
    /// `custom-secret` — certificateRefs to pre-provisioned Secrets.
    Custom,
    /// Per-host certificates via ACME HTTP-01.
    PerHostHttp01,
    /// Wildcard certificate `*.<cluster.domain>` via ACME DNS-01.
    WildcardDns01,
}

impl TlsStrategy {
    pub fn uses_cert_manager(self) -> bool {
        matches!(self, Self::PerHostHttp01 | Self::WildcardDns01)
    }
}

/// Resolve every `expose[]` of a cluster: balancer lookup, host expansion and
/// backend port from the passport endpoint contract.
///
/// Fail-fast (Design Doc 0025 §2.3): an unresolvable `viaBalancer` or a
/// missing endpoint contract aborts compilation — the compiler never falls
/// back to a hardcoded port.
pub fn resolve_exposures<'a>(
    cluster: &'a Cluster,
    passports: &PassportIndex,
) -> Result<Vec<ResolvedExposure<'a>>, CompileError> {
    let mut out = Vec::new();
    for comp in &cluster.components {
        let pin = crate::passport_pin(&comp.passport, &comp.version, comp.passport_rev);
        let summary = passports.get(&comp.passport);
        for ex in &comp.expose {
            let via_ids = ex.via_balancer.ids();
            // Multi-via is an L7 HA story (several edge Gateways); an L4
            // exposure names exactly one balancer (one LB Service per edge).
            if via_ids.len() > 1 {
                let l4 = via_ids.iter().any(|id| {
                    cluster
                        .load_balancers
                        .iter()
                        .find(|lb| lb.id == *id)
                        .is_some_and(|lb| lb.layer != "l7-gateway")
                });
                if l4 {
                    return Err(CompileError::MultiViaOnL4 {
                        endpoint: ex.endpoint.clone(),
                        component: comp.id.clone(),
                    });
                }
            }
            for via_id in via_ids {
                let balancer = cluster
                    .load_balancers
                    .iter()
                    .find(|lb| lb.id == via_id)
                    .ok_or_else(|| CompileError::UnresolvedBalancer {
                        via_balancer: via_id.to_string(),
                        cluster: cluster.id.clone(),
                    })?;

                let backend_port = resolve_port(summary, comp, ex)?;

                let l7 = balancer.layer == "l7-gateway";
                let (host, host_source) = if l7 {
                    (Some(effective_host(comp, cluster, ex)), host_source(ex))
                } else {
                    (None, "none")
                };

                out.push(ResolvedExposure {
                    cluster,
                    component: comp,
                    expose: ex,
                    balancer,
                    host,
                    host_source,
                    path: effective_path(ex),
                    backend_port,
                    pin: pin.clone(),
                });
            }
        }
    }
    Ok(out)
}

fn resolve_port(
    summary: Option<&PassportSummary>,
    comp: &ComponentInstance,
    ex: &Expose,
) -> Result<u16, CompileError> {
    let Some(summary) = summary else {
        return Err(CompileError::UnresolvedEndpoint {
            component: comp.id.clone(),
            endpoint: ex.endpoint.clone(),
            passport: comp.passport.clone(),
            reason: "passport not loaded — pass its contract to the compiler \
                     (amispec compile --passport …)"
                .into(),
        });
    };
    summary
        .endpoint_port(&ex.endpoint)
        .ok_or_else(|| CompileError::UnresolvedEndpoint {
            component: comp.id.clone(),
            endpoint: ex.endpoint.clone(),
            passport: comp.passport.clone(),
            reason: format!(
                "passport `{}` has no interfaces.endpoints[].name `{}`",
                comp.passport, ex.endpoint
            ),
        })
}

/// Effective host (Design Doc 0025 §1.5): `hostname` as-is, else
/// `<subdomain>.<cluster.domain>`, else `<component-id>.<domain>`.
pub fn effective_host(comp: &ComponentInstance, cluster: &Cluster, ex: &Expose) -> String {
    if let Some(h) = ex.hostname.as_deref() {
        return h.to_string();
    }
    if let Some(s) = ex.subdomain.as_deref() {
        return format!("{s}.{}", cluster.domain);
    }
    format!("{}.{}", comp.id, cluster.domain)
}

fn host_source(ex: &Expose) -> &'static str {
    if ex.hostname.is_some() {
        "hostname"
    } else if ex.subdomain.is_some() {
        "subdomain"
    } else {
        "default"
    }
}

/// Effective path prefix (`/` by default).
pub fn effective_path(ex: &Expose) -> String {
    ex.path_prefix.clone().unwrap_or_else(|| "/".into())
}

/// TLS certificate strategy for a balancer (Design Doc 0025 §1.6).
pub fn tls_strategy(lb: &LoadBalancer, exposures: &[&ResolvedExposure<'_>]) -> TlsStrategy {
    let has_subdomain = exposures.iter().any(|e| e.expose.subdomain.is_some());
    match lb.tls.as_deref().unwrap_or("none") {
        "none" | "" => TlsStrategy::None,
        "custom-secret" => TlsStrategy::Custom,
        "letsencrypt-http01" => TlsStrategy::PerHostHttp01,
        "letsencrypt-dns01-wildcard" => TlsStrategy::WildcardDns01,
        // letsencrypt-auto: wildcard when subdomains exist, else HTTP-01
        // (the resolution is fixed in provenance — Design Doc 0025 §1.6).
        _ => {
            if has_subdomain {
                TlsStrategy::WildcardDns01
            } else {
                TlsStrategy::PerHostHttp01
            }
        }
    }
}

/// Resolved tls mode string recorded in provenance (`letsencrypt-auto` folds
/// into the concrete mode it resolved to).
pub fn resolved_tls_label(lb: &LoadBalancer, strategy: TlsStrategy) -> String {
    match lb.tls.as_deref().unwrap_or("none") {
        "letsencrypt-auto" => match strategy {
            TlsStrategy::WildcardDns01 => "letsencrypt-dns01-wildcard".into(),
            _ => "letsencrypt-http01".into(),
        },
        other => other.to_string(),
    }
}

/// Host partition for listener generation: strict subdomains of
/// `cluster.domain` (wildcard-listener candidates) vs apex/external hosts.
pub fn partition_hosts(hosts: &[String], cluster_domain: &str) -> (Vec<String>, Vec<String>) {
    let suffix = format!(".{cluster_domain}");
    let mut subdomains = Vec::new();
    let mut external = Vec::new();
    for h in hosts {
        if h.ends_with(&suffix) && *h != cluster_domain {
            subdomains.push(h.clone());
        } else {
            external.push(h.clone());
        }
    }
    subdomains.sort();
    subdomains.dedup();
    external.sort();
    external.dedup();
    (subdomains, external)
}

/// Listener hostname rules: one wildcard `*.<domain>` when several strict
/// subdomains share the cluster domain, otherwise one listener per host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerHost {
    Wildcard(String),
    Host(String),
}

/// Compute listener hostnames for a balancer's exposure set.
pub fn listener_hosts(hosts: &[String], cluster_domain: &str) -> Vec<ListenerHost> {
    let (subdomains, external) = partition_hosts(hosts, cluster_domain);
    let mut out = Vec::new();
    if subdomains.len() > 1 {
        out.push(ListenerHost::Wildcard(format!("*.{cluster_domain}")));
    } else {
        for h in subdomains {
            out.push(ListenerHost::Host(h));
        }
    }
    for h in external {
        out.push(ListenerHost::Host(h));
    }
    out
}

/// DNS-1123-ish slug for object names derived from hosts.
pub fn host_slug(host: &str) -> String {
    let s: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .to_ascii_lowercase();
    let trimmed = s.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "host".into()
    } else {
        trimmed
    }
}

/// Per-listener TLS plan: hostname + expected Secret (when TLS is on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerPlan {
    pub host: ListenerHost,
    /// Secret name the listener/certificate references (`None` = plaintext).
    pub secret: Option<String>,
}

/// Secret name contract for a listener host (Design Doc 0025 §1.6):
/// wildcard → `<lb-id>-tls`, per host → `<lb-id>-<host-slug>-tls`.
pub fn listener_secret_name(lb_id: &str, host: &ListenerHost) -> String {
    match host {
        ListenerHost::Wildcard(_) => format!("{lb_id}-{TLS_SECRET_SUFFIX}"),
        ListenerHost::Host(h) => format!("{lb_id}-{}-{TLS_SECRET_SUFFIX}", host_slug(h)),
    }
}

/// Listener plan for a balancer's hosts.
///
/// `PerHostHttp01` forces per-host listeners (HTTP-01 cannot issue wildcard
/// certificates); the other strategies use the wildcard partition.
pub fn listener_plan(
    lb_id: &str,
    hosts: &[String],
    cluster_domain: &str,
    strategy: TlsStrategy,
) -> Vec<ListenerPlan> {
    let planned: Vec<ListenerHost> = if strategy == TlsStrategy::PerHostHttp01 {
        let mut all = hosts.to_vec();
        all.sort();
        all.dedup();
        all.into_iter().map(ListenerHost::Host).collect()
    } else {
        listener_hosts(hosts, cluster_domain)
    };
    planned
        .into_iter()
        .map(|host| ListenerPlan {
            secret: match strategy {
                TlsStrategy::None => None,
                _ => Some(listener_secret_name(lb_id, &host)),
            },
            host,
        })
        .collect()
}

/// Stage-02 activation of one balancer: cluster-mergeable Helm flags plus
/// the objects this provider contributes.
#[derive(Debug, Default)]
pub struct Activation {
    pub helm_flags: HelmActivationFlags,
    pub objects: Vec<Value>,
    pub warnings: Vec<String>,
}

/// Compile everything exposure-related for one cluster.
///
/// Returns per-stage object bundles plus cluster-level warnings; empty
/// bundles mean zero balancing artifacts (no exposure).
pub fn materialize(
    cluster: &Cluster,
    exposures: &[ResolvedExposure<'_>],
    provenance: bool,
) -> Result<ExposureArtifacts, CompileError> {
    let mut artifacts = ExposureArtifacts::default();
    if exposures.is_empty() {
        return Ok(artifacts);
    }

    // group exposures by balancer id (BTreeMap → deterministic order)
    let mut by_balancer: BTreeMap<String, Vec<&ResolvedExposure<'_>>> = BTreeMap::new();
    for ex in exposures {
        by_balancer
            .entry(ex.balancer.id.clone())
            .or_default()
            .push(ex);
    }

    // only materialize referenced balancers (Design Doc 0025 §1.3)
    let mut helm_flags = HelmActivationFlags::default();
    let mut need_cert_manager = false;
    for (lb_id, group) in &by_balancer {
        let lb = cluster
            .load_balancers
            .iter()
            .find(|l| l.id == *lb_id)
            .expect("resolve_exposures already resolved the balancer");
        let strategy = tls_strategy(lb, group);
        need_cert_manager |= strategy.uses_cert_manager();
        let mat = materializer_for(lb)?;
        mat.validate(lb)?;

        let ctx = MaterializeCtx {
            cluster,
            lb,
            exposures: group.clone(),
            strategy,
            provenance,
        };

        let act = mat.activate(&ctx)?;
        helm_flags.merge(act.helm_flags);
        artifacts.activation.extend(act.objects);
        artifacts.warnings.extend(act.warnings);

        let routes = mat.routes(&ctx)?;
        artifacts.routes.extend(routes.objects);
        artifacts.warnings.extend(routes.warnings);

        let policies = mat.edge_policies(&ctx)?;
        artifacts.edge_policies.extend(policies.objects);
        artifacts.warnings.extend(policies.warnings);

        // VIP reachability (Design Doc 0025 §3.11): network prerequisites are
        // DECLARED, never inferred. Absent = `none` (fail-closed) + warning.
        match lb.vip_reachability {
            None => artifacts.warnings.push(format!(
                "balancer `{}`: vipReachability is not declared — no VIP \
                 announcements are compiled (fail-closed). Declare \
                 `vipReachability: l2-announce` for LAN/ARP reachability or \
                 `vipReachability: bgp` for routed VIPs",
                lb.id
            )),
            Some(amispec_schema::VipReachability::None) => {}
            Some(amispec_schema::VipReachability::Bgp) => artifacts.warnings.push(format!(
                "balancer `{}`: vipReachability `bgp` is a Day-2 network \
                 prerequisite — configure BGP peering for the VIP yourself; \
                 the compiler emits no announcement policy",
                lb.id
            )),
            Some(amispec_schema::VipReachability::L2Announce) => {
                if lb.upstream_edge.is_some() {
                    return Err(CompileError::VipReachabilityConflict {
                        lb_id: lb.id.clone(),
                    });
                }
                let svc_names: Vec<String> = group
                    .iter()
                    .map(|ex| format!("{}-{}", ex.component.id, ex.expose.endpoint))
                    .collect();
                artifacts
                    .activation
                    .push(l2_announcement_policy(lb, &svc_names, cluster, provenance));
                helm_flags.l2_announcements = true;
                artifacts.warnings.push(format!(
                    "balancer `{}`: VIP is reachable via L2 ARP announcements — \
                     one active node per VIP, failover ~10-20s (lease 15/5/2s); \
                     for many VIPs or routed networks prefer \
                     `vipReachability: bgp`",
                    lb.id
                ));
            }
        }
    }

    // one HelmChartConfig per cluster (merge into the ami init HelmChart)
    if helm_flags.any() {
        let cfg = helm_chart_config(cluster, &helm_flags, provenance);
        artifacts.activation.insert(0, cfg);
    }
    // one cert-manager chain per cluster (the single non-baseline dependency)
    if need_cert_manager {
        artifacts
            .activation
            .splice(1..1, cert_manager_chain(cluster, provenance));
    }
    // backend Services for L7-routed components (stage 05)
    artifacts
        .routes
        .splice(0..0, backend_services(cluster, exposures, provenance));

    // gateways.yaml carries the gateway-class objects; the rest stays in
    // balancer-activation.yaml (Design Doc 0025 §2.2 layout).
    // Vendored CRD prerequisites are pushed per balancer — keep one copy each.
    let mut seen_crds: std::collections::BTreeSet<String> = Default::default();
    artifacts.activation.retain(|o| {
        if o.get("kind").and_then(|k| k.as_str()) != Some("CustomResourceDefinition") {
            return true;
        }
        let name = o
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        seen_crds.insert(name)
    });
    let (gateways, activation): (Vec<Value>, Vec<Value>) =
        artifacts.activation.into_iter().partition(|o| {
            o.get("kind")
                .and_then(|k| k.as_str())
                .is_some_and(|k| GATEWAY_KINDS.contains(&k))
        });
    artifacts.activation = activation;
    artifacts.gateways = gateways;

    Ok(artifacts)
}

/// Cilium Helm activation flags collected across balancers of one cluster.
#[derive(Debug, Default, Clone, Copy)]
pub struct HelmActivationFlags {
    pub envoy: bool,
    pub gateway_api: bool,
    pub ingress_controller: bool,
    /// ARP announcements for LoadBalancer IPs — without it the assigned
    /// Gateway IP is unreachable from the node network on an L2 segment.
    pub l2_announcements: bool,
}

impl HelmActivationFlags {
    pub fn any(&self) -> bool {
        self.envoy || self.gateway_api || self.ingress_controller
    }

    pub fn merge(&mut self, other: Self) {
        self.envoy |= other.envoy;
        self.gateway_api |= other.gateway_api;
        self.ingress_controller |= other.ingress_controller;
        self.l2_announcements |= other.l2_announcements;
    }
}

/// Everything the exposure pipeline added to the tree (per stage).
#[derive(Debug, Default)]
pub struct ExposureArtifacts {
    /// Stage 02 `balancer-activation.yaml`: HelmChartConfig + TLS chain.
    pub activation: Vec<Value>,
    /// Stage 02 `gateways.yaml`: GatewayClass/Gateway/pool objects.
    pub gateways: Vec<Value>,
    /// Stage 05: routes + backend Services.
    pub routes: Vec<Value>,
    /// Stage 06: scope guards + trust borders.
    pub edge_policies: Vec<Value>,
    pub warnings: Vec<String>,
}

/// Object kinds that belong to `gateways.yaml` rather than
/// `balancer-activation.yaml`. Vendored CRDs land here too: they are
/// prerequisites of the gateway-class objects in the same file (Flux applies
/// CRDs before the rest of a Kustomization, so same-file placement is safe).
const GATEWAY_KINDS: &[&str] = &[
    "GatewayClass",
    "Gateway",
    "CiliumGatewayClassConfig",
    "IngressClass",
    "CiliumLoadBalancerIPPool",
    "CustomResourceDefinition",
];

/// Context handed to [`BalancerMaterializer`] methods.
pub struct MaterializeCtx<'a> {
    pub cluster: &'a Cluster,
    pub lb: &'a LoadBalancer,
    pub exposures: Vec<&'a ResolvedExposure<'a>>,
    pub strategy: TlsStrategy,
    pub provenance: bool,
}

impl MaterializeCtx<'_> {
    /// Unique sorted hosts of this balancer's exposure set.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .exposures
            .iter()
            .filter_map(|e| e.host.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Listener plan (hostname + TLS secret contract) for the balancer.
    pub fn listener_plans(&self) -> Vec<ListenerPlan> {
        listener_plan(
            &self.lb.id,
            &self.hosts(),
            &self.cluster.domain,
            self.strategy,
        )
    }

    /// Resolved tls mode label for provenance.
    pub fn resolved_tls(&self) -> String {
        resolved_tls_label(self.lb, self.strategy)
    }
}

/// Shared provenance labels for exposure artifacts.
pub fn exposure_labels(cluster_id: &str, stage: &str, provenance: bool) -> Map<String, Value> {
    let mut labels = Map::new();
    if provenance {
        labels.insert(LABEL_CLUSTER_ID.into(), json!(cluster_id));
        labels.insert(LABEL_STAGE.into(), json!(stage));
    }
    labels
}

/// Backend Service selecting a component and exposing its endpoint contracts
/// (required by HTTPRoute / Ingress backendRefs).
pub fn backend_service(
    cluster_id: &str,
    comp: &ComponentInstance,
    exposures: &[&ResolvedExposure<'_>],
    pin: &str,
    provenance: bool,
) -> Value {
    let mut labels = exposure_labels(cluster_id, "05-applications", provenance);
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(comp.id));
        labels.insert(LABEL_PASSPORT.into(), json!(pin));
    }
    let mut ports: Vec<Value> = Vec::new();
    let mut used_names: Vec<String> = Vec::new();
    for ex in exposures {
        let name = service_port_name(&ex.expose.endpoint, &mut used_names);
        ports.push(json!({
            "name": name,
            "port": ex.backend_port,
            "targetPort": ex.backend_port,
            "protocol": "TCP",
        }));
    }
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": comp.id,
            "namespace": comp.zone.clone().unwrap_or_else(|| "default".into()),
            "labels": Value::Object(labels),
        },
        "spec": {
            "selector": { "app.kubernetes.io/name": comp.id.clone() },
            "ports": ports,
        }
    })
}

/// IANA_SVC_NAME-safe Service port name (≤15 chars, unique per Service).
fn service_port_name(endpoint: &str, used: &mut Vec<String>) -> String {
    let mut name: String = endpoint
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(15)
        .collect();
    if name.is_empty() {
        name = "port".into();
    }
    if used.contains(&name) {
        name = format!("p-{}", used.len() + 1);
    }
    used.push(name.clone());
    name
}

/// Scoped `CiliumL2AnnouncementPolicy`: ARP-announce ONLY the services of
/// this balancer (Design Doc 0025 §3.11 — declared reachability, minimal
/// network surface). L7: the generated `cilium-gateway-<lb-id>` Service;
/// L4: the generated per-endpoint Services via the reserved
/// `io.kubernetes.service.name` selector keys.
fn l2_announcement_policy(
    lb: &LoadBalancer,
    svc_names: &[String],
    cluster: &Cluster,
    provenance: bool,
) -> Value {
    let labels = lb_labels(&cluster.id, lb, STAGE_OPS, provenance);
    let service_selector = if lb.layer == "l7-gateway" {
        json!({
            "matchLabels": {
                "io.kubernetes.service.name": format!("cilium-gateway-{}", lb.id),
            }
        })
    } else {
        json!({
            "matchExpressions": [{
                "key": "io.kubernetes.service.name",
                "operator": "In",
                "values": svc_names,
            }]
        })
    };
    json!({
        "apiVersion": "cilium.io/v2alpha1",
        "kind": "CiliumL2AnnouncementPolicy",
        "metadata": {
            "name": format!("{}-l2", lb.id),
            "labels": Value::Object(labels),
        },
        "spec": {
            "loadBalancerIPs": true,
            "serviceSelector": service_selector,
        }
    })
}

/// One HelmChartConfig merging Cilium L7 activation flags into the `cilium`
/// HelmChart created by `ami init` (k3s helm-controller merge, Design Doc
/// 0025 §1.7).
/// Render the merged Cilium Helm `valuesContent` for the L7 activation.
///
/// Public so the product repo can hold a contract test against the Day-0 base
/// (`os/configs/cilium-helmchart.yaml`): nested blocks repeat the base keys
/// they touch (merge semantics of the k3s helm-controller are ambiguous
/// between concat and deep-merge), and any drift of the repeated base values
/// must fail a test — not appear as a silent config rollback at apply time.
pub fn activation_values_content(flags: &HelmActivationFlags) -> String {
    // Deterministic: fixed key order.
    //
    // `rollOutPods` matters: the Gateway API / Ingress controllers live in
    // cilium-operator and only read their config at startup — without a
    // rollout the merge is invisible and Gateways stay unprogrammed.
    let mut values = String::new();
    values.push_str("envoy:\n  enabled: true\n");
    values.push_str("rollOutCiliumPods: true\n");
    values.push_str(
        "operator:\n  replicas: 1\n  tolerations:\n    - operator: Exists\n  image:\n    useDigest: false\n    digest: \"\"\n  rollOutPods: true\n",
    );
    // eBPF-based TPROXY: the L7 datapath must not depend on iptables/xt_TPROXY
    // modules that minimal distributions do not ship (Cilium Gateway API docs).
    // The base `bpf.masquerade` key is repeated so both merge semantics keep it.
    // NB: this block REPLACES the base `bpf:` map under concat-merge — every
    // base key (masquerade, hostRouting) must be repeated here.
    values.push_str("bpf:\n  masquerade: true\n  hostRouting: true\n  tproxy: true\n");
    if flags.l2_announcements {
        values.push_str("l2announcements:\n  enabled: true\n");
    }
    if flags.gateway_api {
        values.push_str("gatewayAPI:\n  enabled: true\n");
    }
    if flags.ingress_controller {
        values.push_str(
            "ingressController:\n  enabled: true\n  default: true\n  loadbalancerMode: shared\n  service:\n    allocateLoadBalancerNodePorts: false\n",
        );
    }
    values
}

fn helm_chart_config(cluster: &Cluster, flags: &HelmActivationFlags, provenance: bool) -> Value {
    let values = activation_values_content(flags);
    let mut labels = exposure_labels(&cluster.id, "02-operators-and-networking", provenance);
    labels.insert(LABEL_EXPOSURE.into(), json!("true"));

    json!({
        "apiVersion": "helm.cattle.io/v1",
        "kind": "HelmChartConfig",
        "metadata": {
            "name": "cilium",
            "namespace": "kube-system",
            "labels": Value::Object(labels),
        },
        "spec": {
            "valuesContent": values,
        }
    })
}

/// Provenance annotations describing a LoadBalancer for `decompile`.
pub fn lb_annotations(
    lb: &LoadBalancer,
    provenance: bool,
    resolved_tls: &str,
) -> Map<String, Value> {
    let mut ann = Map::new();
    if !provenance {
        return ann;
    }
    ann.insert(LABEL_LB_PROVIDER.into(), json!(lb.provider));
    if let Some(tls) = &lb.tls {
        ann.insert(LABEL_LB_TLS.into(), json!(tls));
    }
    ann.insert(LABEL_TLS_MODE_RESOLVED.into(), json!(resolved_tls));
    if let Some(up) = &lb.upstream_edge {
        ann.insert(LABEL_UPSTREAM_EDGE.into(), json!(up));
    }
    if let Some(tp) = &lb.trusted_proxy_source {
        ann.insert(
            LABEL_TRUSTED_PROXY_SOURCE.into(),
            json!(serde_json::to_string(tp).unwrap_or_else(|_| "null".into())),
        );
    }
    if let Some(fm) = &lb.forwarding_mode {
        ann.insert(LABEL_FORWARDING_MODE.into(), json!(fm));
    }
    if let Some(ip) = &lb.floating_ip_ref {
        ann.insert(LABEL_FLOATING_IP_REF.into(), json!(ip));
    }
    if let Some(pp) = lb.proxy_protocol_v2 {
        ann.insert(LABEL_PROXY_PROTOCOL_V2.into(), json!(pp.to_string()));
    }
    if let Some(h3) = lb.http3_quic {
        ann.insert(LABEL_HTTP3_QUIC.into(), json!(h3.to_string()));
    }
    if let Some(vr) = lb.vip_reachability {
        let s = match vr {
            amispec_schema::VipReachability::L2Announce => "l2-announce",
            amispec_schema::VipReachability::Bgp => "bgp",
            amispec_schema::VipReachability::None => "none",
        };
        ann.insert(LABEL_VIP_REACHABILITY.into(), json!(s));
    }
    ann
}

/// Provenance labels of one LoadBalancer.
pub fn lb_labels(
    cluster_id: &str,
    lb: &LoadBalancer,
    stage: &str,
    provenance: bool,
) -> Map<String, Value> {
    let mut labels = exposure_labels(cluster_id, stage, provenance);
    if provenance {
        labels.insert(LABEL_LB_ID.into(), json!(lb.id));
        labels.insert(LABEL_LB_LAYER.into(), json!(lb.layer));
    }
    labels
}

/// Serialize `securityPolicy` into the route annotation used by `decompile`.
pub fn security_policy_json(ex: &Expose) -> Option<String> {
    ex.security_policy.as_ref().map(|sp| {
        let mut m = Map::new();
        if let Some(ca) = &sp.client_auth {
            m.insert("clientAuth".into(), json!(ca));
        }
        if let Some(origins) = &sp.cors_allowed_origins {
            m.insert("corsAllowedOrigins".into(), json!(origins));
        }
        if let Some(rps) = sp.rate_limit_rps {
            m.insert("rateLimitRps".into(), json!(rps));
        }
        if let Some(aa) = sp.allow_anonymous {
            m.insert("allowAnonymous".into(), json!(aa));
        }
        serde_json::to_string(&Value::Object(m)).unwrap_or_else(|_| "{}".into())
    })
}

/// Provenance labels shared by route objects (HTTPRoute / Ingress / L4 Service).
pub fn route_labels(
    ex: &ResolvedExposure<'_>,
    stage: &str,
    provenance: bool,
) -> Map<String, Value> {
    let mut labels = exposure_labels(&ex.cluster.id, stage, provenance);
    if provenance {
        labels.insert(LABEL_COMPONENT_ID.into(), json!(ex.component.id));
        labels.insert(LABEL_PASSPORT.into(), json!(ex.pin));
        labels.insert(LABEL_ENDPOINT.into(), json!(ex.expose.endpoint));
        // Concrete balancer of THIS route (an expose with several viaBalancer
        // ids yields one route per balancer).
        labels.insert(LABEL_VIA_BALANCER.into(), json!(ex.balancer.id));
        labels.insert(LABEL_SCOPE.into(), json!(ex.expose.scope));
    }
    labels
}

/// Provenance annotations shared by route objects (host + securityPolicy).
pub fn route_annotations(ex: &ResolvedExposure<'_>, provenance: bool) -> Map<String, Value> {
    let mut ann = Map::new();
    if !provenance {
        return ann;
    }
    if let Some(host) = &ex.host {
        ann.insert(LABEL_HOST.into(), json!(host));
    }
    ann.insert(LABEL_HOST_SOURCE.into(), json!(ex.host_source));
    let host_value = ex
        .expose
        .hostname
        .clone()
        .or_else(|| ex.expose.subdomain.clone())
        .unwrap_or_default();
    ann.insert(LABEL_HOST_VALUE.into(), json!(host_value));
    ann.insert(LABEL_PATH_PREFIX.into(), json!(ex.path));
    if let Some(sp) = security_policy_json(ex.expose) {
        ann.insert(LABEL_SECURITY_POLICY.into(), json!(sp));
    }
    ann
}

/// Shared cert-manager chain (the only non-baseline dependency): Namespace,
/// HelmRepository + HelmRelease — one copy per cluster, only when some
/// balancer uses `tls: letsencrypt-*`.
pub fn cert_manager_chain(cluster: &Cluster, provenance: bool) -> Vec<Value> {
    let labels = exposure_labels(&cluster.id, "02-operators-and-networking", provenance);
    let labels_v = Value::Object(labels.clone());
    vec![
        json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": CERT_MANAGER_NAMESPACE, "labels": labels_v.clone() },
        }),
        json!({
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "HelmRepository",
            "metadata": {
                "name": "jetstack",
                "namespace": CERT_MANAGER_NAMESPACE,
                "labels": labels_v.clone(),
            },
            "spec": {
                "interval": "1h",
                "url": "https://charts.jetstack.io",
            },
        }),
        json!({
            "apiVersion": "helm.toolkit.fluxcd.io/v2",
            "kind": "HelmRelease",
            "metadata": {
                "name": "cert-manager",
                "namespace": CERT_MANAGER_NAMESPACE,
                "labels": labels_v,
            },
            "spec": {
                "interval": "1h",
                "chart": {
                    "spec": {
                        "chart": "cert-manager",
                        "version": CERT_MANAGER_CHART_VERSION,
                        "sourceRef": {
                            "kind": "HelmRepository",
                            "name": "jetstack",
                            "namespace": CERT_MANAGER_NAMESPACE,
                        },
                    },
                },
                "values": { "installCRDs": true },
            },
        }),
    ]
}

/// Backend Services for components routed via L7 (HTTPRoute/Ingress
/// `backendRefs` target a Service named after the component, ADR 0009).
///
/// One Service per component covering every exposed endpoint contract —
/// emitted once per cluster (not per balancer).
pub fn backend_services(
    cluster: &Cluster,
    exposures: &[ResolvedExposure<'_>],
    provenance: bool,
) -> Vec<Value> {
    let mut per_component: BTreeMap<String, Vec<&ResolvedExposure<'_>>> = BTreeMap::new();
    for ex in exposures {
        if ex.host.is_some() {
            per_component
                .entry(ex.component.id.clone())
                .or_default()
                .push(ex);
        }
    }
    per_component
        .into_values()
        .map(|group| {
            let comp = group[0].component;
            let pin = &group[0].pin;
            backend_service(&cluster.id, comp, &group, pin, provenance)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use amispec_schema::{Expose, LoadBalancer, SecurityPolicy};

    fn lb(id: &str, layer: &str, provider: &str, tls: Option<&str>) -> LoadBalancer {
        LoadBalancer {
            id: id.into(),
            layer: layer.into(),
            provider: provider.into(),
            upstream_edge: None,
            trusted_proxy_source: None,
            forwarding_mode: None,
            floating_ip_ref: None,
            proxy_protocol_v2: None,
            http3_quic: Some(true),
            tls: tls.map(|s| s.to_string()),
            vip_reachability: None,
        }
    }

    fn exposure<'a>(
        cluster: &'a Cluster,
        comp: &'a ComponentInstance,
        ex: &'a Expose,
        balancer: &'a LoadBalancer,
    ) -> ResolvedExposure<'a> {
        ResolvedExposure {
            cluster,
            component: comp,
            expose: ex,
            balancer,
            host: None,
            host_source: "default",
            path: "/".into(),
            backend_port: 8080,
            pin: "p@1.0.0-rev1".into(),
        }
    }

    fn cluster_fixture() -> Cluster {
        Cluster {
            id: "local".into(),
            name: "Local".into(),
            domain: "example.io".into(),
            k3s_channel: None,
            security: None,
            cni: amispec_schema::CniConfig {
                engine: "cilium-ebpf".into(),
                cluster_mesh_id: 1,
                kube_proxy_replacement: Some(true),
                hubble_live_map: None,
                wireguard_encryption: None,
                mtu_discovery_and_mss_clamp: None,
                fqdn_cache_min_ttl_sec: None,
            },
            nodes: vec![],
            components: vec![],
            bindings: vec![],
            load_balancers: vec![],
            maintenance_window: None,
        }
    }

    fn component(id: &str) -> ComponentInstance {
        ComponentInstance {
            id: id.into(),
            passport: "stateless-app".into(),
            version: "1.0.0".into(),
            passport_rev: 1,
            topology: amispec_schema::ComponentTopology {
                mode: "standalone".into(),
                replicas: Some(1),
                committed_replicas: None,
                shards: None,
                autoscaling: None,
            },
            resources: amispec_schema::ComponentResources {
                cpu_cores: 1.0,
                memory_mb: 256,
            },
            zone: Some("dmz".into()),
            group: None,
            config: None,
            backup_target: None,
            bootstrap: None,
            bindings: vec![],
            expose: vec![],
            workload_override: None,
        }
    }

    fn ex(subdomain: Option<&str>, hostname: Option<&str>) -> Expose {
        Expose {
            endpoint: "web".into(),
            via_balancer: amispec_schema::ViaBalancer::One("l7".into()),
            scope: "public".into(),
            subdomain: subdomain.map(|s| s.to_string()),
            hostname: hostname.map(|s| s.to_string()),
            path_prefix: None,
            security_policy: None,
        }
    }

    #[test]
    fn host_resolution_precedence() {
        let c = cluster_fixture();
        let comp = component("web");
        assert_eq!(
            effective_host(&comp, &c, &ex(Some("api"), None)),
            "api.example.io"
        );
        assert_eq!(
            effective_host(&comp, &c, &ex(Some("api"), Some("apex.io"))),
            "apex.io"
        );
        assert_eq!(effective_host(&comp, &c, &ex(None, None)), "web.example.io");
    }

    #[test]
    fn listener_partition_wildcard() {
        let hosts = vec![
            "api.example.io".to_string(),
            "admin.example.io".to_string(),
            "example.io".to_string(),
        ];
        let got = listener_hosts(&hosts, "example.io");
        assert_eq!(
            got,
            vec![
                ListenerHost::Wildcard("*.example.io".into()),
                ListenerHost::Host("example.io".into())
            ]
        );
    }

    #[test]
    fn listener_partition_single_host() {
        let hosts = vec!["app.localhost".to_string()];
        let got = listener_hosts(&hosts, "example.local");
        assert_eq!(got, vec![ListenerHost::Host("app.localhost".into())]);
    }

    #[test]
    fn tls_strategy_auto_resolution() {
        let cluster = cluster_fixture();
        let comp = component("web");
        let bal = lb("l7", "l7-gateway", "cilium-envoy", Some("letsencrypt-auto"));
        let ex1 = ex(Some("api"), None);
        let mut e1 = exposure(&cluster, &comp, &ex1, &bal);
        e1.host = Some("api.example.io".into());
        assert_eq!(tls_strategy(&bal, &[&e1]), TlsStrategy::WildcardDns01);

        let ex2 = ex(None, Some("app.localhost"));
        let mut e2 = exposure(&cluster, &comp, &ex2, &bal);
        e2.host = Some("app.localhost".into());
        assert_eq!(tls_strategy(&bal, &[&e2]), TlsStrategy::PerHostHttp01);
    }

    #[test]
    fn listener_plan_secrets() {
        let hosts = vec![
            "api.example.io".to_string(),
            "admin.example.io".to_string(),
            "app.localhost".to_string(),
        ];
        let plan = listener_plan("main-l7", &hosts, "example.io", TlsStrategy::WildcardDns01);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].host, ListenerHost::Wildcard("*.example.io".into()));
        assert_eq!(plan[0].secret.as_deref(), Some("main-l7-tls"));
        assert_eq!(plan[1].secret.as_deref(), Some("main-l7-app-localhost-tls"));

        // HTTP-01 cannot issue wildcards → one listener per host
        let plan = listener_plan("main-l7", &hosts, "example.io", TlsStrategy::PerHostHttp01);
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|p| matches!(p.host, ListenerHost::Host(_))));

        // plaintext: no secrets
        let plan = listener_plan("main-l7", &hosts, "example.io", TlsStrategy::None);
        assert!(plan.iter().all(|p| p.secret.is_none()));
    }

    #[test]
    fn service_port_names_are_safe() {
        let mut used = Vec::new();
        assert_eq!(service_port_name("web", &mut used), "web");
        assert_eq!(service_port_name("web", &mut used), "p-2");
        assert_eq!(
            service_port_name("very-long-endpoint-name", &mut used).len(),
            15
        );
    }

    #[test]
    fn security_policy_roundtrip_json() {
        let mut e = ex(None, None);
        e.security_policy = Some(SecurityPolicy {
            client_auth: Some("oidc".into()),
            cors_allowed_origins: Some(vec!["https://a.example".into()]),
            rate_limit_rps: Some(500),
            allow_anonymous: Some(false),
        });
        let json = security_policy_json(&e).unwrap();
        assert!(json.contains("oidc"));
        assert!(json.contains("500"));
    }
}
