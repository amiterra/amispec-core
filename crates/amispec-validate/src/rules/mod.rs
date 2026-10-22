//! Validation rules (structural + semantic + optional CUE).

pub mod cue;
pub mod deep;
mod layout;
mod passport;
mod topology;

use crate::report::{Finding, Report};
use crate::value::{as_map, Map, Yaml};
use crate::DocumentKind;

/// Validator options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Also run `cue vet -d '#Type'` (requires schema_dir + `cue` on PATH).
    pub use_cue: bool,
    /// Directory containing `component_passport.cue` and `topology_spec.cue`.
    pub schema_dir: Option<String>,
}

/// Validate a parsed root mapping for a known kind.
pub(crate) fn validate(kind: DocumentKind, root: &Map, report: &mut Report) {
    let mut findings: Vec<Finding> = Vec::new();
    match kind {
        DocumentKind::ComponentPassport => passport::check(root, &mut findings),
        DocumentKind::TopologyBlueprint => topology::check(root, &mut findings),
        DocumentKind::CanvasLayout => layout::check(root, &mut findings),
    }
    for f in findings {
        report.push(f);
    }
}

/// Convenience: validate topology YAML and return a report (used by compile pipeline).
pub fn validate_topology_str(source: &str, yaml: &str) -> Report {
    crate::validate_str(source, yaml, &Options::default())
}

#[allow(unused)]
pub(crate) fn root_mapping(v: &Yaml) -> Option<&Map> {
    as_map(v)
}
