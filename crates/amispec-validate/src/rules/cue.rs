//! Optional authoritative `cue vet` integration.
//!
//! Runs the `cue` binary (never a shell) against the normative CUE schemas.
//! Missing `cue` is a warning, not a hard failure, so CI can choose.

use crate::report::{Finding, Report};
use crate::DocumentKind;
use std::path::Path;
use std::process::Command;

pub fn run_cue_vet(kind: DocumentKind, yaml: &str, schema_dir: &str, report: &mut Report) {
    let (def, schema_file, extra) = match kind {
        DocumentKind::ComponentPassport => {
            ("#ComponentPassport", "component_passport.cue", None)
        }
        DocumentKind::TopologyBlueprint => (
            "#TopologyBlueprint",
            "topology_spec.cue",
            Some("component_passport.cue"),
        ),
        DocumentKind::CanvasLayout => (
            "#CanvasLayout",
            "topology_spec.cue",
            Some("component_passport.cue"),
        ),
    };

    let schema_path = Path::new(schema_dir).join(schema_file);
    if !schema_path.is_file() {
        report.push(Finding::warning(
            "$",
            "cue-missing-schema",
            format!("CUE schema not found: {}", schema_path.display()),
        ));
        return;
    }

    // Unique temp file; cleaned up on all paths below.
    let tmp = std::env::temp_dir().join(format!(
        "amispec-validate-{}-{}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if let Err(e) = std::fs::write(&tmp, yaml) {
        report.push(Finding::warning(
            "$",
            "cue-tmp",
            format!("cannot write temp instance: {e}"),
        ));
        return;
    }

    let mut cmd = Command::new("cue");
    cmd.arg("vet").arg("-d").arg(def).arg(&schema_path);
    if let Some(extra_file) = extra {
        let extra_path = Path::new(schema_dir).join(extra_file);
        if extra_path.is_file() {
            cmd.arg(&extra_path);
        }
    }
    cmd.arg(&tmp);

    let result = cmd.output();
    let _ = std::fs::remove_file(&tmp);

    match result {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let mut err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if err.is_empty() {
                err = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
            report.push(Finding::error(
                "$",
                "cue-vet",
                format!("cue vet rejected document: {err}"),
            ));
        }
        Err(e) => {
            report.push(Finding::warning(
                "$",
                "cue-unavailable",
                format!("cue binary not runnable ({e}); skipped authoritative check"),
            ));
        }
    }
}
