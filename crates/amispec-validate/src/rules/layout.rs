//! CanvasLayout rules.

use crate::patterns::is_slug;
use crate::report::Finding;
use crate::value::*;

pub fn check(root: &Map, out: &mut Vec<Finding>) {
    match root.get("clusterId").and_then(as_str) {
        Some(id) if is_slug(id) => {}
        Some(id) => out.push(Finding::error(
            "clusterId",
            "id-regex",
            format!("clusterId `{id}` MUST match ^[a-z0-9-]+$"),
        )),
        None => out.push(Finding::error("clusterId", "required", "clusterId is required")),
    }

    if let Some(vp) = root.get("viewport") {
        if let Some(z) = get(vp, "zoom").and_then(as_f64) {
            if z <= 0.0 {
                out.push(Finding::error(
                    "viewport.zoom",
                    "zoom-positive",
                    format!("zoom {z} MUST be > 0"),
                ));
            }
        }
        for axis in ["x", "y"] {
            if get(vp, axis).and_then(as_f64).is_none() && get(vp, axis).is_some() {
                out.push(Finding::error(
                    format!("viewport.{axis}"),
                    "type-number",
                    format!("{axis} MUST be a number"),
                ));
            }
        }
    }
}
