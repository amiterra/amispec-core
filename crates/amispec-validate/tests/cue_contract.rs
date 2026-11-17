//! CUE-schema sync contract: `amispec/schemas/*.cue` is the normative schema;
//! the Rust validator mirrors it. These tests keep both in lockstep on the
//! SHARED fixtures — if they drift, `cargo test` fails (not only `make -C
//! amispec`). Skipped (with a note) only when the `cue` CLI is unavailable.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn vet_sh() -> PathBuf {
    repo_root().join("amispec/scripts/vet.sh")
}

fn cue_available() -> bool {
    Command::new("bash")
        .arg("-lc")
        .arg("command -v cue >/dev/null || [ -x \"$HOME/.local/bin/cue\" ]")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn vet(kind: &str, file: &Path) -> bool {
    Command::new("bash")
        .arg(vet_sh())
        .arg(kind)
        .arg(file)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn yaml_files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "yaml")
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with(prefix))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

#[test]
fn cue_schema_accepts_valid_fixtures_and_catalog_passports() {
    if !cue_available() {
        eprintln!("SKIP: cue CLI not found — install cuelang.org/go/cmd/cue");
        return;
    }
    let valid = repo_root().join("amispec/tests/valid");
    for f in yaml_files(&valid, "passport-") {
        assert!(vet("passport", &f), "CUE rejected valid fixture {}", f.display());
    }
    for f in yaml_files(&valid, "topology-") {
        assert!(vet("topology", &f), "CUE rejected valid fixture {}", f.display());
    }
    // Real catalog content must satisfy the normative schema too.
    let mut n = 0;
    let mut stack = vec![repo_root().join("catalog/passports")];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with("rev") && n.ends_with(".yaml")
            }) {
                assert!(vet("passport", &p), "CUE rejected catalog passport {}", p.display());
                n += 1;
            }
        }
    }
    assert!(n > 0, "no catalog passports found — layout broken");
}

#[test]
fn cue_schema_rejects_invalid_fixtures() {
    if !cue_available() {
        eprintln!("SKIP: cue CLI not found — install cuelang.org/go/cmd/cue");
        return;
    }
    let invalid = repo_root().join("amispec/tests/invalid");
    let files = yaml_files(&invalid, "passport-");
    assert!(!files.is_empty(), "no invalid fixtures found");
    for f in files {
        assert!(
            !vet("passport", &f),
            "CUE accepted invalid fixture {} — schema drifted from requirements",
            f.display()
        );
    }
}
