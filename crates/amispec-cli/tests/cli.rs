//! CLI smoke tests (binary-level). Keep thin: parse errors and exit codes.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_amispec")
}

#[test]
fn version_prints_standard() {
    let out = Command::new(bin()).arg("version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("AmiSpec"), "{s}");
}

#[test]
fn validate_unknown_kind_fails() {
    let dir = std::env::temp_dir().join("amispec-cli-unknown-kind");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("x.yaml");
    std::fs::write(&f, "kind: Nope\napiVersion: x\n").unwrap();
    let out = Command::new(bin())
        .args(["validate", f.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("kind-enum") || s.contains("FAIL"), "{s}");
}

#[test]
fn compile_missing_input_fails() {
    let out = Command::new(bin())
        .args([
            "compile",
            "/nonexistent/topology.yaml",
            "-o",
            "/tmp/amispec-cli-out",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
