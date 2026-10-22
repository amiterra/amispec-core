//! `amispec` — thin CLI over amispec-validate / amispec-compile.
//!
//! The broad product CLI is amiterra (`ami`); this binary exists for CI and
//! standalone use. Commands map 1:1 to library APIs.

use amispec_compile::compile;
use amispec_schema::AMISPEC_STANDARD_VERSION;
use amispec_validate::{validate_file, Options as ValidateOptions};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(
    name = "amispec",
    version,
    about = "AmiSpec validate & compile (standard 1.0)",
    long_about = "Library-first tooling for the AmiSpec standard.\n\
                  Use `amispec validate` and `amispec compile` in CI.\n\
                  Product CLIs (e.g. amiterra `ami`) embed amispec-validate / amispec-compile crates."
)]
struct Cli {
    /// Path to normative CUE schemas (for optional cue vet)
    #[arg(long, global = true)]
    schema_dir: Option<PathBuf>,

    /// Invoke `cue vet` in addition to built-in checks
    #[arg(long, global = true, default_value_t = false)]
    cue: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate AmiSpec YAML documents (passport / topology / layout)
    Validate {
        /// Files or directories to validate
        paths: Vec<PathBuf>,
        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
    },
    /// Compile a topology.yaml into a k3s/FluxCD manifest tree
    Compile {
        /// Input topology.yaml
        input: PathBuf,
        /// Output directory
        #[arg(short, long)]
        out: PathBuf,
        /// Compute artifacts without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Reverse-decompile a FluxCD tree (with AmiSpec provenance) to topology.yaml
    Decompile {
        /// Manifest tree root (e.g. out/clusters or out)
        input: PathBuf,
        /// Write reconstructed topology.yaml here
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Print standard version this tool targets
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Decompile { input, output } => {
            let report = amispec_compile::decompile_dir(&input).context("decompile")?;
            eprintln!(
                "scanned {} file(s), {} object(s) with provenance",
                report.files_scanned, report.objects_with_provenance
            );
            for w in &report.warnings {
                eprintln!("warn: {w}");
            }
            let Some(topo) = report.topology else {
                bail!("no topology reconstructed");
            };
            let yaml = serde_yaml::to_string(&topo).context("serialize topology")?;
            if output.as_os_str() == "-" {
                print!("{yaml}");
            } else {
                std::fs::write(&output, yaml)
                    .with_context(|| format!("write {}", output.display()))?;
                eprintln!("wrote {}", output.display());
            }
            Ok(())
        }
        Command::Version => {
            println!("amispec-core targeting AmiSpec standard {AMISPEC_STANDARD_VERSION}");
            Ok(())
        }
        Command::Validate { paths, strict } => {
            let files = collect_yaml(&paths)?;
            if files.is_empty() {
                bail!("no YAML files found");
            }
            let opts = ValidateOptions {
                use_cue: cli.cue,
                schema_dir: cli.schema_dir.map(|p| p.display().to_string()),
            };
            let mut failed = 0;
            for f in &files {
                let report = validate_file(f, &opts);
                print_report(&report, strict);
                if !report.is_ok() || (strict && !report.findings.is_empty()) {
                    failed += 1;
                }
            }
            if failed > 0 {
                bail!("{failed} file(s) failed validation");
            }
            println!("validated {} file(s) OK", files.len());
            Ok(())
        }
        Command::Compile {
            input,
            out,
            dry_run,
        } => {
            let raw = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let topo = amispec_schema::parse_topology(&raw).context("parse topology")?;
            let opts = amispec_compile::Options {
                out_dir: out.clone(),
                provenance: true,
                dry_run,
            };
            let result = compile(&topo, &amispec_compile::PassportIndex::default(), &opts).context("compile")?;
            println!(
                "compiled cluster(s) {:?} component(s) {:?} → {} artifact(s) into {}",
                result.cluster_ids,
                result.component_ids,
                result.files.len(),
                out.display()
            );
            for a in &result.files {
                println!("  {}", a.relative_path);
            }
            Ok(())
        }
    }
}

fn collect_yaml(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            for entry in WalkDir::new(p) {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .map(|e| e == "yaml" || e == "yml")
                        .unwrap_or(false)
                {
                    files.push(path.to_path_buf());
                }
            }
        } else if p.is_file() {
            files.push(p.clone());
        } else {
            bail!("path not found: {}", p.display());
        }
    }
    files.sort();
    Ok(files)
}

fn print_report(report: &amispec_validate::Report, strict: bool) {
    let status = if report.is_ok() && !(strict && !report.findings.is_empty()) {
        "PASS"
    } else {
        "FAIL"
    };
    let kind = report
        .kind
        .map(|k| k.as_str())
        .unwrap_or("?");
    println!("{status} {} ({kind})", report.source);
    for f in &report.findings {
        let sev = match f.severity {
            amispec_validate::Severity::Error => "error",
            amispec_validate::Severity::Warning => "warn ",
        };
        println!("  {sev} [{}] {}: {}", f.rule, f.path, f.message);
    }
}

#[allow(dead_code)]
fn default_schema_dir() -> Option<PathBuf> {
    // relative layout: ../amispec/schemas when running from amispec-core
    let p = Path::new("../amispec/schemas");
    if p.join("component_passport.cue").exists() {
        Some(p.to_path_buf())
    } else {
        None
    }
}
