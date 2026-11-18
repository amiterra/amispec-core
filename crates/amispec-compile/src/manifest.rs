//! Manifest assembly helpers (deterministic multi-doc YAML).

use crate::GeneratedFile;
use serde_json::Value;

/// Collects generated documents and emits stable multi-doc YAML.
pub struct Builder {
    files: Vec<GeneratedFile>,
}

impl Builder {
    pub fn new(_provenance: bool) -> Self {
        Self { files: Vec::new() }
    }

    /// Append documents as a multi-doc YAML file.
    pub fn docs(&mut self, relative_path: &str, docs: &[Value]) {
        if docs.is_empty() {
            // keep an empty list document so the kustomization path exists
            self.files.push(GeneratedFile {
                relative_path: relative_path.to_string(),
                contents: "[]\n".to_string(),
            });
            return;
        }
        let parts: Vec<String> = docs
            .iter()
            .map(|d| quote_yaml11_bools(&serde_yaml::to_string(d).unwrap_or_default()))
            .filter(|s| !s.trim().is_empty())
            .collect();
        self.files.push(GeneratedFile {
            relative_path: relative_path.to_string(),
            contents: parts.join("---\n"),
        });
    }

    /// Write a `kustomize.config.k8s.io/v1beta1` Kustomization.
    pub fn kustomization(&mut self, relative_path: &str, resources: &[&str]) {
        let doc = serde_json::json!({
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": resources,
        });
        self.files.push(GeneratedFile {
            relative_path: relative_path.to_string(),
            contents: serde_yaml::to_string(&doc).unwrap_or_default(),
        });
    }

    /// Append a pre-rendered multi-doc YAML file byte-for-byte (vendored
    /// operator release manifests — GR-OPR-006 supply artifacts).
    pub fn raw(&mut self, relative_path: &str, contents: &str) {
        self.files.push(GeneratedFile {
            relative_path: relative_path.to_string(),
            contents: contents.to_string(),
        });
    }

    /// Like [`Self::kustomization`], with owned resource names.
    pub fn kustomization_owned(&mut self, relative_path: &str, resources: &[String]) {
        let refs: Vec<&str> = resources.iter().map(|s| s.as_str()).collect();
        self.kustomization(relative_path, &refs);
    }

    pub fn finish(self) -> Vec<GeneratedFile> {
        self.files
    }
}

/// Quote plain scalars that YAML 1.1 resolves to booleans (`on/off/yes/no/y/n`).
///
/// serde_yaml follows YAML 1.2 (where those are strings) and emits them bare,
/// but Kubernetes' go-yaml reads YAML 1.1 — `huge_pages: on` would arrive as
/// the boolean `true` and fail CRD string validation. Block-scalar bodies are
/// left untouched (script content is literal).
fn quote_yaml11_bools(yaml: &str) -> String {
    const BOOLS: &[&str] = &["on", "off", "yes", "no", "y", "n"];
    fn is_bool(s: &str) -> bool {
        let lower = s.to_ascii_lowercase();
        BOOLS.contains(&lower.as_str())
    }
    let mut out = String::with_capacity(yaml.len());
    let mut block_indent: Option<usize> = None;
    for line in yaml.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        let indent = trimmed.len() - trimmed.trim_start().len();
        if let Some(bi) = block_indent {
            if trimmed.trim().is_empty() || indent > bi {
                out.push_str(line);
                continue;
            }
            block_indent = None;
        }
        let body = trimmed.trim_start();
        let block_started = [": |", ": |-", ": |+", ": >", ": >-", ": >+"]
            .iter()
            .any(|ind| body.ends_with(ind));
        if block_started {
            block_indent = Some(indent);
            out.push_str(line);
            continue;
        }
        let replaced;
        if let Some((_key, val)) = body.split_once(": ") {
            if is_bool(val) && !val.starts_with('"') && !val.starts_with('\'') {
                let prefix = &trimmed[..trimmed.len() - val.len()];
                replaced = format!("{prefix}\"{val}\"\n");
                out.push_str(&replaced);
                continue;
            }
        }
        if let Some(val) = body.strip_prefix("- ") {
            if is_bool(val) {
                let prefix = &trimmed[..trimmed.len() - val.len()];
                replaced = format!("{prefix}\"{val}\"\n");
                out.push_str(&replaced);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn docs_joins_multi_doc_yaml() {
        let mut b = Builder::new(true);
        b.docs("a.yaml", &[json!({"kind": "A"}), json!({"kind": "B"})]);
        let files = b.finish();
        assert_eq!(files.len(), 1);
        assert!(files[0].contents.contains("kind: A"));
        assert!(files[0].contents.contains("kind: B"));
        assert!(files[0].contents.contains("---"));
    }

    #[test]
    fn empty_docs_emit_empty_list() {
        let mut b = Builder::new(true);
        b.docs("empty.yaml", &[]);
        let files = b.finish();
        assert_eq!(files[0].contents.trim(), "[]");
    }

    #[test]
    fn kustomization_lists_resources() {
        let mut b = Builder::new(true);
        b.kustomization("kustomization.yaml", &["a.yaml", "b.yaml"]);
        let files = b.finish();
        assert!(files[0].contents.contains("kustomize.config.k8s.io"));
        assert!(files[0].contents.contains("a.yaml"));
        assert!(files[0].contents.contains("b.yaml"));
    }

    #[test]
    fn yaml11_bools_get_quoted_but_block_scalars_do_not() {
        let src = "a: on\nb: \"off\"\nc: |\n  keep on\n  - no\nd: yes\ne: n\n";
        let out = quote_yaml11_bools(src);
        assert_eq!(out, "a: \"on\"\nb: \"off\"\nc: |\n  keep on\n  - no\nd: \"yes\"\ne: \"n\"\n");
    }
}
