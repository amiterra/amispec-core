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
            .map(|d| serde_yaml::to_string(d).unwrap_or_default())
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

    pub fn finish(self) -> Vec<GeneratedFile> {
        self.files
    }
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
}
