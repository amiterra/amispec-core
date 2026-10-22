//! Validation report and findings.

use crate::DocumentKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub path: String,
    pub message: String,
    pub rule: String,
}

impl Finding {
    pub fn error(path: impl Into<String>, rule: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
            rule: rule.into(),
        }
    }

    pub fn warning(path: impl Into<String>, rule: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            path: path.into(),
            message: message.into(),
            rule: rule.into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub source: String,
    pub kind: Option<DocumentKind>,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            ..Default::default()
        }
    }

    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn is_ok(&self) -> bool {
        !self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
    }

    pub fn error_count(&self) -> usize {
        self.errors().count()
    }
}
