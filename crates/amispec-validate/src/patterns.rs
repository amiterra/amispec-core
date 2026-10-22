//! Pattern matchers mirroring the normative CUE regexes in AmiSpec 1.0.
//!
//! Hand-written matchers keep the validator dependency-free (no `regex`) and
//! make the accepted language explicit and auditable.

/// `id` / `projectId` / `cluster.id` — `^[a-z0-9-]+$`
pub fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `imageDigest` / `chartDigest` — `^sha256:[a-f0-9]{64}$`
pub fn is_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `accentColor` — `^#[0-9a-fA-F]{6}$`
pub fn is_accent_color(s: &str) -> bool {
    let Some(hex) = s.strip_prefix('#') else {
        return false;
    };
    hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Age recipient — `^age1[a-z0-9]+$`
pub fn is_age_key(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("age1") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// SOPS secret URI — `^sops://.*$`
pub fn is_sops_uri(s: &str) -> bool {
    s.starts_with("sops://")
}

/// Script reference — `^(passport|topology)://scripts/[a-zA-Z0-9_.-]+$`
pub fn is_script_ref(s: &str) -> bool {
    let Some((scheme, path)) = s.split_once("://") else {
        return false;
    };
    if scheme != "passport" && scheme != "topology" {
        return false;
    }
    let Some(name) = path.strip_prefix("scripts/") else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug() {
        assert!(is_slug("demo-app"));
        assert!(is_slug("a"));
        assert!(is_slug("a1"));
        assert!(!is_slug(""));
        assert!(!is_slug("Demo_APP"));
        assert!(!is_slug("has space"));
        assert!(!is_slug("has_underscore"));
        // CUE pattern ^[a-z0-9-]+$ allows a leading hyphen
        assert!(is_slug("-lead"));
    }

    #[test]
    fn digest() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(is_sha256_digest(&format!("sha256:{}", "0".repeat(64))));
        assert!(!is_sha256_digest("sha256:xyz"));
        assert!(!is_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
    }

    #[test]
    fn color() {
        assert!(is_accent_color("#2563EB"));
        assert!(is_accent_color("#ffffff"));
        assert!(!is_accent_color("blue"));
        assert!(!is_accent_color("#fff"));
    }

    #[test]
    fn age() {
        assert!(is_age_key("age1abc123"));
        assert!(!is_age_key("not-an-age-key"));
        assert!(!is_age_key("age1"));
    }

    #[test]
    fn sops() {
        assert!(is_sops_uri("sops://secrets/x.enc.yaml"));
        assert!(!is_sops_uri("file://x"));
    }

    #[test]
    fn script_ref() {
        assert!(is_script_ref("passport://scripts/seed"));
        assert!(is_script_ref("topology://scripts/draining_v2.sh"));
        assert!(!is_script_ref("http://scripts/x"));
        assert!(!is_script_ref("passport://other/x"));
        assert!(!is_script_ref("passport://scripts/"));
    }
}
