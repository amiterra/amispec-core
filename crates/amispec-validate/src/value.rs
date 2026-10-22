//! Thin YAML value helpers (serde_yaml::Value).

pub type Yaml = serde_yaml::Value;
pub type Map = serde_yaml::Mapping;

pub fn get<'a>(v: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    v.get(key)
}

pub fn as_bool(v: &Yaml) -> Option<bool> {
    v.as_bool()
}

pub fn as_str(v: &Yaml) -> Option<&str> {
    v.as_str()
}

pub fn as_i64(v: &Yaml) -> Option<i64> {
    v.as_i64()
}

pub fn as_u64(v: &Yaml) -> Option<u64> {
    v.as_u64()
}

pub fn as_f64(v: &Yaml) -> Option<f64> {
    v.as_f64()
}

pub fn as_seq(v: &Yaml) -> Option<&Vec<Yaml>> {
    v.as_sequence()
}

pub fn as_map(v: &Yaml) -> Option<&Map> {
    v.as_mapping()
}

/// Display a mapping key for path building.
pub fn key_str(k: &Yaml) -> String {
    match k {
        Yaml::String(s) => s.clone(),
        Yaml::Number(n) => n.to_string(),
        Yaml::Bool(b) => b.to_string(),
        other => format!("{other:?}"),
    }
}

/// Optional string field.
pub fn opt_str<'a>(parent: &'a Yaml, key: &str) -> Option<&'a str> {
    get(parent, key).and_then(as_str)
}

/// Required non-empty string field; push error if missing.
pub fn req_str(parent: &Yaml, key: &str, path: &str, out: &mut Vec<crate::Finding>) -> Option<String> {
    match opt_str(parent, key) {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => {
            out.push(crate::Finding::error(
                path,
                "required",
                format!("`{key}` is required and MUST be a non-empty string"),
            ));
            None
        }
    }
}


pub fn check_int_range(
    parent: &Yaml,
    key: &str,
    path: &str,
    min: i64,
    max: Option<i64>,
    out: &mut Vec<crate::Finding>,
    rule: &str,
) {
    if let Some(raw) = get(parent, key) {
        match as_i64(raw) {
            Some(n) => {
                if n < min || max.is_some_and(|m| n > m) {
                    let bound = match max {
                        Some(m) => format!("{min}..={m}"),
                        None => format!(">={min}"),
                    };
                    out.push(crate::Finding::error(
                        format!("{path}.{key}"),
                        rule,
                        format!("value {n} MUST be {bound}"),
                    ));
                }
            }
            None => {
                out.push(crate::Finding::error(
                    format!("{path}.{key}"),
                    "type-int",
                    format!("`{key}` MUST be an integer"),
                ));
            }
        }
    }
}

/// Optional enum membership.
pub fn check_enum(
    parent: &Yaml,
    key: &str,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<crate::Finding>,
    rule: &str,
) {
    if let Some(s) = opt_str(parent, key) {
        if !allowed.contains(&s) {
            out.push(crate::Finding::error(
                format!("{path}.{key}"),
                rule,
                format!("`{s}` is not one of {allowed:?}"),
            ));
        }
    }
}

/// Required enum membership.
pub fn req_enum(
    parent: &Yaml,
    key: &str,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<crate::Finding>,
    rule: &str,
) {
    match opt_str(parent, key) {
        Some(s) if allowed.contains(&s) => {}
        Some(s) => out.push(crate::Finding::error(
            format!("{path}.{key}"),
            rule,
            format!("`{s}` is not one of {allowed:?}"),
        )),
        None => out.push(crate::Finding::error(
            format!("{path}.{key}"),
            "required",
            format!("`{key}` is required"),
        )),
    }
}
