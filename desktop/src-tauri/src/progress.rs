//! Step progress from the Go sidecar.
//!
//! In `--desktop` mode the sidecar prints lines like
//! `PROGRESS {"step":3,"total":6,"key":"gitleaks","label":"Checking for leaked passwords and keys"}`.
//! They become a `scan-progress` Tauri event so the toast and the Codebase
//! Scanning box can show "Step 3 of 6". An open-ended phase (the pen test) sends
//! `total: 0` and may carry a running `count` + `unit`.
//!
//! Anything that does not parse is ignored (never shown as progress, never a
//! panic). There is no percentage and no time estimate by design.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

const MARKER: &str = "PROGRESS ";
const MAX_LABEL: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    #[serde(default)]
    pub step: u32,
    #[serde(default)]
    pub total: u32,
    #[serde(default)]
    pub key: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Parses one stdout line (ANSI already stripped). Returns None for anything
/// that is not a well-formed PROGRESS line.
pub fn parse_progress_line(line: &str) -> Option<ScanProgress> {
    let pos = line.find(MARKER)?;
    let json = line[pos + MARKER.len()..].trim();
    let mut p: ScanProgress = serde_json::from_str(json).ok()?;
    p.label = p.label.trim().to_string();
    if p.label.is_empty() || p.label.chars().count() > MAX_LABEL || p.label.chars().any(|c| c.is_control()) {
        return None;
    }
    // A step line must be inside its own range; total 0 means open-ended.
    if p.total > 0 && (p.step == 0 || p.step > p.total) {
        return None;
    }
    if p.total == 0 && p.step != 0 {
        return None;
    }
    Some(p)
}

/// Splits a stdout chunk into parsed progress updates and the remaining text
/// (every line that is not a valid PROGRESS line), so progress lines can be kept
/// out of the developer terminal while everything else is forwarded as before.
pub fn extract_progress(chunk: &str) -> (Vec<ScanProgress>, String) {
    let mut found = Vec::new();
    let mut rest: Vec<&str> = Vec::new();
    for raw_line in chunk.split('\n') {
        let stripped = crate::strip_ansi(raw_line.trim());
        match parse_progress_line(&stripped) {
            Some(p) => found.push(p),
            None => rest.push(raw_line),
        }
    }
    (found, rest.join("\n"))
}

pub fn emit_progress(app: &AppHandle, updates: Vec<ScanProgress>) {
    for p in updates {
        let _ = app.emit("scan-progress", p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_line_becomes_payload() {
        let p = parse_progress_line(
            r#"PROGRESS {"step":3,"total":6,"key":"gitleaks","label":"Checking for leaked passwords and keys"}"#,
        )
        .unwrap();
        assert_eq!(p.step, 3);
        assert_eq!(p.total, 6);
        assert_eq!(p.key, "gitleaks");
        assert_eq!(p.label, "Checking for leaked passwords and keys");
        assert_eq!(p.count, None);
    }

    #[test]
    fn open_ended_with_count() {
        let p = parse_progress_line(
            r#"PROGRESS {"step":0,"total":0,"key":"testing","label":"Testing your site","count":14,"unit":"checks"}"#,
        )
        .unwrap();
        assert_eq!((p.step, p.total, p.count), (0, 0, Some(14)));
        assert_eq!(p.unit.as_deref(), Some("checks"));
    }

    #[test]
    fn marker_after_other_output_still_parses() {
        assert!(parse_progress_line(r#"  3 / 7 done PROGRESS {"step":1,"total":2,"key":"a","label":"A"}"#).is_some());
    }

    #[test]
    fn garbage_is_ignored() {
        for bad in [
            "",
            "PROGRESS",
            "PROGRESS ",
            "PROGRESS not json",
            r#"PROGRESS {"step":1,"total":2"#, // partial
            r#"PROGRESS {"step":"x","total":2,"label":"A"}"#,
            r#"PROGRESS {"step":1,"total":2}"#, // no label
            r#"PROGRESS {"step":1,"total":2,"label":""}"#,
            r#"PROGRESS {"step":0,"total":2,"label":"A"}"#,
            r#"PROGRESS {"step":9,"total":2,"label":"A"}"#,
            r#"PROGRESS {"step":2,"total":0,"label":"A"}"#,
            r#"PROGRESS {"step":-1,"total":2,"label":"A"}"#,
            r#"PROGRESS [1,2,3]"#,
            "READY http://127.0.0.1:1",
            "\u{0}\u{1}\u{2}",
        ] {
            assert!(parse_progress_line(bad).is_none(), "should ignore {:?}", bad);
        }
        let long = format!(r#"PROGRESS {{"step":1,"total":2,"label":"{}"}}"#, "x".repeat(500));
        assert!(parse_progress_line(&long).is_none());
    }

    #[test]
    fn extract_splits_progress_from_other_lines() {
        let chunk = "hello\nPROGRESS {\"step\":1,\"total\":2,\"key\":\"a\",\"label\":\"A\"}\nPROGRESS {bad\nworld";
        let (found, rest) = extract_progress(chunk);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "A");
        assert_eq!(rest, "hello\nPROGRESS {bad\nworld");
    }

    #[test]
    fn extract_handles_ansi_and_empty() {
        let (found, rest) = extract_progress("\u{1b}[32mPROGRESS {\"step\":1,\"total\":1,\"key\":\"a\",\"label\":\"A\"}\u{1b}[0m");
        assert_eq!(found.len(), 1);
        assert_eq!(rest, "");
        let (found, rest) = extract_progress("");
        assert!(found.is_empty());
        assert_eq!(rest, "");
    }
}
