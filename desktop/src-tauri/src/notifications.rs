//! Gentle "time to scan again" nudges. The frontend passes the known projects
//! (it owns the recent-projects store); this module decides who is due, sends
//! the desktop notification, and remembers when in ~/.trojan/notifications.json
//! so each project hears from us at most once a week.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;

/// A project is stale when its last scan is at least this many days old.
pub const STALE_AFTER_DAYS: i64 = 7;
/// Minimum days between two nudges for the same project.
pub const THROTTLE_DAYS: i64 = 7;
const DAY_SECS: i64 = 86_400;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NudgeState {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// project path -> unix seconds of the last nudge
    #[serde(default)]
    pub last_notified: HashMap<String, i64>,
}

fn default_true() -> bool {
    true
}

impl Default for NudgeState {
    fn default() -> Self {
        NudgeState { enabled: true, last_notified: HashMap::new() }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProjectInfo {
    pub path: String,
    pub name: String,
    /// Unix seconds of the last scan.
    pub last_scan: i64,
}

/// Pure decision: which projects should get a nudge right now.
pub fn due_projects<'a>(
    state: &NudgeState,
    projects: &'a [ProjectInfo],
    now: i64,
    stale_after_days: i64,
) -> Vec<&'a ProjectInfo> {
    if !state.enabled {
        return vec![];
    }
    projects
        .iter()
        .filter(|p| now - p.last_scan >= stale_after_days * DAY_SECS)
        .filter(|p| match state.last_notified.get(&p.path) {
            Some(t) => now - t >= THROTTLE_DAYS * DAY_SECS,
            None => true,
        })
        .collect()
}

pub fn message_for(p: &ProjectInfo, now: i64) -> String {
    let days = ((now - p.last_scan) / DAY_SECS).max(1);
    if days < 14 {
        format!("It's been a week since Trojan checked {}. Want a quick scan to see if it's still holding up?", p.name)
    } else {
        format!("It's been {} days since Trojan checked {}. Want a quick scan to see if it's still holding up?", days, p.name)
    }
}

fn state_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".trojan").join("notifications.json"))
}

fn load_state() -> NudgeState {
    state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(s: &NudgeState) {
    if let Some(p) = state_path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(s) {
            let _ = std::fs::write(p, json);
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Called by the frontend on start and then daily. Sends due notifications and
/// returns the paths that were nudged.
#[tauri::command]
pub fn nudge_check(app: AppHandle, projects: Vec<ProjectInfo>) -> Vec<String> {
    let now = now_secs();
    let mut state = load_state();
    let due: Vec<ProjectInfo> = due_projects(&state, &projects, now, STALE_AFTER_DAYS)
        .into_iter()
        .cloned()
        .collect();
    let mut sent = vec![];
    for p in due {
        let ok = app.notification().builder().title("Trojan").body(message_for(&p, now)).show().is_ok();
        if ok {
            state.last_notified.insert(p.path.clone(), now);
            sent.push(p.path);
        }
    }
    if !sent.is_empty() {
        save_state(&state);
    }
    sent
}

#[tauri::command]
pub fn get_nudge_enabled() -> bool {
    load_state().enabled
}

#[tauri::command]
pub fn set_nudge_enabled(enabled: bool) {
    let mut s = load_state();
    s.enabled = enabled;
    save_state(&s);
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: i64 = DAY_SECS;
    fn proj(path: &str, last_scan: i64) -> ProjectInfo {
        ProjectInfo { path: path.into(), name: path.into(), last_scan }
    }

    #[test]
    fn stale_threshold() {
        let now = 100 * D;
        let s = NudgeState::default();
        let ps = [proj("fresh", now - 6 * D), proj("edge", now - 7 * D), proj("old", now - 30 * D)];
        let due: Vec<_> = due_projects(&s, &ps, now, 7).iter().map(|p| p.path.clone()).collect();
        assert_eq!(due, vec!["edge", "old"]);
    }

    #[test]
    fn once_per_project_per_week() {
        let now = 100 * D;
        let mut s = NudgeState::default();
        s.last_notified.insert("a".into(), now - 3 * D);
        s.last_notified.insert("b".into(), now - 7 * D);
        let ps = [proj("a", now - 20 * D), proj("b", now - 20 * D), proj("c", now - 20 * D)];
        let due: Vec<_> = due_projects(&s, &ps, now, 7).iter().map(|p| p.path.clone()).collect();
        assert_eq!(due, vec!["b", "c"]);
    }

    #[test]
    fn respects_toggle() {
        let now = 100 * D;
        let s = NudgeState { enabled: false, ..Default::default() };
        assert!(due_projects(&s, &[proj("a", now - 30 * D)], now, 7).is_empty());
    }

    #[test]
    fn copy_has_no_em_dash_and_names_project() {
        let m = message_for(&proj("Shop", 0), 8 * D);
        assert!(m.contains("Shop") && !m.contains('\u{2014}'));
    }

    #[test]
    fn missing_fields_default_to_enabled() {
        let s: NudgeState = serde_json::from_str("{}").unwrap();
        assert!(s.enabled);
    }
}
