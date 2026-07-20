use tauri::{AppHandle, Emitter, Manager, async_runtime::Receiver};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_deep_link::DeepLinkExt;
use std::sync::Mutex;

/// Keeps spawned Go sidecar processes alive so their embedded HTTP servers
/// keep serving the report after `start_scan` / `start_dast` return.
struct ActiveScans(Mutex<Vec<CommandChild>>);

/// Strip ANSI escape sequences from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' { in_esc = false; }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Serializable return type carrying both the report URL and the cache file path.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanReturn {
    url: String,
    cache_path: String,
}

/// Reads stdout/stderr from the Go sidecar until it emits "READY <url>".
/// Also captures a "CACHE_PATH <path>" line that arrives before READY.
/// Returns `(url, cache_path)` on success.
async fn await_ready(mut rx: Receiver<CommandEvent>) -> Result<(String, String), String> {
    // Rolling buffer of the last 4 non-empty stdout lines (for error context).
    let mut last_stdout: Vec<String> = Vec::new();
    let mut last_stderr: Vec<String> = Vec::new();
    let mut cache_path = String::new();

    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(bytes) => {
                let raw = String::from_utf8_lossy(&bytes);
                let line = strip_ansi(raw.trim());

                // Capture CACHE_PATH before READY arrives.
                if let Some(pos) = line.find("CACHE_PATH ") {
                    let p = line[pos + 11..].trim().to_string();
                    if !p.is_empty() { cache_path = p; }
                }

                // Search for "READY " anywhere in the ANSI-stripped line.
                // The animation goroutine may interleave cursor sequences with
                // the READY signal, so we can't rely on it being at position 0.
                if let Some(pos) = line.find("READY ") {
                    let url = line[pos + 6..].trim().to_string();
                    if !url.is_empty() && url.starts_with("http") {
                        return Ok((url, cache_path));
                    }
                }

                if !line.is_empty() {
                    last_stdout.push(line);
                    if last_stdout.len() > 6 { last_stdout.remove(0); }
                }
            }
            CommandEvent::Stderr(bytes) => {
                let line = strip_ansi(String::from_utf8_lossy(&bytes).trim());
                eprintln!("[trojan stderr] {}", line);
                if !line.is_empty() {
                    last_stderr.push(line);
                    if last_stderr.len() > 4 { last_stderr.remove(0); }
                }
            }
            CommandEvent::Terminated(status) => {
                // Prefer stderr (panics, real errors) over stdout (progress noise).
                let detail = if !last_stderr.is_empty() {
                    last_stderr.join(" · ")
                } else if last_stdout.iter().any(|l| l.contains("No scanners")) {
                    return Err("No scanners installed. Run 'trojan init' in a terminal first.".to_string());
                } else if last_stdout.iter().any(|l| l.contains("could not start UI")) {
                    // Server startup failure — show the warning line
                    last_stdout.iter()
                        .find(|l| l.contains("could not start"))
                        .cloned()
                        .unwrap_or_else(|| format!("server failed to start (exit {:?})", status.code))
                } else {
                    // Show last 2 stdout lines — enough to see what went wrong
                    let tail: Vec<_> = last_stdout.iter().rev().take(2).rev().collect();
                    if tail.is_empty() {
                        format!("process exited (code {:?}) — try rebuilding the sidecar", status.code)
                    } else {
                        tail.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" · ")
                    }
                };
                return Err(format!("Scan failed: {}", detail));
            }
            _ => {}
        }
    }
    Err("Sidecar closed without starting — try rebuilding the binary.".to_string())
}

/// Open a native OS folder picker and return the selected path.
#[tauri::command]
async fn pick_folder(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .set_title("Choose a project to scan")
        .blocking_pick_folder()
        .map(|p| p.to_string())
}

/// Kill all previously tracked scan children, freeing their HTTP server ports.
fn kill_old_scans(app: &AppHandle) {
    if let Ok(mut children) = app.state::<ActiveScans>().0.lock() {
        for child in children.drain(..) {
            let _ = child.kill();
        }
    }
}

/// Run all static scanners on a local path.
#[tauri::command]
async fn start_scan(app: AppHandle, path: String) -> Result<ScanReturn, String> {
    // Kill any previous scan processes so their ports are freed before we start.
    kill_old_scans(&app);

    let (rx, child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["scan", &path, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let (url, cache_path) = await_ready(rx).await?;
    // Keep child alive — dropping it kills the embedded HTTP server.
    if let Ok(mut children) = app.state::<ActiveScans>().0.lock() {
        children.push(child);
    }
    Ok(ScanReturn { url, cache_path })
}

/// Run DAST scanning (Nuclei) against a live local server URL.
#[tauri::command]
async fn start_dast(app: AppHandle, url: String) -> Result<ScanReturn, String> {
    kill_old_scans(&app);

    let (rx, child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["dast", &url, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let (report_url, cache_path) = await_ready(rx).await?;
    if let Ok(mut children) = app.state::<ActiveScans>().0.lock() {
        children.push(child);
    }
    Ok(ScanReturn { url: report_url, cache_path })
}

/// Re-serve a previously cached scan result without re-running scanners.
#[tauri::command]
async fn serve_scan(app: AppHandle, cache_path: String) -> Result<String, String> {
    kill_old_scans(&app);

    let (rx, child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["serve", &cache_path, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let (url, _) = await_ready(rx).await?;
    if let Ok(mut children) = app.state::<ActiveScans>().0.lock() {
        children.push(child);
    }
    Ok(url)
}

/// Run a dependency-only scan (Trivy) and return the server URL + cache path.
/// Much faster than start_scan — only Trivy runs, no SAST/secrets/IaC.
#[tauri::command]
async fn scan_deps(app: AppHandle, path: String) -> Result<ScanReturn, String> {
    kill_old_scans(&app);

    let (rx, child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["deps", &path, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let (url, cache_path) = await_ready(rx).await?;
    if let Ok(mut children) = app.state::<ActiveScans>().0.lock() {
        children.push(child);
    }
    Ok(ScanReturn { url, cache_path })
}

/// Open a URL in the system browser (used for the auth flow).
#[tauri::command]
async fn open_auth(app: AppHandle, url: String) -> Result<(), String> {
    app.opener()
        .open_url(&url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            // Store for keeping Go sidecar child processes alive.
            app.manage(ActiveScans(Mutex::new(Vec::new())));

            // On Windows/Linux, register the trojan:// scheme at runtime so
            // deep links work in dev mode too. On macOS the scheme is baked
            // into Info.plist at build time — register_all() is unimplemented
            // there and panics, so we skip it on that platform.
            #[cfg(not(target_os = "macos"))]
            app.deep_link().register_all()?;

            // Forward deep-link URLs to the React frontend as a Tauri event.
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                let urls: Vec<String> = event.urls().iter().map(|u| u.to_string()).collect();
                let _ = handle.emit("deep-link-received", urls);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_folder,
            start_scan,
            start_dast,
            scan_deps,
            open_auth,
            serve_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
