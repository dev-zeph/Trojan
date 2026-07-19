use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;

/// Shared helper — reads stdout from a sidecar until the Go binary emits
/// "READY <url>", then returns that URL to React for iframe rendering.
async fn await_ready(mut rx: tauri_plugin_shell::process::CommandReceiver) -> Result<String, String> {
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(bytes) => {
                let line = String::from_utf8_lossy(&bytes);
                if let Some(url) = line.trim().strip_prefix("READY ") {
                    return Ok(url.trim().to_string());
                }
            }
            CommandEvent::Stderr(bytes) => {
                eprintln!("[trojan] {}", String::from_utf8_lossy(&bytes).trim());
            }
            CommandEvent::Terminated(status) => {
                return Err(format!(
                    "process exited before READY (code: {:?})",
                    status.code
                ));
            }
            _ => {}
        }
    }
    Err("sidecar closed without emitting READY".to_string())
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

/// Run all static scanners (SAST/SCA/Secrets/IaC/SBOM) on a local path.
#[tauri::command]
async fn start_scan(app: AppHandle, path: String) -> Result<String, String> {
    let (rx, _child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["scan", &path, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;

    await_ready(rx).await
}

/// Run DAST scanning (Nuclei) against a live local server URL.
#[tauri::command]
async fn start_dast(app: AppHandle, url: String) -> Result<String, String> {
    let (rx, _child) = app
        .shell()
        .sidecar("trojan")
        .map_err(|e| format!("sidecar not found: {e}"))?
        .args(["dast", &url, "--desktop"])
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;

    await_ready(rx).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .invoke_handler(tauri::generate_handler![pick_folder, start_scan, start_dast])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
