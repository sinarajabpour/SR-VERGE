//! Import-time check of a downloaded subscription against the bundled core.
//!
//! mihomo refuses to load a whole config when a single proxy is invalid
//! (unsupported cipher, malformed key, …), so one broken server in a
//! subscription would make every other server unusable. Before a profile is
//! saved, run the core's own `-t` check and drop each proxy it rejects.

use anyhow::Result;
use clash_verge_logging::{Type, logging};
use std::path::PathBuf;
use tauri_plugin_shell::ShellExt as _;

use crate::config::Config;
use crate::core::handle;
use crate::utils::{dirs, proxy_parser};

/// Upper bound on core runs, so a pathological subscription cannot stall
/// the import.
const MAX_PRUNE_ROUNDS: usize = 32;

/// Drop the proxies the core refuses to load.
///
/// Returns the (possibly) cleaned config and the names of the removed
/// proxies. On any problem running the check itself, the config is returned
/// unchanged and the normal activation path reports errors as before.
pub async fn prune_rejected_proxies(config: String) -> (String, Vec<String>) {
    match prune(&config).await {
        Ok(result) => result,
        Err(e) => {
            logging!(warn, Type::Validate, "import check skipped: {e:#}");
            (config, Vec::new())
        }
    }
}

async fn prune(original: &str) -> Result<(String, Vec<String>)> {
    let clash_core = Config::verge().await.latest_arc().get_valid_clash_core();
    let app_dir = dirs::app_home_dir()?;
    let check_file = app_dir.join(format!("import-check-{}.yaml", std::process::id()));
    let result = prune_with_core(original, clash_core.as_str(), &app_dir, &check_file).await;
    let _ = tokio::fs::remove_file(&check_file).await;
    result
}

async fn prune_with_core(
    original: &str,
    clash_core: &str,
    app_dir: &PathBuf,
    check_file: &PathBuf,
) -> Result<(String, Vec<String>)> {
    let app_dir = dirs::path_to_str(app_dir)?;
    let check_path = dirs::path_to_str(check_file)?;
    let mut config = original.to_owned();
    let mut dropped = Vec::new();

    for _ in 0..MAX_PRUNE_ROUNDS {
        tokio::fs::write(check_file, &config).await?;
        let command = handle::Handle::app_handle()
            .shell()
            .sidecar(clash_core)?
            .args(["-t", "-d", app_dir, "-f", check_path]);
        let output = tokio::time::timeout(crate::constants::timing::VALIDATION_TIMEOUT, command.output()).await??;
        if output.status.success() {
            break;
        }

        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Not a per-proxy problem: leave the config for the normal
        // activation path to report.
        let Some(index) = proxy_parser::rejected_proxy_index(&log) else {
            break;
        };
        let (next, name) = proxy_parser::remove_proxy(&config, index)?;
        logging!(
            warn,
            Type::Validate,
            "import check: core rejected proxy #{index} `{name}`, removed it"
        );
        dropped.push(name);
        config = next;
    }

    Ok((config, dropped))
}
