use std::path::PathBuf;

use crate::error::{Error, Result};

/// Default state root: `directories` data dir plus `batch-baker`.
///
/// * macOS: `~/Library/Application Support/batch-baker`
/// * Linux: `~/.local/share/batch-baker`
/// * Windows: `%APPDATA%\batch-baker`
pub fn default_state_home() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| Error::msg("could not resolve a home directory for state"))?;
    Ok(base.data_dir().join("batch-baker"))
}
