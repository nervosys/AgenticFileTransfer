//! Configuration file support (~/.aft/config.toml).
//!
//! Loads default settings from a TOML file so users don't need to
//! specify common options on every invocation.

use serde::Deserialize;

use crate::error::{AftError, AftResult};

/// Top-level configuration structure mirroring CLI global options.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct AftConfig {
    /// Default output format ("text", "json", "quiet")
    pub format: Option<String>,
    /// Number of parallel connections
    pub parallel: Option<usize>,
    /// Maximum retry attempts
    pub retries: Option<u32>,
    /// Retry delay in milliseconds
    pub retry_delay_ms: Option<u64>,
    /// Connection timeout in seconds
    pub connect_timeout: Option<u64>,
    /// Transfer timeout in seconds (0 = none)
    pub timeout: Option<u64>,
    /// Skip TLS verification
    pub insecure: Option<bool>,
    /// Maximum bandwidth in bytes/sec (0 = unlimited)
    pub rate_limit: Option<u64>,
    /// Default user agent string
    pub user_agent: Option<String>,
    /// Default bearer token
    pub bearer_token: Option<String>,

    /// AFTP server settings
    pub server: Option<ServerConfig>,
}

/// Server-specific configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    pub port: Option<u16>,
    pub bind: Option<String>,
    pub compression: Option<bool>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub auth_token: Option<String>,
}

/// Returns `~/.aft/config.toml` path, or None if home dir is unavailable.
pub fn config_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".aft").join("config.toml"))
}

/// Load configuration from `~/.aft/config.toml`. Returns default if file doesn't exist.
pub fn load_config() -> AftResult<AftConfig> {
    let path = match config_path() {
        Some(p) => p,
        None => return Ok(AftConfig::default()),
    };

    if !path.exists() {
        return Ok(AftConfig::default());
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| AftError::Other(format!("Failed to read config {}: {}", path.display(), e)))?;

    let config: AftConfig = toml::from_str(&content)
        .map_err(|e| AftError::Other(format!("Invalid config {}: {}", path.display(), e)))?;

    Ok(config)
}

/// Ensure the `~/.aft/` directory exists.
pub fn ensure_aft_dir() -> AftResult<std::path::PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| AftError::Other("Cannot determine home directory".into()))?
        .join(".aft");

    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| AftError::Other(format!("Cannot create ~/.aft: {}", e)))?;
    }

    Ok(dir)
}
