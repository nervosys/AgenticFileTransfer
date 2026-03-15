//! Transfer history logging (~/.aft/history.jsonl).
//!
//! Appends a structured JSON Lines record after each completed transfer
//! so agents can query past operations and humans can audit transfer activity.
//! Uses append-only JSON Lines format (one JSON object per line) for O(1) writes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config;
use crate::engine::TransferResult;

/// A single history entry for a completed transfer.
#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: String,
    pub operation: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<String>,
    pub status: String,
    pub bytes_transferred: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Path to the history file.
fn history_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".aft").join("history.jsonl"))
}

/// Append a transfer record to the history file.
pub fn log_transfer(
    operation: &str,
    source: Option<&str>,
    destination: Option<&str>,
    protocol: Option<&str>,
    status: &str,
    transfer: Option<&TransferResult>,
    error: Option<&str>,
) {
    let path = match history_path() {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Err(_) = config::ensure_aft_dir() {
        return;
    }

    let entry = HistoryEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        source: source.map(scrub_url_credentials),
        destination: destination.map(scrub_url_credentials),
        protocol: protocol.map(|s| s.to_string()),
        status: status.to_string(),
        bytes_transferred: transfer.map(|t| t.bytes_transferred).unwrap_or(0),
        duration_ms: transfer.map(|t| t.duration_ms).unwrap_or(0),
        error: error.map(|s| s.to_string()),
    };

    // Append-only JSON Lines: one JSON object per line, O(1) per write
    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(file, "{}", json);
        }
    }
}

/// Remove credentials from URLs before logging.
/// Strips `user:password@` from URL authority and sensitive query params.
fn scrub_url_credentials(url: &str) -> String {
    // Handle scheme://user:pass@host patterns
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end];
        let rest = &url[scheme_end + 3..];

        // Find the @ sign before the first /
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];

        let cleaned_authority = if let Some(at_pos) = authority.rfind('@') {
            // Strip everything before @
            &authority[at_pos + 1..]
        } else {
            authority
        };

        let path_and_query = &rest[authority_end..];

        // Strip sensitive query params
        let cleaned_pq = scrub_query_params(path_and_query);

        format!("{}://{}{}", scheme, cleaned_authority, cleaned_pq)
    } else {
        url.to_string()
    }
}

/// Remove sensitive query parameters from a URL path+query string.
fn scrub_query_params(path_query: &str) -> String {
    if let Some(q_pos) = path_query.find('?') {
        let path = &path_query[..q_pos];
        let query = &path_query[q_pos + 1..];

        let sensitive = [
            "token", "key", "secret", "password", "sig", "se", "sp", "spr", "sv", "ss",
            "access_key", "secret_key", "api_key", "bearer", "oauth_token", "auth_code",
        ];
        let filtered: Vec<&str> = query
            .split('&')
            .filter(|param| {
                let name = param.split('=').next().unwrap_or("");
                !sensitive.iter().any(|s| name.eq_ignore_ascii_case(s))
            })
            .collect();

        if filtered.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, filtered.join("&"))
        }
    } else {
        path_query.to_string()
    }
}
