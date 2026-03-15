#![allow(dead_code)]
//! Security audit logging for DoD compliance (CMMC 2.0 AU domain).
//!
//! Produces structured JSON audit records for security-relevant events
//! including authentication attempts, file access, and configuration changes.
//! Designed for SIEM integration and forensic analysis.

use std::path::PathBuf;

use serde::Serialize;

/// Severity levels for audit events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Types of auditable security events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    AuthSuccess,
    AuthFailure,
    AuthLockout,
    FileRead,
    FileWrite,
    FileList,
    TlsHandshake,
    InsecureMode,
    ConnectionOpen,
    ConnectionClose,
    ServerStart,
    ServerStop,
}

/// A structured audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    pub source_ip: Option<String>,
    pub resource: Option<String>,
    pub outcome: String,
    pub details: Option<String>,
    pub session_id: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(event_type: AuditEventType, severity: AuditSeverity, outcome: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            severity,
            source_ip: None,
            resource: None,
            outcome: outcome.to_string(),
            details: None,
            session_id: None,
        }
    }

    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    pub fn with_resource(mut self, resource: &str) -> Self {
        self.resource = Some(resource.to_string());
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }
}

/// Path to the audit log file.
fn audit_log_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".aft").join("audit.log"))
}

/// Write an audit event to the audit log (one JSON object per line — JSON Lines format).
pub fn log_audit_event(event: &AuditEvent) {
    let path = match audit_log_path() {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(json) = serde_json::to_string(event) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Restrict log permissions on Unix (owner-only read/write)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            let _ = writeln!(file, "{}", json);
        }
    }
}

/// Log an authentication success event.
pub fn log_auth_success(source_ip: &str) {
    log_audit_event(
        &AuditEvent::new(AuditEventType::AuthSuccess, AuditSeverity::Info, "success")
            .with_source_ip(source_ip),
    );
}

/// Log an authentication failure event.
pub fn log_auth_failure(source_ip: &str, reason: &str) {
    log_audit_event(
        &AuditEvent::new(
            AuditEventType::AuthFailure,
            AuditSeverity::Warning,
            "failure",
        )
        .with_source_ip(source_ip)
        .with_details(reason),
    );
}

/// Log an authentication lockout event.
pub fn log_auth_lockout(source_ip: &str) {
    log_audit_event(
        &AuditEvent::new(
            AuditEventType::AuthLockout,
            AuditSeverity::Critical,
            "lockout",
        )
        .with_source_ip(source_ip)
        .with_details("Too many failed authentication attempts"),
    );
}

/// Log a file access event.
pub fn log_file_access(event_type: AuditEventType, source_ip: &str, resource: &str, bytes: u64) {
    log_audit_event(
        &AuditEvent::new(event_type, AuditSeverity::Info, "success")
            .with_source_ip(source_ip)
            .with_resource(resource)
            .with_details(&format!("{} bytes", bytes)),
    );
}

/// Log server lifecycle events.
pub fn log_server_event(event_type: AuditEventType, details: &str) {
    log_audit_event(
        &AuditEvent::new(event_type, AuditSeverity::Info, "success").with_details(details),
    );
}
