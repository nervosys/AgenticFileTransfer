// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Telemetry module for anonymous usage data collection.
//!
//! This module provides **opt-in (disabled by default)** anonymous usage
//! telemetry to help improve AFT. Nothing is collected or transmitted unless
//! the user explicitly opts in with `aft telemetry opt-in`. When enabled, no
//! personal data is collected — only aggregate usage statistics such as
//! commands used, protocol types, transfer sizes, and error types.
//!
//! When enabled, data is exported to an OpenTelemetry collector as the logs
//! signal over OTLP/HTTP. The exporter is configured entirely from the standard
//! `OTEL_EXPORTER_OTLP_*` environment variables (endpoint, protocol, headers)
//! plus `OTEL_SERVICE_NAME`; it defaults to `http/protobuf` and also supports
//! `http/json`. The collector's auth token is read from
//! `OTEL_EXPORTER_OTLP_HEADERS` at runtime and is never stored in the binary.
//! Users can opt back out at any time via `aft telemetry opt-out`.

use crate::error::{AftError, AftResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Default telemetry endpoint (Nervosys OpenTelemetry/OTLP collector)
pub const DEFAULT_TELEMETRY_ENDPOINT: &str = "https://nervosys.ai/otlp";

/// Telemetry configuration stored on disk (~/.aft/telemetry.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled (disabled by default; opt-in only)
    pub enabled: bool,

    /// Anonymous identifier for this installation (UUID v4)
    pub installation_id: String,

    /// When the config was first created (Unix timestamp)
    pub created_at: i64,

    /// When the user last changed their preference
    pub preference_changed_at: Option<i64>,

    /// Version of the config format
    pub version: u32,

    /// Remote telemetry endpoint URL
    #[serde(default = "default_endpoint")]
    pub remote_endpoint: String,

    /// API key for remote endpoint (optional, for authenticated endpoints)
    #[serde(default)]
    pub remote_api_key: Option<String>,

    /// Whether to send telemetry to remote endpoint (disabled by default).
    /// A config file written by an older, opt-out build that omits this field
    /// deserializes to `false` here, so upgrades never silently keep sending.
    #[serde(default)]
    pub remote_enabled: bool,
}

fn default_endpoint() -> String {
    DEFAULT_TELEMETRY_ENDPOINT.to_string()
}

/// Current telemetry config schema version. Bumped from 1 to 2 when the default
/// changed from opt-out to opt-in, which drives the one-time migration in
/// [`TelemetryConfig::load`].
const CONFIG_VERSION: u32 = 2;

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in: disabled until the user runs `telemetry opt-in`
            installation_id: generate_uuid(),
            created_at: chrono::Utc::now().timestamp(),
            preference_changed_at: None,
            version: CONFIG_VERSION,
            remote_endpoint: DEFAULT_TELEMETRY_ENDPOINT.to_string(),
            remote_api_key: None,
            remote_enabled: false, // Opt-in: no remote sending until enabled
        }
    }
}

/// Generate a UUID v4 using rand (no uuid crate dependency)
fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    // Format as UUID v4 (set version and variant bits)
    let mut uuid = bytes;
    uuid[6] = (uuid[6] & 0x0f) | 0x40; // Version 4
    uuid[8] = (uuid[8] & 0x3f) | 0x80; // Variant RFC 4122
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    )
}

impl TelemetryConfig {
    /// Get the path to the telemetry config file
    pub fn config_path() -> AftResult<PathBuf> {
        let config_dir = if cfg!(target_os = "windows") {
            dirs::config_dir().map(|p| p.join("aft"))
        } else {
            dirs::home_dir().map(|p| p.join(".aft"))
        };

        config_dir
            .map(|p| p.join("telemetry.json"))
            .ok_or_else(|| AftError::Other("Cannot determine config directory".into()))
    }

    /// Load telemetry config from disk, creating default if not exists
    pub fn load() -> AftResult<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let mut config: TelemetryConfig = serde_json::from_str(&content)
                .map_err(|e| AftError::Other(format!("Invalid telemetry config: {}", e)))?;
            // Migration to opt-in: a config written by an older opt-out build in
            // which the user never made an explicit choice
            // (`preference_changed_at` is None) must not keep telemetry on. Only
            // configs where the user actively chose are left untouched.
            if config.version < CONFIG_VERSION && config.preference_changed_at.is_none() {
                config.enabled = false;
                config.remote_enabled = false;
                config.version = CONFIG_VERSION;
                config.save()?;
            }
            Ok(config)
        } else {
            // First run: create the default (opt-in, telemetry disabled) config.
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Whether a telemetry config file already exists on disk. Used to detect a
    /// first run so the CLI can show a one-time opt-in notice.
    pub fn exists() -> bool {
        Self::config_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Save telemetry config to disk
    pub fn save(&self) -> AftResult<()> {
        let config_path = Self::config_path()?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| AftError::Other(format!("Failed to serialize telemetry config: {}", e)))?;
        fs::write(&config_path, content)?;

        Ok(())
    }

    /// Enable telemetry
    pub fn opt_in(&mut self) -> AftResult<()> {
        self.enabled = true;
        self.remote_enabled = true;
        self.preference_changed_at = Some(chrono::Utc::now().timestamp());
        self.save()
    }

    /// Disable telemetry
    pub fn opt_out(&mut self) -> AftResult<()> {
        self.enabled = false;
        self.remote_enabled = false;
        self.preference_changed_at = Some(chrono::Utc::now().timestamp());
        self.save()
    }

    /// Reset installation ID (generates new anonymous identifier)
    pub fn reset_id(&mut self) -> AftResult<()> {
        self.installation_id = generate_uuid();
        self.preference_changed_at = Some(chrono::Utc::now().timestamp());
        self.save()
    }

    /// Check if telemetry is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Configure remote endpoint
    pub fn set_endpoint(&mut self, endpoint: &str) -> AftResult<()> {
        self.remote_endpoint = endpoint.to_string();
        self.preference_changed_at = Some(chrono::Utc::now().timestamp());
        self.save()
    }

    /// Configure remote API key
    pub fn set_api_key(&mut self, api_key: Option<String>) -> AftResult<()> {
        self.remote_api_key = api_key;
        self.preference_changed_at = Some(chrono::Utc::now().timestamp());
        self.save()
    }

    /// Check if remote telemetry is enabled
    pub fn is_remote_enabled(&self) -> bool {
        self.enabled && self.remote_enabled
    }
}

// =============================================================================
// TELEMETRY EVENTS
// =============================================================================

/// Types of telemetry events we track
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TelemetryEvent {
    /// CLI command invoked
    CommandInvoked {
        command: String,
        subcommand: Option<String>,
        duration_ms: Option<u64>,
        success: bool,
    },

    /// File transfer completed
    TransferCompleted {
        protocol: String,
        direction: String, // "download" or "upload"
        size_bytes: u64,
        duration_ms: u64,
        parallel_connections: u32,
        resumed: bool,
        compressed: bool,
        encrypted: bool,
        success: bool,
    },

    /// Server started
    ServerStarted {
        port: u16,
        transport: String, // "tcp", "websocket", "quic"
        tls_enabled: bool,
    },

    /// Protocol used
    ProtocolUsed { protocol: String },

    /// Error occurred (no PII, just error type)
    ErrorOccurred {
        error_type: String,
        command: Option<String>,
    },

    /// Application started
    AppStarted {
        version: String,
        os: String,
        arch: String,
    },
}

// =============================================================================
// TELEMETRY RECORD (STRUCTURED DATA FOR AI ANALYSIS)
// =============================================================================

/// A structured telemetry record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRecord {
    /// Unique record ID
    pub id: String,

    /// Installation ID (anonymous)
    pub installation_id: String,

    /// Event category (e.g., "workflow", "error", "performance", "usage")
    pub category: String,

    /// Event name or type
    pub event: String,

    /// Structured data payload
    pub data: HashMap<String, serde_json::Value>,

    /// Tags for filtering
    pub tags: Vec<String>,

    /// Optional context/session ID
    pub context: Option<String>,

    /// Unix timestamp when recorded
    pub timestamp: i64,

    /// Human-readable timestamp (ISO 8601)
    pub timestamp_iso: String,

    /// AFT version
    pub version: String,
}

impl TelemetryRecord {
    /// Create a new telemetry record
    pub fn new(
        installation_id: &str,
        category: &str,
        event: &str,
        data: HashMap<String, serde_json::Value>,
        tags: Vec<String>,
        context: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: generate_uuid(),
            installation_id: installation_id.to_string(),
            category: category.to_string(),
            event: event.to_string(),
            data,
            tags,
            context,
            timestamp: now.timestamp(),
            timestamp_iso: now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

// =============================================================================
// OTLP/HTTP JSON MAPPING
// =============================================================================
// The remote collector speaks OpenTelemetry (OTLP/HTTP, JSON encoding). These
// helpers map our records onto the OTLP *logs* signal. Encoding rules that bite:
// per the protobuf-JSON mapping, 64-bit integer fields (`timeUnixNano`,
// `intValue`) are serialized as decimal **strings**, while doubles and bools are
// JSON numbers/bools.

/// OpenTelemetry severity for a record's category: ERROR for the "error"
/// category, INFO for everything else.
fn otlp_severity(category: &str) -> (i64, &'static str) {
    if category.eq_ignore_ascii_case("error") {
        (17, "ERROR")
    } else {
        (9, "INFO")
    }
}

/// Convert a JSON value into an OTLP `AnyValue` object.
fn otlp_any_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => serde_json::json!({ "stringValue": s }),
        Value::Bool(b) => serde_json::json!({ "boolValue": b }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::json!({ "intValue": i.to_string() })
            } else {
                serde_json::json!({ "doubleValue": n.as_f64().unwrap_or(0.0) })
            }
        }
        // Null, arrays, objects: keep the data as a compact JSON string rather
        // than dropping it or inventing a structure the collector may reject.
        Value::Null => serde_json::json!({ "stringValue": "" }),
        other => serde_json::json!({ "stringValue": other.to_string() }),
    }
}

/// One OTLP `KeyValue`.
fn otlp_kv(key: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "key": key, "value": value })
}

/// Convert telemetry records into an OTLP/HTTP JSON logs request body: a single
/// `resourceLogs` entry for this installation, one `logRecord` per record.
fn records_to_otlp_logs(
    service_name: &str,
    installation_id: &str,
    records: &[TelemetryRecord],
) -> serde_json::Value {
    let version = env!("CARGO_PKG_VERSION");
    let log_records: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            // seconds -> nanoseconds, widened so the multiply cannot overflow.
            let nanos = (r.timestamp as i128 * 1_000_000_000).to_string();
            let (sev_num, sev_text) = otlp_severity(&r.category);
            let mut attrs = vec![
                otlp_kv("category", serde_json::json!({ "stringValue": r.category })),
                otlp_kv("event", serde_json::json!({ "stringValue": r.event })),
                otlp_kv("record.id", serde_json::json!({ "stringValue": r.id })),
            ];
            if let Some(ctx) = &r.context {
                attrs.push(otlp_kv(
                    "context",
                    serde_json::json!({ "stringValue": ctx }),
                ));
            }
            if !r.tags.is_empty() {
                attrs.push(otlp_kv(
                    "tags",
                    serde_json::json!({ "stringValue": r.tags.join(",") }),
                ));
            }
            for (k, v) in &r.data {
                attrs.push(otlp_kv(k, otlp_any_value(v)));
            }
            serde_json::json!({
                "timeUnixNano": nanos,
                "observedTimeUnixNano": nanos,
                "severityNumber": sev_num,
                "severityText": sev_text,
                "body": { "stringValue": format!("{}.{}", r.category, r.event) },
                "attributes": attrs,
            })
        })
        .collect();

    serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    otlp_kv("service.name", serde_json::json!({ "stringValue": service_name })),
                    otlp_kv("service.version", serde_json::json!({ "stringValue": version })),
                    otlp_kv(
                        "service.instance.id",
                        serde_json::json!({ "stringValue": installation_id }),
                    ),
                ]
            },
            "scopeLogs": [{
                "scope": { "name": "aft.telemetry", "version": version },
                "logRecords": log_records,
            }]
        }]
    })
}

// =============================================================================
// OTLP EXPORTER CONFIG (standard OTEL_* environment variables)
// =============================================================================
// The exporter is configured the way any OpenTelemetry SDK would be, from the
// standard environment variables. Crucially, the auth token is read from
// `OTEL_EXPORTER_OTLP[_LOGS]_HEADERS` at runtime and is NEVER stored in the
// source tree or the binary.

/// OTLP/HTTP wire format, from `OTEL_EXPORTER_OTLP[_LOGS]_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpProtocol {
    HttpProtobuf,
    HttpJson,
}

/// Read a logs-signal-specific env var, falling back to the generic one.
fn otlp_env(specific: &str, generic: &str) -> Option<String> {
    std::env::var(specific)
        .or_else(|_| std::env::var(generic))
        .ok()
        .filter(|s| !s.is_empty())
}

/// Negotiated protocol. Defaults to protobuf (the OTLP default), matching a
/// collector configured with `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`.
fn otlp_protocol() -> OtlpProtocol {
    match otlp_env(
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
    )
    .as_deref()
    {
        Some("http/json") => OtlpProtocol::HttpJson,
        // "http/protobuf", "grpc" (we only do HTTP), unset, or anything else.
        _ => OtlpProtocol::HttpProtobuf,
    }
}

/// Service name from `OTEL_SERVICE_NAME`, defaulting to `aft`.
fn otlp_service_name() -> String {
    std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "aft".to_string())
}

/// Resolve the logs endpoint URL.
///
/// Per the OTLP spec, a signal-specific `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is
/// used verbatim, whereas the generic `OTEL_EXPORTER_OTLP_ENDPOINT` (or our
/// stored default) is a base to which the `/v1/logs` path is appended.
fn otlp_logs_endpoint(config_endpoint: &str) -> String {
    if let Ok(e) = std::env::var("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") {
        if !e.is_empty() {
            return e;
        }
    }
    let base = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| config_endpoint.to_string());
    format!("{}/v1/logs", base.trim_end_matches('/'))
}

/// Parse `OTEL_EXPORTER_OTLP[_LOGS]_HEADERS` — a comma-separated list of
/// `key=value` pairs (e.g. `Authorization=Bearer abc,X-Tenant=42`) — into
/// header pairs. `split_once('=')` keeps tokens that themselves contain `=`.
fn otlp_headers() -> Vec<(String, String)> {
    let raw = match otlp_env(
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ) {
        Some(r) => r,
        None => return Vec::new(),
    };
    raw.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}

// =============================================================================
// OTLP/HTTP PROTOBUF MAPPING
// =============================================================================
// Binary protobuf encoding of the same logs, for `OTEL_EXPORTER_OTLP_PROTOCOL=
// http/protobuf`. Uses the prost message types from `opentelemetry-proto`.

/// Build an OTLP `AnyValue` protobuf from a JSON value, mirroring
/// [`otlp_any_value`] but as the typed message.
fn otlp_any_value_pb(v: &serde_json::Value) -> opentelemetry_proto::tonic::common::v1::AnyValue {
    use opentelemetry_proto::tonic::common::v1::{any_value::Value as PbValue, AnyValue};
    use serde_json::Value;
    let value = match v {
        Value::String(s) => PbValue::StringValue(s.clone()),
        Value::Bool(b) => PbValue::BoolValue(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PbValue::IntValue(i)
            } else {
                PbValue::DoubleValue(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::Null => PbValue::StringValue(String::new()),
        other => PbValue::StringValue(other.to_string()),
    };
    AnyValue { value: Some(value) }
}

/// A string-valued OTLP `KeyValue` protobuf.
fn otlp_kv_pb(key: &str, val: &str) -> opentelemetry_proto::tonic::common::v1::KeyValue {
    use opentelemetry_proto::tonic::common::v1::{any_value::Value as PbValue, AnyValue, KeyValue};
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(PbValue::StringValue(val.to_string())),
        }),
    }
}

/// Encode telemetry records as a binary OTLP `ExportLogsServiceRequest`
/// (protobuf), ready to POST as `application/x-protobuf`.
fn records_to_otlp_protobuf(
    service_name: &str,
    installation_id: &str,
    records: &[TelemetryRecord],
) -> Vec<u8> {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
    use opentelemetry_proto::tonic::common::v1::{any_value::Value as PbValue, AnyValue, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{
        LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use prost::Message;

    let version = env!("CARGO_PKG_VERSION");

    let log_records: Vec<LogRecord> = records
        .iter()
        .map(|r| {
            // seconds -> nanoseconds; widen so the multiply cannot overflow, then
            // clamp back into the u64 the field expects.
            let nanos = (r.timestamp as i128 * 1_000_000_000).clamp(0, u64::MAX as i128) as u64;
            let (sev, sev_text) = if r.category.eq_ignore_ascii_case("error") {
                (SeverityNumber::Error, "ERROR")
            } else {
                (SeverityNumber::Info, "INFO")
            };
            let mut attributes = vec![
                otlp_kv_pb("category", &r.category),
                otlp_kv_pb("event", &r.event),
                otlp_kv_pb("record.id", &r.id),
            ];
            if let Some(ctx) = &r.context {
                attributes.push(otlp_kv_pb("context", ctx));
            }
            if !r.tags.is_empty() {
                attributes.push(otlp_kv_pb("tags", &r.tags.join(",")));
            }
            for (k, v) in &r.data {
                attributes.push(KeyValue {
                    key: k.clone(),
                    value: Some(otlp_any_value_pb(v)),
                });
            }
            LogRecord {
                time_unix_nano: nanos,
                observed_time_unix_nano: nanos,
                severity_number: sev as i32,
                severity_text: sev_text.to_string(),
                body: Some(AnyValue {
                    value: Some(PbValue::StringValue(format!("{}.{}", r.category, r.event))),
                }),
                attributes,
                dropped_attributes_count: 0,
                flags: 0,
                trace_id: Vec::new(),
                span_id: Vec::new(),
            }
        })
        .collect();

    let resource = Resource {
        attributes: vec![
            otlp_kv_pb("service.name", service_name),
            otlp_kv_pb("service.version", version),
            otlp_kv_pb("service.instance.id", installation_id),
        ],
        dropped_attributes_count: 0,
    };

    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "aft.telemetry".to_string(),
                    version: version.to_string(),
                    ..Default::default()
                }),
                log_records,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    request.encode_to_vec()
}

// =============================================================================
// TELEMETRY STORE (JSONL FILE STORAGE + REMOTE SYNC)
// =============================================================================

/// Storage for telemetry records (JSONL file for easy streaming/appending)
pub struct TelemetryStore {
    config: TelemetryConfig,
}

impl TelemetryStore {
    /// Create a new telemetry store
    pub fn new() -> AftResult<Self> {
        let config = TelemetryConfig::load()?;
        Ok(Self { config })
    }

    /// Get path to the telemetry records file
    pub fn records_path() -> AftResult<PathBuf> {
        let config_dir = if cfg!(target_os = "windows") {
            dirs::config_dir().map(|p| p.join("aft"))
        } else {
            dirs::home_dir().map(|p| p.join(".aft"))
        };

        config_dir
            .map(|p| p.join("telemetry_records.jsonl"))
            .ok_or_else(|| AftError::Other("Cannot determine config directory".into()))
    }

    /// Check if telemetry is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }

    /// Record a new telemetry event
    pub fn record(
        &self,
        category: &str,
        event: &str,
        data: HashMap<String, serde_json::Value>,
        tags: Vec<String>,
        context: Option<String>,
    ) -> AftResult<TelemetryRecord> {
        if !self.is_enabled() {
            return Err(AftError::Other("Telemetry is disabled".into()));
        }

        let record = TelemetryRecord::new(
            &self.config.installation_id,
            category,
            event,
            data,
            tags,
            context,
        );

        // Append to JSONL file
        let path = Self::records_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        let line = serde_json::to_string(&record)
            .map_err(|e| AftError::Other(format!("Failed to serialize record: {}", e)))?;
        writeln!(file, "{}", line)?;

        Ok(record)
    }

    /// Record a TelemetryEvent
    pub fn record_event(&self, event: TelemetryEvent) -> AftResult<TelemetryRecord> {
        if !self.is_enabled() {
            return Err(AftError::Other("Telemetry is disabled".into()));
        }

        let (category, event_name, data) = match &event {
            TelemetryEvent::CommandInvoked {
                command,
                subcommand,
                duration_ms,
                success,
            } => {
                let mut d = HashMap::new();
                d.insert("command".to_string(), serde_json::json!(command));
                if let Some(sub) = subcommand {
                    d.insert("subcommand".to_string(), serde_json::json!(sub));
                }
                if let Some(ms) = duration_ms {
                    d.insert("duration_ms".to_string(), serde_json::json!(ms));
                }
                d.insert("success".to_string(), serde_json::json!(success));
                ("usage", "command_invoked", d)
            }
            TelemetryEvent::TransferCompleted {
                protocol,
                direction,
                size_bytes,
                duration_ms,
                parallel_connections,
                resumed,
                compressed,
                encrypted,
                success,
            } => {
                let mut d = HashMap::new();
                d.insert("protocol".to_string(), serde_json::json!(protocol));
                d.insert("direction".to_string(), serde_json::json!(direction));
                d.insert("size_bytes".to_string(), serde_json::json!(size_bytes));
                d.insert("duration_ms".to_string(), serde_json::json!(duration_ms));
                d.insert(
                    "parallel_connections".to_string(),
                    serde_json::json!(parallel_connections),
                );
                d.insert("resumed".to_string(), serde_json::json!(resumed));
                d.insert("compressed".to_string(), serde_json::json!(compressed));
                d.insert("encrypted".to_string(), serde_json::json!(encrypted));
                d.insert("success".to_string(), serde_json::json!(success));
                ("performance", "transfer_completed", d)
            }
            TelemetryEvent::ServerStarted {
                port,
                transport,
                tls_enabled,
            } => {
                let mut d = HashMap::new();
                d.insert("port".to_string(), serde_json::json!(port));
                d.insert("transport".to_string(), serde_json::json!(transport));
                d.insert("tls_enabled".to_string(), serde_json::json!(tls_enabled));
                ("usage", "server_started", d)
            }
            TelemetryEvent::ProtocolUsed { protocol } => {
                let mut d = HashMap::new();
                d.insert("protocol".to_string(), serde_json::json!(protocol));
                ("usage", "protocol_used", d)
            }
            TelemetryEvent::ErrorOccurred {
                error_type,
                command,
            } => {
                let mut d = HashMap::new();
                d.insert("error_type".to_string(), serde_json::json!(error_type));
                if let Some(cmd) = command {
                    d.insert("command".to_string(), serde_json::json!(cmd));
                }
                ("error", "error_occurred", d)
            }
            TelemetryEvent::AppStarted { version, os, arch } => {
                let mut d = HashMap::new();
                d.insert("version".to_string(), serde_json::json!(version));
                d.insert("os".to_string(), serde_json::json!(os));
                d.insert("arch".to_string(), serde_json::json!(arch));
                ("usage", "app_started", d)
            }
        };

        self.record(category, event_name, data, vec![], None)
    }

    /// Read all records, optionally filtered
    pub fn read_records(
        &self,
        category: Option<&str>,
        event: Option<&str>,
        after: Option<i64>,
        before: Option<i64>,
        limit: Option<usize>,
    ) -> AftResult<Vec<TelemetryRecord>> {
        let path = Self::records_path()?;
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut records: Vec<TelemetryRecord> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let record: TelemetryRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => continue, // Skip malformed records
            };

            // Apply filters
            if let Some(cat) = category {
                if record.category != cat {
                    continue;
                }
            }
            if let Some(evt) = event {
                if record.event != evt {
                    continue;
                }
            }
            if let Some(after_ts) = after {
                if record.timestamp < after_ts {
                    continue;
                }
            }
            if let Some(before_ts) = before {
                if record.timestamp > before_ts {
                    continue;
                }
            }

            records.push(record);
        }

        // Sort by timestamp descending (newest first)
        records.sort_by_key(|r| std::cmp::Reverse(r.timestamp));

        // Apply limit
        if let Some(lim) = limit {
            records.truncate(lim);
        }

        Ok(records)
    }

    /// Get record count
    pub fn count_records(&self) -> AftResult<usize> {
        let path = Self::records_path()?;
        if !path.exists() {
            return Ok(0);
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        Ok(reader.lines().filter(|l| l.is_ok()).count())
    }

    /// Clear all records
    pub fn clear_records(&self) -> AftResult<usize> {
        let path = Self::records_path()?;
        if !path.exists() {
            return Ok(0);
        }

        let count = self.count_records()?;
        fs::remove_file(&path)?;
        Ok(count)
    }

    /// Get the installation ID
    #[allow(dead_code)] // Public API for telemetry consumers
    pub fn installation_id(&self) -> &str {
        &self.config.installation_id
    }

    /// Get the config
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Sync records to remote endpoint (async)
    pub async fn sync_to_remote(&self, limit: Option<usize>) -> AftResult<SyncResult> {
        if !self.config.is_remote_enabled() {
            return Err(AftError::Other(
                "Remote telemetry is disabled. Use 'aft telemetry opt-in' to enable.".into(),
            ));
        }

        // Read records to sync
        let records = self.read_records(None, None, None, None, limit)?;

        if records.is_empty() {
            return Ok(SyncResult {
                records_sent: 0,
                success: true,
                error: None,
            });
        }

        // Resolve the exporter configuration from the standard OpenTelemetry
        // environment variables, falling back to the stored config. This is why
        // the auth token is never baked into the binary: it arrives at runtime
        // via `OTEL_EXPORTER_OTLP_HEADERS` (e.g. `Authorization=Bearer …`).
        let service_name = otlp_service_name();
        let protocol = otlp_protocol();
        let url = otlp_logs_endpoint(&self.config.remote_endpoint);

        // Encode the batch in the negotiated wire format.
        let (body, content_type) = match protocol {
            OtlpProtocol::HttpProtobuf => (
                records_to_otlp_protobuf(&service_name, &self.config.installation_id, &records),
                "application/x-protobuf",
            ),
            OtlpProtocol::HttpJson => {
                let json =
                    records_to_otlp_logs(&service_name, &self.config.installation_id, &records);
                (
                    serde_json::to_vec(&json).unwrap_or_default(),
                    "application/json",
                )
            }
        };

        let client = reqwest::Client::new();
        let mut request = client
            .post(url)
            .header("Content-Type", content_type)
            .header("User-Agent", format!("aft/{}", env!("CARGO_PKG_VERSION")));

        // Headers from OTEL_EXPORTER_OTLP[_LOGS]_HEADERS (auth lives here).
        for (k, v) in otlp_headers() {
            request = request.header(k, v);
        }
        // Back-compat: an API key stored in the telemetry config still applies
        // (skipped if an Authorization header was already supplied via env).
        if let Some(ref api_key) = self.config.remote_api_key {
            request = request.header("X-Api-Key", api_key);
        }

        let response = request.body(body).send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    Ok(SyncResult {
                        records_sent: records.len(),
                        success: true,
                        error: None,
                    })
                } else {
                    let status = resp.status();
                    let error_text = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Ok(SyncResult {
                        records_sent: 0,
                        success: false,
                        error: Some(format!("HTTP {}: {}", status, error_text)),
                    })
                }
            }
            Err(e) => Ok(SyncResult {
                records_sent: 0,
                success: false,
                error: Some(format!("Request failed: {}", e)),
            }),
        }
    }
}

/// Result of a sync operation
#[derive(Debug)]
pub struct SyncResult {
    pub records_sent: usize,
    pub success: bool,
    pub error: Option<String>,
}

// =============================================================================
// TELEMETRY COLLECTOR (CONVENIENCE WRAPPER)
// =============================================================================

/// Telemetry collector that batches and sends events
pub struct TelemetryCollector {
    store: TelemetryStore,
    pending_events: Vec<TelemetryEvent>,
}

impl TelemetryCollector {
    /// Create a new telemetry collector
    pub fn new() -> AftResult<Self> {
        let store = TelemetryStore::new()?;
        Ok(Self {
            store,
            pending_events: Vec::new(),
        })
    }

    /// Check if telemetry is enabled
    pub fn is_enabled(&self) -> bool {
        self.store.is_enabled()
    }

    /// Track a telemetry event (queues for batching)
    pub fn track(&mut self, event: TelemetryEvent) {
        if self.is_enabled() {
            self.pending_events.push(event);
        }
    }

    /// Track a CLI command invocation
    pub fn track_command(
        &mut self,
        command: &str,
        subcommand: Option<&str>,
        duration_ms: Option<u64>,
        success: bool,
    ) {
        self.track(TelemetryEvent::CommandInvoked {
            command: command.to_string(),
            subcommand: subcommand.map(|s| s.to_string()),
            duration_ms,
            success,
        });
    }

    /// Track a transfer completion
    #[allow(clippy::too_many_arguments)]
    pub fn track_transfer(
        &mut self,
        protocol: &str,
        direction: &str,
        size_bytes: u64,
        duration_ms: u64,
        parallel: u32,
        resumed: bool,
        compressed: bool,
        encrypted: bool,
        success: bool,
    ) {
        self.track(TelemetryEvent::TransferCompleted {
            protocol: protocol.to_string(),
            direction: direction.to_string(),
            size_bytes,
            duration_ms,
            parallel_connections: parallel,
            resumed,
            compressed,
            encrypted,
            success,
        });
    }

    /// Track an error
    pub fn track_error(&mut self, error_type: &str, command: Option<&str>) {
        self.track(TelemetryEvent::ErrorOccurred {
            error_type: error_type.to_string(),
            command: command.map(|s| s.to_string()),
        });
    }

    /// Get the installation ID
    #[allow(dead_code)] // Public API for telemetry consumers
    pub fn installation_id(&self) -> &str {
        self.store.installation_id()
    }

    /// Flush pending events to disk
    pub fn flush(&mut self) -> AftResult<()> {
        if !self.is_enabled() || self.pending_events.is_empty() {
            return Ok(());
        }

        for event in self.pending_events.drain(..) {
            // Ignore errors during flush (best-effort telemetry)
            let _ = self.store.record_event(event);
        }

        Ok(())
    }
}

impl Drop for TelemetryCollector {
    fn drop(&mut self) {
        // Try to flush remaining events on drop
        let _ = self.flush();
    }
}

// =============================================================================
// INFO TEXT
// =============================================================================

/// What data is collected (for user information)
pub const TELEMETRY_INFO: &str = r#"
AFT collects anonymous usage data to help improve the product.

WHAT WE COLLECT:
  • Commands used (e.g., 'get', 'put', 'serve')
  • Protocol types (e.g., 'http', 'sftp', 's3', 'aftp')
  • Transfer sizes and durations (numbers only)
  • Error types (no personal details or file paths)
  • Anonymous installation ID (randomly generated UUID)
  • OS and architecture (e.g., 'windows', 'x86_64')

WHAT WE DO NOT COLLECT:
  • File names, paths, or content
  • URLs or hostnames
  • Personal information
  • API keys, tokens, or credentials
  • IP addresses (beyond what's needed for HTTPS)

Your installation ID: {installation_id}
Status: {status}
Endpoint: {endpoint}

Manage your preference:
  aft telemetry opt-in   - Enable data collection
  aft telemetry opt-out  - Disable data collection (default)
  aft telemetry reset    - Generate new anonymous ID
  aft telemetry status   - Show current status
  aft telemetry sync     - Manually sync to remote
"#;

/// Format the telemetry info text with current values
pub fn format_telemetry_info(config: &TelemetryConfig) -> String {
    TELEMETRY_INFO
        .replace("{installation_id}", &config.installation_id)
        .replace(
            "{status}",
            if config.enabled {
                "Enabled"
            } else {
                "Disabled"
            },
        )
        .replace("{endpoint}", &config.remote_endpoint)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_generation() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();

        // Check format: 8-4-4-4-12
        assert_eq!(uuid1.len(), 36);
        assert_eq!(uuid1.chars().nth(8), Some('-'));
        assert_eq!(uuid1.chars().nth(13), Some('-'));
        assert_eq!(uuid1.chars().nth(18), Some('-'));
        assert_eq!(uuid1.chars().nth(23), Some('-'));

        // Check uniqueness
        assert_ne!(uuid1, uuid2);

        // Check version nibble (should be '4')
        assert_eq!(uuid1.chars().nth(14), Some('4'));
    }

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();

        // Opt-in by default: telemetry is off until the user explicitly enables it.
        assert!(!config.enabled);
        assert!(!config.remote_enabled);
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.remote_endpoint, DEFAULT_TELEMETRY_ENDPOINT);
        assert!(config.remote_api_key.is_none());
        assert!(!config.installation_id.is_empty());
    }

    #[test]
    fn test_telemetry_record_creation() {
        let mut data = HashMap::new();
        data.insert("key".to_string(), serde_json::json!("value"));

        let record = TelemetryRecord::new(
            "test-install-id",
            "test",
            "test_event",
            data,
            vec!["tag1".to_string()],
            None,
        );

        assert_eq!(record.installation_id, "test-install-id");
        assert_eq!(record.category, "test");
        assert_eq!(record.event, "test_event");
        assert_eq!(record.version, env!("CARGO_PKG_VERSION"));
        assert!(!record.id.is_empty());
    }

    #[test]
    fn otlp_logs_payload_shape() {
        let mut data = HashMap::new();
        data.insert("bytes".to_string(), serde_json::json!(1024_i64));
        data.insert("ratio".to_string(), serde_json::json!(0.5_f64));
        data.insert("ok".to_string(), serde_json::json!(true));
        let rec = TelemetryRecord::new("inst-1", "usage", "put", data, vec![], None);

        let body = records_to_otlp_logs("aft", "inst-1", std::slice::from_ref(&rec));
        let lr = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];

        // int64 fields are encoded as decimal strings per OTLP/JSON.
        assert!(lr["timeUnixNano"].is_string());
        assert_eq!(lr["body"]["stringValue"], "usage.put");
        assert_eq!(lr["severityText"], "INFO");

        // resource identifies the installation.
        let res_attrs = &body["resourceLogs"][0]["resource"]["attributes"];
        let joined = res_attrs.to_string();
        assert!(joined.contains("service.instance.id") && joined.contains("inst-1"));

        // AnyValue typing: int → string intValue, double → number, bool → bool.
        let attrs = lr["attributes"].as_array().unwrap();
        let find = |k: &str| attrs.iter().find(|a| a["key"] == k).unwrap()["value"].clone();
        assert_eq!(find("bytes")["intValue"], "1024");
        assert_eq!(find("ratio")["doubleValue"], serde_json::json!(0.5));
        assert_eq!(find("ok")["boolValue"], serde_json::json!(true));
    }

    #[test]
    fn otlp_error_category_maps_to_error_severity() {
        let rec = TelemetryRecord::new("i", "error", "boom", HashMap::new(), vec![], None);
        let body = records_to_otlp_logs("aft", "i", std::slice::from_ref(&rec));
        let lr = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["severityText"], "ERROR");
        assert_eq!(lr["severityNumber"], 17);
    }

    #[test]
    fn otlp_protobuf_decodes_back_to_the_records() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
        use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
        use prost::Message;

        let mut data = HashMap::new();
        data.insert("bytes".to_string(), serde_json::json!(2048_i64));
        let rec = TelemetryRecord::new("inst-9", "error", "boom", data, vec![], None);

        let bytes = records_to_otlp_protobuf("my-app", "inst-9", std::slice::from_ref(&rec));
        // Round-trips through the wire format.
        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
        let rl = &req.resource_logs[0];
        let lr = &rl.scope_logs[0].log_records[0];

        assert_eq!(lr.severity_number, SeverityNumber::Error as i32);
        // Resource carries the OTEL_SERVICE_NAME we passed.
        let svc = rl
            .resource
            .as_ref()
            .unwrap()
            .attributes
            .iter()
            .find(|kv| kv.key == "service.name")
            .and_then(|kv| kv.value.clone())
            .unwrap();
        assert!(matches!(
            svc.value,
            Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(ref s)) if s == "my-app"
        ));
        // The int attribute survives as an OTLP intValue.
        let bytes_attr = lr.attributes.iter().find(|kv| kv.key == "bytes").unwrap();
        assert!(matches!(
            bytes_attr.value.as_ref().unwrap().value,
            Some(opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(2048))
        ));
    }

    #[test]
    fn otlp_headers_parse_bearer_with_spaces_and_multiple_pairs() {
        std::env::set_var(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "Authorization=Bearer abc.def-ghi,X-Tenant=42",
        );
        let hdrs = otlp_headers();
        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        assert!(hdrs.contains(&(
            "Authorization".to_string(),
            "Bearer abc.def-ghi".to_string()
        )));
        assert!(hdrs.contains(&("X-Tenant".to_string(), "42".to_string())));
    }
}
