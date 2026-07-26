// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use colored::*;
use serde::Serialize;

use crate::output::Format;

/// Full ontology schema describing all AFT capabilities.
///
/// This is a self-describing, machine-readable specification that AI agents
/// can use to discover, understand, and correctly invoke AFT operations.
/// Output via `aft schema` or `aft --agent schema`.
#[derive(Serialize)]
pub struct OntologySchema {
    /// JSON-LD context for semantic interoperability
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// All supported operations with full parameter schemas
    pub operations: Vec<OperationSchema>,
    /// Supported transfer protocols and their capabilities
    pub protocols: Vec<ProtocolInfo>,
    /// Available output formats
    pub output_formats: Vec<String>,
    /// Global CLI options applicable to all operations
    pub global_options: Vec<OptionSchema>,
    /// Schema for the structured output returned by all operations
    pub output_schema: OutputSchemaRef,
    /// Agent integration guidance
    pub agent_usage: AgentUsage,
}

#[derive(Serialize)]
pub struct OperationSchema {
    pub name: String,
    pub description: String,
    pub usage: String,
    pub parameters: Vec<ParameterSchema>,
    pub returns: String,
}

#[derive(Serialize)]
pub struct ParameterSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub required: bool,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Serialize)]
pub struct ProtocolInfo {
    pub scheme: String,
    pub name: String,
    pub supports_download: bool,
    pub supports_upload: bool,
    pub supports_list: bool,
    pub supports_resume: bool,
    pub supports_ranges: bool,
    /// "active" = fully implemented, "planned" = trait stub present
    pub status: String,
}

#[derive(Serialize)]
pub struct OptionSchema {
    pub flag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Serialize)]
pub struct OutputSchemaRef {
    pub description: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Serialize)]
pub struct FieldSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct AgentUsage {
    pub recommended_flags: Vec<String>,
    pub output_parsing: String,
    pub error_handling: String,
    pub discovery: String,
    pub examples: Vec<AgentExample>,
}

#[derive(Serialize)]
pub struct AgentExample {
    pub task: String,
    pub command: String,
    pub notes: String,
}

pub fn generate_schema() -> OntologySchema {
    OntologySchema {
        context: "https://schema.org".to_string(),
        type_: "SoftwareApplication".to_string(),
        name: "aft".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "Agentic File Transfer — High-performance file transfer CLI for humans and AI agents".to_string(),

        operations: vec![
            OperationSchema {
                name: "get".to_string(),
                description: "Download a file from a URL to local storage".to_string(),
                usage: "aft get <url> [-o output]".to_string(),
                parameters: vec![
                    ParameterSchema { name: "url".to_string(), type_: "string".to_string(), required: true, description: "Source URL (http, https, ftp, sftp, s3, file)".to_string(), default: None },
                    ParameterSchema { name: "--output / -o".to_string(), type_: "string".to_string(), required: false, description: "Output file or directory path".to_string(), default: Some("filename from URL".to_string()) },
                    ParameterSchema { name: "--resume".to_string(), type_: "bool".to_string(), required: false, description: "Resume partially downloaded file".to_string(), default: Some("false".to_string()) },
                    ParameterSchema { name: "--checksum".to_string(), type_: "enum(sha256, sha512, md5)".to_string(), required: false, description: "Verify with checksum algorithm".to_string(), default: None },
                    ParameterSchema { name: "--checksum-value".to_string(), type_: "string".to_string(), required: false, description: "Expected checksum hex value".to_string(), default: None },
                    ParameterSchema { name: "--header / -H".to_string(), type_: "string (repeatable)".to_string(), required: false, description: "Custom HTTP header (format: key:value)".to_string(), default: None },
                    ParameterSchema { name: "--bearer-token".to_string(), type_: "string".to_string(), required: false, description: "Bearer token for auth".to_string(), default: None },
                    ParameterSchema { name: "--auth".to_string(), type_: "string".to_string(), required: false, description: "Basic auth (format: user:password)".to_string(), default: None },
                    ParameterSchema { name: "--max-redirects".to_string(), type_: "integer".to_string(), required: false, description: "Max HTTP redirects".to_string(), default: Some("10".to_string()) },
                ],
                returns: "TransferResult with bytes_transferred, duration_ms, throughput, checksum".to_string(),
            },
            OperationSchema {
                name: "put".to_string(),
                description: "Upload a local file to a remote URL".to_string(),
                usage: "aft put <source> <url>".to_string(),
                parameters: vec![
                    ParameterSchema { name: "source".to_string(), type_: "string".to_string(), required: true, description: "Local file path to upload".to_string(), default: None },
                    ParameterSchema { name: "url".to_string(), type_: "string".to_string(), required: true, description: "Destination URL".to_string(), default: None },
                    ParameterSchema { name: "--content-type".to_string(), type_: "string".to_string(), required: false, description: "MIME content type".to_string(), default: None },
                    ParameterSchema { name: "--method".to_string(), type_: "enum(PUT, POST, PATCH)".to_string(), required: false, description: "HTTP method".to_string(), default: Some("PUT".to_string()) },
                ],
                returns: "TransferResult".to_string(),
            },
            OperationSchema {
                name: "copy".to_string(),
                description: "Copy files between any two locations (local or remote)".to_string(),
                usage: "aft copy <source> <destination>".to_string(),
                parameters: vec![
                    ParameterSchema { name: "source".to_string(), type_: "string".to_string(), required: true, description: "Source path or URL".to_string(), default: None },
                    ParameterSchema { name: "destination".to_string(), type_: "string".to_string(), required: true, description: "Destination path or URL".to_string(), default: None },
                    ParameterSchema { name: "--recursive / -r".to_string(), type_: "bool".to_string(), required: false, description: "Recurse into directories".to_string(), default: Some("false".to_string()) },
                ],
                returns: "TransferResult".to_string(),
            },
            OperationSchema {
                name: "head".to_string(),
                description: "Inspect remote resource metadata without downloading".to_string(),
                usage: "aft head <url>".to_string(),
                parameters: vec![
                    ParameterSchema { name: "url".to_string(), type_: "string".to_string(), required: true, description: "URL to inspect".to_string(), default: None },
                ],
                returns: "ResourceMetadata with content_length, content_type, last_modified, etag, headers".to_string(),
            },
            OperationSchema {
                name: "ls".to_string(),
                description: "List contents of a remote or local directory".to_string(),
                usage: "aft ls <url>".to_string(),
                parameters: vec![
                    ParameterSchema { name: "url".to_string(), type_: "string".to_string(), required: true, description: "Directory URL or path".to_string(), default: None },
                ],
                returns: "Array of DirectoryEntry with name, size, is_directory, last_modified".to_string(),
            },
            OperationSchema {
                name: "checksum".to_string(),
                description: "Compute checksum of a local file".to_string(),
                usage: "aft checksum <path> [--algorithm sha256]".to_string(),
                parameters: vec![
                    ParameterSchema { name: "path".to_string(), type_: "string".to_string(), required: true, description: "File path".to_string(), default: None },
                    ParameterSchema { name: "--algorithm / -a".to_string(), type_: "enum(sha256, sha512, md5)".to_string(), required: false, description: "Hash algorithm".to_string(), default: Some("sha256".to_string()) },
                ],
                returns: "ChecksumResult with algorithm, value".to_string(),
            },
            OperationSchema {
                name: "schema".to_string(),
                description: "Output the full agentic ontology schema as JSON".to_string(),
                usage: "aft schema".to_string(),
                parameters: vec![],
                returns: "OntologySchema JSON document".to_string(),
            },
            OperationSchema {
                name: "capabilities".to_string(),
                description: "List available protocols, operations, and features".to_string(),
                usage: "aft capabilities".to_string(),
                parameters: vec![],
                returns: "Capabilities report".to_string(),
            },
            OperationSchema {
                name: "serve".to_string(),
                description: "Start an AFTP file server for high-performance binary transfers".to_string(),
                usage: "aft serve <root> [--port 2600] [--bind 0.0.0.0] [--auth-token TOKEN] [--compression]".to_string(),
                parameters: vec![
                    ParameterSchema { name: "root".to_string(), type_: "string".to_string(), required: true, description: "Directory to serve files from".to_string(), default: None },
                    ParameterSchema { name: "--port".to_string(), type_: "integer".to_string(), required: false, description: "TCP port (default 2600)".to_string(), default: Some("2600".to_string()) },
                    ParameterSchema { name: "--bind".to_string(), type_: "string".to_string(), required: false, description: "Bind address".to_string(), default: Some("0.0.0.0".to_string()) },
                    ParameterSchema { name: "--auth-token".to_string(), type_: "string".to_string(), required: false, description: "Pre-shared auth token".to_string(), default: None },
                    ParameterSchema { name: "--compression".to_string(), type_: "bool".to_string(), required: false, description: "Enable zstd compression".to_string(), default: Some("false".to_string()) },
                ],
                returns: "Server status (runs until interrupted)".to_string(),
            },
            OperationSchema {
                name: "crypto".to_string(),
                description: "Quantum-resistant cryptographic operations (ML-KEM-1024 + AES-256-GCM, neural network cipher)".to_string(),
                usage: "aft crypto <keygen|train|encrypt|decrypt> [options]".to_string(),
                parameters: vec![
                    ParameterSchema { name: "action".to_string(), type_: "enum(keygen, train, encrypt, decrypt)".to_string(), required: true, description: "Cryptographic action to perform".to_string(), default: None },
                    ParameterSchema { name: "--input / -i".to_string(), type_: "string".to_string(), required: false, description: "Input file path".to_string(), default: None },
                    ParameterSchema { name: "--output / -o".to_string(), type_: "string".to_string(), required: false, description: "Output file path".to_string(), default: None },
                    ParameterSchema { name: "--public-key".to_string(), type_: "string".to_string(), required: false, description: "Path to public key file (PEM)".to_string(), default: None },
                    ParameterSchema { name: "--secret-key".to_string(), type_: "string".to_string(), required: false, description: "Path to secret key file (PEM)".to_string(), default: None },
                    ParameterSchema { name: "--cipher".to_string(), type_: "enum(mlkem, neural)".to_string(), required: false, description: "Cipher to use (\"kyber\" accepted as a legacy alias for mlkem)".to_string(), default: Some("mlkem".to_string()) },
                ],
                returns: "CryptoResult with operation, cipher, input_size, output_size".to_string(),
            },
            OperationSchema {
                name: "telemetry".to_string(),
                description: "Manage anonymous usage telemetry collection and reporting".to_string(),
                usage: "aft telemetry <status|opt-in|opt-out|reset|sync|clear|export|config>".to_string(),
                parameters: vec![
                    ParameterSchema { name: "action".to_string(), type_: "enum(status, opt-in, opt-out, reset, sync, clear, export, config)".to_string(), required: true, description: "Telemetry management action".to_string(), default: None },
                ],
                returns: "Telemetry status or action confirmation".to_string(),
            },
        ],

        protocols: vec![
            ProtocolInfo { scheme: "http".to_string(), name: "HTTP".to_string(), supports_download: true, supports_upload: true, supports_list: false, supports_resume: true, supports_ranges: true, status: "active".to_string() },
            ProtocolInfo { scheme: "https".to_string(), name: "HTTPS (TLS)".to_string(), supports_download: true, supports_upload: true, supports_list: false, supports_resume: true, supports_ranges: true, status: "active".to_string() },
            ProtocolInfo { scheme: "file".to_string(), name: "Local File System".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "active".to_string() },
            ProtocolInfo { scheme: "ftp".to_string(), name: "FTP".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "planned".to_string() },
            ProtocolInfo { scheme: "ftps".to_string(), name: "FTPS (FTP over TLS)".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "planned".to_string() },
            ProtocolInfo { scheme: "sftp".to_string(), name: "SFTP (SSH File Transfer)".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "planned".to_string() },
            ProtocolInfo { scheme: "scp".to_string(), name: "SCP (Secure Copy)".to_string(), supports_download: true, supports_upload: true, supports_list: false, supports_resume: false, supports_ranges: false, status: "planned".to_string() },
            ProtocolInfo { scheme: "s3".to_string(), name: "Amazon S3".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "planned".to_string() },
            ProtocolInfo { scheme: "aftp".to_string(), name: "AFTP (Agentic File Transfer Protocol)".to_string(), supports_download: true, supports_upload: true, supports_list: true, supports_resume: true, supports_ranges: true, status: "active".to_string() },
        ],

        output_formats: vec!["text".to_string(), "json".to_string(), "quiet".to_string()],

        global_options: vec![
            OptionSchema { flag: "--format".to_string(), short: Some("-f".to_string()), type_: "enum(text, json, quiet)".to_string(), description: "Output format".to_string(), default: Some("text".to_string()) },
            OptionSchema { flag: "--agent".to_string(), short: None, type_: "bool".to_string(), description: "Agent mode: JSON output, no interactive elements".to_string(), default: Some("false".to_string()) },
            OptionSchema { flag: "--parallel".to_string(), short: None, type_: "integer".to_string(), description: "Parallel connections for chunked transfers".to_string(), default: Some("4".to_string()) },
            OptionSchema { flag: "--retries".to_string(), short: None, type_: "integer".to_string(), description: "Max retry attempts with exponential backoff".to_string(), default: Some("3".to_string()) },
            OptionSchema { flag: "--retry-delay-ms".to_string(), short: None, type_: "integer".to_string(), description: "Initial retry delay (doubles each attempt)".to_string(), default: Some("1000".to_string()) },
            OptionSchema { flag: "--connect-timeout".to_string(), short: None, type_: "integer (seconds)".to_string(), description: "Connection timeout".to_string(), default: Some("30".to_string()) },
            OptionSchema { flag: "--timeout".to_string(), short: None, type_: "integer (seconds)".to_string(), description: "Transfer timeout (0 = unlimited)".to_string(), default: Some("0".to_string()) },
            OptionSchema { flag: "--insecure".to_string(), short: None, type_: "bool".to_string(), description: "Skip TLS certificate verification".to_string(), default: Some("false".to_string()) },
            OptionSchema { flag: "--verbose".to_string(), short: Some("-v".to_string()), type_: "bool".to_string(), description: "Verbose output".to_string(), default: Some("false".to_string()) },
            OptionSchema { flag: "--quiet".to_string(), short: Some("-q".to_string()), type_: "bool".to_string(), description: "Suppress non-error output".to_string(), default: Some("false".to_string()) },
        ],

        output_schema: OutputSchemaRef {
            description: "All operations return a unified JSON result object".to_string(),
            fields: vec![
                FieldSchema { name: "status".to_string(), type_: "enum(success, error)".to_string(), description: "Operation outcome".to_string() },
                FieldSchema { name: "operation".to_string(), type_: "string".to_string(), description: "Operation name".to_string() },
                FieldSchema { name: "source".to_string(), type_: "string | null".to_string(), description: "Source URL or path".to_string() },
                FieldSchema { name: "destination".to_string(), type_: "string | null".to_string(), description: "Destination URL or path".to_string() },
                FieldSchema { name: "protocol".to_string(), type_: "string | null".to_string(), description: "Protocol used (http, https, file, ftp, sftp, s3)".to_string() },
                FieldSchema { name: "transfer.bytes_transferred".to_string(), type_: "integer".to_string(), description: "Total bytes transferred".to_string() },
                FieldSchema { name: "transfer.duration_ms".to_string(), type_: "integer".to_string(), description: "Transfer duration in milliseconds".to_string() },
                FieldSchema { name: "transfer.throughput_bytes_per_sec".to_string(), type_: "float".to_string(), description: "Transfer speed in bytes/second".to_string() },
                FieldSchema { name: "transfer.checksum.algorithm".to_string(), type_: "string".to_string(), description: "Hash algorithm used".to_string() },
                FieldSchema { name: "transfer.checksum.value".to_string(), type_: "string".to_string(), description: "Hex-encoded hash value".to_string() },
                FieldSchema { name: "transfer.checksum.verified".to_string(), type_: "bool".to_string(), description: "Whether checksum matched expected value".to_string() },
                FieldSchema { name: "transfer.retries_used".to_string(), type_: "integer".to_string(), description: "Number of retries performed".to_string() },
                FieldSchema { name: "transfer.chunks_used".to_string(), type_: "integer".to_string(), description: "Number of parallel chunks used".to_string() },
                FieldSchema { name: "metadata".to_string(), type_: "object | null".to_string(), description: "Resource metadata (from head operation)".to_string() },
                FieldSchema { name: "entries".to_string(), type_: "array | null".to_string(), description: "Directory listing (from ls operation)".to_string() },
                FieldSchema { name: "error".to_string(), type_: "string | null".to_string(), description: "Error message (when status is error)".to_string() },
                FieldSchema { name: "timestamp".to_string(), type_: "string (ISO 8601)".to_string(), description: "Operation timestamp in UTC".to_string() },
            ],
        },

        agent_usage: AgentUsage {
            recommended_flags: vec![
                "--agent".to_string(),
                "--format json".to_string(),
            ],
            output_parsing: "Parse stdout as JSON. Check .status field first: 'success' or 'error'. Access transfer metrics via .transfer object.".to_string(),
            error_handling: "On error, .error contains a human-readable message. Exit code is 1 on failure, 0 on success.".to_string(),
            discovery: "Run 'aft schema' for full capability schema. Run 'aft capabilities' for a summary.".to_string(),
            examples: vec![
                AgentExample {
                    task: "Download a file and get structured result".to_string(),
                    command: "aft --agent get https://example.com/data.json -o /tmp/data.json".to_string(),
                    notes: "The --agent flag ensures JSON output with no interactive progress bars".to_string(),
                },
                AgentExample {
                    task: "Check file metadata before downloading".to_string(),
                    command: "aft --agent head https://example.com/large-file.tar.gz".to_string(),
                    notes: "Use .metadata.content_length to check file size before transfer".to_string(),
                },
                AgentExample {
                    task: "Download with integrity verification".to_string(),
                    command: "aft --agent get https://example.com/release.tar.gz --checksum sha256 --checksum-value abc123...".to_string(),
                    notes: "Transfer fails with checksum_mismatch error if hash doesn't match".to_string(),
                },
                AgentExample {
                    task: "List directory contents".to_string(),
                    command: "aft --agent ls /var/data/".to_string(),
                    notes: "Returns .entries array with name, size, is_directory, last_modified".to_string(),
                },
                AgentExample {
                    task: "Resume an interrupted large download".to_string(),
                    command: "aft --agent get https://example.com/huge.iso -o /tmp/huge.iso --resume".to_string(),
                    notes: "Automatically detects existing partial file and resumes from last byte".to_string(),
                },
            ],
        },
    }
}

pub fn print_schema(format: Format) {
    let schema = generate_schema();
    match format {
        Format::Json | Format::Text => {
            // Schema is always JSON for machine readability
            if let Ok(json) = serde_json::to_string_pretty(&schema) {
                println!("{}", json);
            } else {
                eprintln!("Error: failed to serialize schema");
            }
        }
        Format::Quiet => {}
    }
}

pub fn print_capabilities(format: Format) {
    let schema = generate_schema();

    match format {
        Format::Json => {
            #[derive(Serialize)]
            struct Capabilities {
                name: String,
                version: String,
                protocols: Vec<ProtocolInfo>,
                operations: Vec<String>,
                output_formats: Vec<String>,
            }

            let caps = Capabilities {
                name: schema.name,
                version: schema.version,
                protocols: schema.protocols,
                operations: schema.operations.iter().map(|o| o.name.clone()).collect(),
                output_formats: schema.output_formats,
            };
            if let Ok(json) = serde_json::to_string_pretty(&caps) {
                println!("{}", json);
            } else {
                eprintln!("Error: failed to serialize capabilities");
            }
        }
        Format::Quiet => {}
        Format::Text => {
            println!();
            println!(
                "{}",
                " AFT - Agentic File Transfer ".on_blue().white().bold()
            );
            println!(" {} {}", "Version:".dimmed(), env!("CARGO_PKG_VERSION"));
            println!();

            println!("{}", " Protocols ".on_cyan().black().bold());
            println!();
            for proto in &schema.protocols {
                let status_icon = match proto.status.as_str() {
                    "active" => "*".green(),
                    _ => "o".yellow(),
                };
                let features: Vec<&str> = [
                    proto.supports_download.then_some("download"),
                    proto.supports_upload.then_some("upload"),
                    proto.supports_list.then_some("list"),
                    proto.supports_resume.then_some("resume"),
                    proto.supports_ranges.then_some("range"),
                ]
                .into_iter()
                .flatten()
                .collect();
                println!(
                    "  {} {:8} {:24} [{}]",
                    status_icon,
                    proto.scheme.bold(),
                    proto.name.dimmed(),
                    features.join(" ").dimmed()
                );
            }

            println!();
            println!("{}", " Operations ".on_cyan().black().bold());
            println!();
            for op in &schema.operations {
                println!(
                    "  {} {:16} {}",
                    ">".green(),
                    op.name.bold(),
                    op.description.dimmed()
                );
            }

            println!();
            println!("{}", " Output Formats ".on_cyan().black().bold());
            println!();
            for fmt in &schema.output_formats {
                println!("  - {}", fmt);
            }

            println!();
            println!(
                "  {} Use '{}' for full machine-readable schema",
                "*".normal(),
                "aft schema".yellow().bold()
            );
            println!();
        }
    }
}
