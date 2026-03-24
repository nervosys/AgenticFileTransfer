use std::cmp;

use colored::*;

use crate::engine::TransferResult;
use crate::protocols::{DirectoryEntry, ResourceMetadata};

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Text,
    Json,
    Quiet,
}

/// Unified output result for all operations.
///
/// Every command returns this structure, ensuring consistent, parseable
/// output for both human operators and AI agents.
#[derive(Debug, serde::Serialize)]
pub struct OutputResult {
    /// Operation outcome: "success" or "error"
    pub status: String,
    /// Operation name (e.g., "download", "upload", "head")
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<TransferResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ResourceMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<DirectoryEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// ISO 8601 timestamp of the operation
    pub timestamp: String,
}

impl OutputResult {
    pub fn success(operation: &str) -> Self {
        Self {
            status: "success".to_string(),
            operation: operation.to_string(),
            source: None,
            destination: None,
            transfer: None,
            metadata: None,
            entries: None,
            error: None,
            protocol: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn failure(operation: &str, error: &str) -> Self {
        Self {
            status: "error".to_string(),
            operation: operation.to_string(),
            source: None,
            destination: None,
            transfer: None,
            metadata: None,
            entries: None,
            error: Some(error.to_string()),
            protocol: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Render the output result in the requested format
pub fn print_result(result: &OutputResult, format: Format) {
    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
        Format::Quiet => {
            if result.status == "error" {
                if let Some(ref err) = result.error {
                    eprintln!("{}", err);
                }
            }
        }
        Format::Text => print_text_result(result),
    }
}

fn print_text_result(result: &OutputResult) {
    if result.status == "error" {
        println!("\n{} {}", "x".red().bold(), result.operation.red().bold());
        if let Some(ref err) = result.error {
            println!("  {} {}", "Error:".red(), err);
        }
        println!();
        return;
    }

    // Skip printing for meta-commands that already printed their own output
    if result.operation == "schema" || result.operation == "capabilities" {
        return;
    }

    println!(
        "\n{} {} {}",
        "*".green().bold(),
        result.operation.green().bold(),
        "complete".green()
    );

    if let Some(ref src) = result.source {
        println!("  {} {}", "Source:".cyan().bold(), src);
    }
    if let Some(ref dst) = result.destination {
        println!("  {} {}", "Dest:  ".cyan().bold(), dst);
    }
    if let Some(ref proto) = result.protocol {
        println!(
            "  {} {}",
            "Proto: ".cyan().bold(),
            proto.to_uppercase().yellow()
        );
    }

    if let Some(ref transfer) = result.transfer {
        println!(
            "  {} {}",
            "Size:  ".cyan().bold(),
            format_bytes(transfer.bytes_transferred)
        );
        if transfer.duration_ms > 0 {
            println!(
                "  {} {}",
                "Time:  ".cyan().bold(),
                format_duration(transfer.duration_ms)
            );
            println!(
                "  {} {}",
                "Speed: ".cyan().bold(),
                format_speed(transfer.throughput_bytes_per_sec)
            );
        }
        if transfer.retries_used > 0 {
            println!("  {} {}", "Retries:".yellow().bold(), transfer.retries_used);
        }
        if transfer.chunks_used > 1 {
            println!(
                "  {} {} parallel",
                "Chunks:".cyan().bold(),
                transfer.chunks_used
            );
        }
        if let Some(ref cs) = transfer.checksum {
            let status = if cs.verified {
                "verified".green().to_string()
            } else {
                "computed".normal().to_string()
            };
            let display_len = cmp::min(16, cs.value.len());
            println!(
                "  {} {}:{}... ({})",
                "Hash:  ".cyan().bold(),
                cs.algorithm.dimmed(),
                cs.value[..display_len].yellow(),
                status
            );
        }
    }

    if let Some(ref meta) = result.metadata {
        if let Some(size) = meta.content_length {
            println!("  {} {}", "Size:    ".cyan().bold(), format_bytes(size));
        }
        if let Some(ref ct) = meta.content_type {
            println!("  {} {}", "Type:    ".cyan().bold(), ct);
        }
        if let Some(ref lm) = meta.last_modified {
            println!("  {} {}", "Modified:".cyan().bold(), lm);
        }
        if let Some(ref etag) = meta.etag {
            println!("  {} {}", "ETag:    ".cyan().bold(), etag);
        }
        println!(
            "  {} {}",
            "Ranges:  ".cyan().bold(),
            if meta.accepts_ranges {
                "supported".green().to_string()
            } else {
                "not supported".red().to_string()
            }
        );

        if !meta.headers.is_empty() {
            println!("  {}", "Headers:".cyan().bold());
            let mut headers: Vec<_> = meta.headers.iter().collect();
            headers.sort_by_key(|(k, _)| (*k).clone());
            for (k, v) in headers {
                println!("    {}: {}", k.dimmed(), v);
            }
        }
    }

    if let Some(ref entries) = result.entries {
        println!("  {} {} items", "Listed:".cyan().bold(), entries.len());
        println!();
        for entry in entries {
            let icon = if entry.is_directory { "[D]" } else { "   " };
            let name = if entry.is_directory {
                entry.name.blue().bold().to_string()
            } else {
                entry.name.normal().to_string()
            };
            let size = entry.size.map(format_bytes).unwrap_or_default();
            let modified = entry.last_modified.as_deref().unwrap_or("");
            println!(
                "    {} {:40} {:>10}  {}",
                icon,
                name,
                size.dimmed(),
                modified.dimmed()
            );
        }
    }

    println!();
}

/// Create an indicatif progress bar for interactive transfers
pub fn create_progress_bar(total: Option<u64>, format: Format) -> Option<indicatif::ProgressBar> {
    if matches!(format, Format::Quiet | Format::Json) {
        return None;
    }

    let pb = if let Some(total) = total {
        let pb = indicatif::ProgressBar::new(total);
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})",
                )
                .expect("hardcoded progress bar template is valid")
                .progress_chars("=> "),
        );
        pb
    } else {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {bytes} ({bytes_per_sec})")
                .expect("hardcoded progress bar template is valid"),
        );
        pb
    };

    Some(pb)
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_duration(ms: u64) -> String {
    if ms >= 3_600_000 {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    } else if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1_000 {
        format!("{:.2}s", ms as f64 / 1_000.0)
    } else {
        format!("{}ms", ms)
    }
}

fn format_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}
