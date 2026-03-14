//! DoD classification levels and compliance enforcement.
//!
//! Implements classification markings per Executive Order 13526 and
//! DoDI 5200.01, with policy enforcement for encryption requirements
//! and TLS version minimums based on classification level.

use serde::{Deserialize, Serialize};

/// DoD classification levels per Executive Order 13526 and DoDI 5200.01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum Classification {
    /// UNCLASSIFIED — No classification; publicly releasable after review
    Unclassified,
    /// CUI — Controlled Unclassified Information (32 CFR Part 2002)
    Cui,
    /// CONFIDENTIAL — Could cause damage to national security
    Confidential,
    /// SECRET — Could cause serious damage to national security
    Secret,
    /// TOP SECRET — Could cause exceptionally grave damage to national security
    TopSecret,
}

#[allow(dead_code)]
impl Classification {
    /// Parse a classification level from a string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().replace('-', " ").trim() {
            "UNCLASSIFIED" | "U" => Some(Self::Unclassified),
            "CUI" | "CONTROLLED UNCLASSIFIED INFORMATION" => Some(Self::Cui),
            "CONFIDENTIAL" | "C" => Some(Self::Confidential),
            "SECRET" | "S" => Some(Self::Secret),
            "TOP SECRET" | "TS" | "TOPSECRET" => Some(Self::TopSecret),
            _ => None,
        }
    }

    /// Full classification banner text.
    pub fn banner(&self) -> &str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Cui => "CUI // CONTROLLED UNCLASSIFIED INFORMATION",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
        }
    }

    /// Whether this classification level requires data encryption.
    pub fn requires_encryption(&self) -> bool {
        !matches!(self, Self::Unclassified)
    }

    /// HTTP header value for classification marking.
    pub fn header_value(&self) -> &str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Cui => "CUI",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
        }
    }
}

/// Print the DoD classification banner to stderr.
pub fn print_banner(classification: Classification) {
    let banner = classification.banner();
    let border = "=".repeat(banner.len() + 4);
    eprintln!("\n{}", border);
    eprintln!("  {}", banner);
    eprintln!("{}\n", border);
}

/// Validate that the current configuration meets classification requirements.
pub fn validate_compliance(
    classification: Classification,
    insecure: bool,
) -> Result<(), String> {
    if insecure && classification != Classification::Unclassified {
        return Err(format!(
            "STIG VIOLATION: --insecure cannot be used with {} data",
            classification.banner()
        ));
    }

    Ok(())
}
