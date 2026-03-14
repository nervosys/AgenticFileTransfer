//! DoD (Department of Defense) Cross-Domain Solution protocol handler.
//!
//! Wraps HTTPS transfers with DoD classification headers, enforces
//! STIG compliance (no `--insecure` for classified data), and prints
//! required classification banners.
//!
//! URL format: `dod://CLASSIFICATION@host/path`
//!
//! Examples:
//!   `dod://UNCLASSIFIED@files.mil/public/report.pdf`
//!   `dod://CUI@portal.disa.mil/cui/data.tar.gz`
//!   `dod://SECRET@siprnet-host/ops/plan.docx`

use async_trait::async_trait;

use crate::crypto::classification::{self, Classification};
use crate::error::{AftError, AftResult};
use crate::protocols::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};

pub struct DodHandler;

impl DodHandler {
    /// Parse `dod://CLASSIFICATION@host/path` into (Classification, https URL).
    fn parse_dod_url(url: &str) -> AftResult<(Classification, String)> {
        let rest = url
            .strip_prefix("dod://")
            .ok_or_else(|| AftError::InvalidUrl("DoD URL must start with dod://".into()))?;

        // Extract classification from userinfo position
        let (class_str, host_path) = if let Some(at_pos) = rest.find('@') {
            (&rest[..at_pos], &rest[at_pos + 1..])
        } else {
            ("UNCLASSIFIED", rest)
        };

        let classification = Classification::parse(class_str).ok_or_else(|| {
            AftError::InvalidUrl(format!(
                "Unknown classification '{}'. Use: UNCLASSIFIED, CUI, CONFIDENTIAL, SECRET, or TOP-SECRET",
                class_str
            ))
        })?;

        let https_url = format!("https://{}", host_path);
        Ok((classification, https_url))
    }

    /// Build options with DoD headers and enforce STIG compliance.
    fn build_dod_opts(
        opts: &ProtocolOptions,
        classification: Classification,
    ) -> AftResult<ProtocolOptions> {
        classification::validate_compliance(classification, opts.insecure)
            .map_err(|e| AftError::Other(e))?;

        let mut dod_opts = opts.clone();
        dod_opts.headers.insert(
            "X-Classification".to_string(),
            classification.header_value().to_string(),
        );
        dod_opts.headers.insert(
            "X-DoD-CDS".to_string(),
            "AFT/1.0".to_string(),
        );
        // Never allow insecure for DoD transfers
        dod_opts.insecure = false;
        Ok(dod_opts)
    }
}

#[async_trait]
impl ProtocolHandler for DodHandler {
    fn scheme(&self) -> &str {
        "dod"
    }

    fn name(&self) -> &str {
        "DoD Cross-Domain Solution (CDS)"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (classification, https_url) = Self::parse_dod_url(url)?;
        classification::print_banner(classification);
        let dod_opts = Self::build_dod_opts(opts, classification)?;

        let handler = crate::protocols::http::HttpHandler::new("https".to_string());
        handler.head(&https_url, &dod_opts).await
    }

    async fn download(
        &self,
        url: &str,
        dest: &std::path::Path,
        opts: &ProtocolOptions,
        resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (classification, https_url) = Self::parse_dod_url(url)?;
        classification::print_banner(classification);
        let dod_opts = Self::build_dod_opts(opts, classification)?;

        let handler = crate::protocols::http::HttpHandler::new("https".to_string());
        handler
            .download(&https_url, dest, &dod_opts, resume_from, progress)
            .await
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        let (classification, https_url) = Self::parse_dod_url(url)?;
        let dod_opts = Self::build_dod_opts(opts, classification)?;

        let handler = crate::protocols::http::HttpHandler::new("https".to_string());
        handler
            .download_range(&https_url, start, end, &dod_opts)
            .await
    }

    async fn upload(
        &self,
        source: &std::path::Path,
        url: &str,
        opts: &ProtocolOptions,
        content_type: Option<&str>,
        method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (classification, https_url) = Self::parse_dod_url(url)?;
        classification::print_banner(classification);
        let dod_opts = Self::build_dod_opts(opts, classification)?;

        let handler = crate::protocols::http::HttpHandler::new("https".to_string());
        handler
            .upload(source, &https_url, &dod_opts, content_type, method, progress)
            .await
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (classification, https_url) = Self::parse_dod_url(url)?;
        classification::print_banner(classification);
        let dod_opts = Self::build_dod_opts(opts, classification)?;

        let handler = crate::protocols::http::HttpHandler::new("https".to_string());
        handler.list(&https_url, &dod_opts).await
    }
}
