use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use reqwest::Client;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct GcsHandler;

/// Parse gs://bucket/object → (bucket, object).
fn parse_gcs_url(url: &str) -> AftResult<(String, String)> {
    let rest = url
        .strip_prefix("gs://")
        .ok_or_else(|| AftError::InvalidUrl("Not a gs:// URL".into()))?;

    let (bucket, object) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    if bucket.is_empty() {
        return Err(AftError::InvalidUrl("GCS URL missing bucket name".into()));
    }

    Ok((bucket, object))
}

/// Get auth token from opts or GOOGLE_APPLICATION_CREDENTIALS-adjacent env vars.
fn get_gcs_auth(opts: &ProtocolOptions) -> Option<String> {
    // Bearer token takes priority
    if let Some(ref token) = opts.bearer_token {
        return Some(token.clone());
    }
    // Check env for a pre-obtained access token
    if let Ok(token) = std::env::var("GCS_ACCESS_TOKEN") {
        return Some(token);
    }
    None
}

fn build_client(opts: &ProtocolOptions) -> AftResult<Client> {
    let mut builder = Client::builder().danger_accept_invalid_certs(opts.insecure);

    if opts.connect_timeout_secs > 0 {
        builder =
            builder.connect_timeout(std::time::Duration::from_secs(opts.connect_timeout_secs));
    }
    if opts.timeout_secs > 0 {
        builder = builder.timeout(std::time::Duration::from_secs(opts.timeout_secs));
    }
    builder = builder.user_agent(
        opts.user_agent
            .as_deref()
            .unwrap_or(&format!("aft/{}", env!("CARGO_PKG_VERSION"))),
    );

    builder
        .build()
        .map_err(|e| AftError::ConnectionFailed(e.to_string()))
}

fn apply_auth(req: reqwest::RequestBuilder, opts: &ProtocolOptions) -> reqwest::RequestBuilder {
    if let Some(token) = get_gcs_auth(opts) {
        req.bearer_auth(token)
    } else {
        req
    }
}

#[async_trait]
impl ProtocolHandler for GcsHandler {
    fn scheme(&self) -> &str {
        "gs"
    }

    fn name(&self) -> &str {
        "Google Cloud Storage"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (bucket, object) = parse_gcs_url(url)?;
        let client = build_client(opts)?;

        let api_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            bucket,
            urlencoding::encode(&object)
        );

        let req = apply_auth(client.get(&api_url), opts);
        let resp = req.send().await?;

        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("GCS metadata failed: {}", resp.status()),
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AftError::Other(format!("GCS metadata parse: {}", e)))?;

        let content_length = body
            .get("size")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok());

        let content_type = body
            .get("contentType")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let last_modified = body
            .get("updated")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let etag = body
            .get("etag")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(ResourceMetadata {
            content_length,
            content_type,
            last_modified,
            etag,
            accepts_ranges: true,
            headers: HashMap::new(),
        })
    }

    async fn download(
        &self,
        url: &str,
        dest: &Path,
        opts: &ProtocolOptions,
        resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (bucket, object) = parse_gcs_url(url)?;
        let client = build_client(opts)?;

        // Use the media download endpoint
        let api_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
            bucket,
            urlencoding::encode(&object)
        );

        let mut req = apply_auth(client.get(&api_url), opts);

        let mut bytes_already = 0u64;
        if let Some(offset) = resume_from {
            req = req.header(reqwest::header::RANGE, format!("bytes={}-", offset));
            bytes_already = offset;
        }

        let resp = req.send().await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("GCS GET failed: {}", resp.status()),
            });
        }

        let total_size = resp.content_length().map(|cl| cl + bytes_already);

        let mut file = if resume_from.is_some() {
            tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(dest)
                .await?
        } else {
            tokio::fs::File::create(dest).await?
        };

        let mut downloaded = bytes_already;
        let mut stream = resp.bytes_stream();

        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AftError::TransferFailed(e.to_string()))?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            if let Some(ref cb) = progress {
                cb(downloaded, total_size);
            }
        }

        file.flush().await?;
        Ok(downloaded)
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        let (bucket, object) = parse_gcs_url(url)?;
        let client = build_client(opts)?;

        let api_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
            bucket,
            urlencoding::encode(&object)
        );

        let req = apply_auth(client.get(&api_url), opts)
            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, end));

        let resp = req.send().await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("GCS GET range failed: {}", resp.status()),
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AftError::TransferFailed(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn upload(
        &self,
        source: &Path,
        url: &str,
        opts: &ProtocolOptions,
        content_type: Option<&str>,
        _method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (bucket, object) = parse_gcs_url(url)?;
        let client = build_client(opts)?;

        let data = tokio::fs::read(source).await?;
        let file_size = data.len() as u64;

        let ct = content_type.unwrap_or("application/octet-stream");

        // Use the simple upload endpoint
        let api_url = format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            bucket,
            urlencoding::encode(&object)
        );

        let req = apply_auth(client.post(&api_url), opts)
            .header(reqwest::header::CONTENT_TYPE, ct)
            .body(data);

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("GCS upload failed: {}", resp.status()),
            });
        }

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (bucket, prefix) = parse_gcs_url(url)?;
        let client = build_client(opts)?;

        let mut api_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?delimiter=/",
            bucket
        );
        if !prefix.is_empty() {
            api_url = format!("{}&prefix={}", api_url, urlencoding::encode(&prefix));
        }

        let req = apply_auth(client.get(&api_url), opts);
        let resp = req.send().await?;

        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("GCS list failed: {}", resp.status()),
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AftError::Other(format!("GCS list parse: {}", e)))?;

        let mut entries = Vec::new();

        // Prefixes (directories)
        if let Some(prefixes) = body.get("prefixes").and_then(|v| v.as_array()) {
            for p in prefixes {
                if let Some(name) = p.as_str() {
                    let display = name
                        .strip_prefix(&prefix)
                        .unwrap_or(name)
                        .trim_end_matches('/')
                        .to_string();
                    if !display.is_empty() {
                        entries.push(DirectoryEntry {
                            name: display,
                            size: None,
                            is_directory: true,
                            last_modified: None,
                            relative_path: None,
                            is_symlink: None,
                            permissions: None,
                        });
                    }
                }
            }
        }

        // Items (files)
        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let display = name.strip_prefix(&prefix).unwrap_or(name).to_string();
                if !display.is_empty() && !display.ends_with('/') {
                    let size = item
                        .get("size")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok());
                    let last_modified = item
                        .get("updated")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    entries.push(DirectoryEntry {
                        name: display,
                        size,
                        is_directory: false,
                        last_modified,
                        relative_path: None,
                        is_symlink: None,
                        permissions: None,
                    });
                }
            }
        }

        Ok(entries)
    }
}
