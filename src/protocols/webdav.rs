use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct WebDavHandler {
    scheme: String,
}

impl WebDavHandler {
    pub fn new(scheme: String) -> Self {
        Self { scheme }
    }

    fn build_client(&self, opts: &ProtocolOptions) -> AftResult<Client> {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(opts.insecure)
            .redirect(reqwest::redirect::Policy::limited(opts.max_redirects));

        if opts.connect_timeout_secs > 0 {
            builder =
                builder.connect_timeout(std::time::Duration::from_secs(opts.connect_timeout_secs));
        }
        if opts.timeout_secs > 0 {
            builder = builder.timeout(std::time::Duration::from_secs(opts.timeout_secs));
        }
        if let Some(ref ua) = opts.user_agent {
            builder = builder.user_agent(ua.clone());
        } else {
            builder = builder.user_agent(format!("aft/{}", env!("CARGO_PKG_VERSION")));
        }

        builder
            .build()
            .map_err(|e| AftError::ConnectionFailed(e.to_string()))
    }

    fn apply_auth(
        &self,
        mut req: reqwest::RequestBuilder,
        opts: &ProtocolOptions,
    ) -> reqwest::RequestBuilder {
        if let Some(ref token) = opts.bearer_token {
            req = req.bearer_auth(token);
        }
        if let Some((ref user, ref pass)) = opts.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }
        for (key, value) in &opts.headers {
            req = req.header(key.as_str(), value.as_str());
        }
        req
    }

    /// Convert webdav:// URL → https://, webdavs:// → https://, webdav-http:// → http://
    fn to_http_url(&self, url: &str) -> String {
        if let Some(rest) = url.strip_prefix("webdavs://") {
            format!("https://{}", rest)
        } else if let Some(rest) = url.strip_prefix("webdav://") {
            format!("https://{}", rest)
        } else if let Some(rest) = url.strip_prefix("dav://") {
            format!("https://{}", rest)
        } else {
            url.to_string()
        }
    }
}

#[async_trait]
impl ProtocolHandler for WebDavHandler {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn name(&self) -> &str {
        "WebDAV"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let http_url = self.to_http_url(url);
        let client = self.build_client(opts)?;
        let req = self.apply_auth(client.head(&http_url), opts);
        let resp = req.send().await?;

        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: resp
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string(),
            });
        }

        let headers = resp.headers();
        let mut header_map = HashMap::new();
        for (k, v) in headers.iter() {
            if let Ok(val) = v.to_str() {
                header_map.insert(k.to_string(), val.to_string());
            }
        }

        Ok(ResourceMetadata {
            content_length: headers
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            content_type: headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            last_modified: headers
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            etag: headers
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            accepts_ranges: headers
                .get(reqwest::header::ACCEPT_RANGES)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("bytes"))
                .unwrap_or(false),
            headers: header_map,
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
        let http_url = self.to_http_url(url);
        let client = self.build_client(opts)?;
        let mut req = self.apply_auth(client.get(&http_url), opts);

        let mut bytes_already = 0u64;
        if let Some(offset) = resume_from {
            req = req.header(reqwest::header::RANGE, format!("bytes={}-", offset));
            bytes_already = offset;
        }

        let resp = req.send().await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: resp
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string(),
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
        let http_url = self.to_http_url(url);
        let client = self.build_client(opts)?;
        let req = self
            .apply_auth(client.get(&http_url), opts)
            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, end));

        let resp = req.send().await?;
        if resp.status() != reqwest::StatusCode::PARTIAL_CONTENT && !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: resp
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string(),
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
        let http_url = self.to_http_url(url);
        let file_size = tokio::fs::metadata(source).await?.len();
        let body = tokio::fs::read(source).await?;

        let client = self.build_client(opts)?;
        let mut req = self.apply_auth(client.put(&http_url), opts).body(body);

        if let Some(ct) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, ct);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: resp
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string(),
            });
        }

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let http_url = self.to_http_url(url);
        let client = self.build_client(opts)?;

        // PROPFIND with Depth: 1 to list immediate children
        let propfind_body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:displayname/>
    <D:getcontentlength/>
    <D:resourcetype/>
    <D:getlastmodified/>
  </D:prop>
</D:propfind>"#;

        let req = self
            .apply_auth(
                client.request(
                    reqwest::Method::from_bytes(b"PROPFIND")
                        .expect("PROPFIND is a valid HTTP method"),
                    &http_url,
                ),
                opts,
            )
            .header("Depth", "1")
            .header(reqwest::header::CONTENT_TYPE, "application/xml")
            .body(propfind_body);

        let resp = req.send().await?;

        // WebDAV returns 207 Multi-Status for PROPFIND
        if resp.status().as_u16() != 207 && !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: resp
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string(),
            });
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AftError::Other(format!("WebDAV PROPFIND body: {}", e)))?;

        Ok(parse_propfind_response(&body, &http_url))
    }
}

/// Minimal XML parser for WebDAV PROPFIND multi-status responses.
/// Extracts href, displayname, contentlength, resourcetype, lastmodified
/// without requiring a full XML dependency.
fn parse_propfind_response(xml: &str, base_url: &str) -> Vec<DirectoryEntry> {
    let mut entries = Vec::new();

    // Normalize base URL for comparison (strip trailing slash)
    let base_path = url::Url::parse(base_url)
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();

    // Split by <D:response> or <d:response> blocks
    let response_pattern = ["<D:response>", "<d:response>", "<response>"];
    let end_pattern = ["</D:response>", "</d:response>", "</response>"];

    let xml_lower = xml.to_lowercase();
    let mut search_pos = 0;

    loop {
        // Find next response block start
        let start = response_pattern
            .iter()
            .filter_map(|p| {
                xml_lower[search_pos..]
                    .find(&p.to_lowercase())
                    .map(|i| i + search_pos)
            })
            .min();

        let start = match start {
            Some(s) => s,
            None => break,
        };

        // Find response block end
        let end = end_pattern
            .iter()
            .filter_map(|p| {
                xml_lower[start..]
                    .find(&p.to_lowercase())
                    .map(|i| i + start + p.len())
            })
            .min();

        let end = match end {
            Some(e) => e,
            None => break,
        };

        let block = &xml[start..end];
        search_pos = end;

        // Extract href
        let href = extract_tag_content(block, "href").unwrap_or_default();

        // Skip the collection itself (the base URL entry)
        let href_path = url::Url::parse(&href)
            .map(|u| u.path().trim_end_matches('/').to_string())
            .unwrap_or_else(|_| href.trim_end_matches('/').to_string());
        if href_path == base_path || href_path.is_empty() {
            continue;
        }

        let is_directory = block.to_lowercase().contains("<d:collection")
            || block.to_lowercase().contains("<collection");

        let name = extract_tag_content(block, "displayname")
            .or_else(|| {
                // Fall back to last segment of href
                href.trim_end_matches('/').rsplit('/').next().map(|s| {
                    // URL-decode the segment
                    url::form_urlencoded::parse(s.as_bytes())
                        .map(|(k, _)| k.to_string())
                        .next()
                        .unwrap_or_else(|| s.to_string())
                })
            })
            .unwrap_or_default();

        if name.is_empty() {
            continue;
        }

        let size =
            extract_tag_content(block, "getcontentlength").and_then(|s| s.parse::<u64>().ok());

        let last_modified = extract_tag_content(block, "getlastmodified");

        entries.push(DirectoryEntry {
            name,
            size,
            is_directory,
            last_modified,
            relative_path: None,
            is_symlink: None,
            permissions: None,
        });
    }

    entries
}

/// Extract text content from the first occurrence of a tag (case-insensitive).
/// Handles DAV: namespace prefixes (D:, d:, or no prefix).
fn extract_tag_content(xml: &str, tag: &str) -> Option<String> {
    let xml_lower = xml.to_lowercase();
    let tag_lower = tag.to_lowercase();

    // Try patterns: <D:tag>, <d:tag>, <tag>
    let patterns = [format!("<d:{}>", tag_lower), format!("<{}>", tag_lower)];
    let end_patterns = [format!("</d:{}>", tag_lower), format!("</{}>", tag_lower)];

    for (open, close) in patterns.iter().zip(end_patterns.iter()) {
        if let Some(start) = xml_lower.find(open.as_str()) {
            let content_start = start + open.len();
            if let Some(end) = xml_lower[content_start..].find(close.as_str()) {
                let content = xml[content_start..content_start + end].trim();
                if !content.is_empty() {
                    return Some(content.to_string());
                }
            }
        }
    }

    None
}
