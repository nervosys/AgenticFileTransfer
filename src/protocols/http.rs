// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct HttpHandler {
    scheme: String,
    /// Cached client — avoids rebuilding connection pool on every request.
    cached_client: Mutex<Option<Client>>,
}

impl HttpHandler {
    pub fn new(scheme: String) -> Self {
        Self {
            scheme,
            cached_client: Mutex::new(None),
        }
    }
    fn get_or_build_client(&self, opts: &ProtocolOptions) -> AftResult<Client> {
        let mut guard = self.cached_client.lock().unwrap();
        if let Some(ref client) = *guard {
            return Ok(client.clone());
        }
        let client = self.build_client(opts)?;
        *guard = Some(client.clone());
        Ok(client)
    }

    fn build_client(&self, opts: &ProtocolOptions) -> AftResult<Client> {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(opts.insecure)
            .redirect(reqwest::redirect::Policy::limited(opts.max_redirects))
            // Performance: disable Nagle, keep connections alive, large pool
            .tcp_nodelay(true)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate(); // skip decompression middleware

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
}

#[async_trait]
impl ProtocolHandler for HttpHandler {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn name(&self) -> &str {
        "HTTP/HTTPS"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let client = self.get_or_build_client(opts)?;
        let req = self.apply_auth(client.head(url), opts);
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

        let content_length = headers
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let last_modified = headers
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let accepts_ranges = headers
            .get(reqwest::header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);

        Ok(ResourceMetadata {
            content_length,
            content_type,
            last_modified,
            etag,
            accepts_ranges,
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
        let client = self.get_or_build_client(opts)?;
        let mut req = self.apply_auth(client.get(url), opts);

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

        let file = if resume_from.is_some() {
            tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(dest)
                .await?
        } else {
            let f = tokio::fs::File::create(dest).await?;
            // Pre-allocate file to avoid fragmentation overhead
            if let Some(size) = total_size {
                let _ = f.set_len(size).await;
            }
            f
        };

        let mut downloaded = bytes_already;
        let mut stream = resp.bytes_stream();
        let mut file = tokio::io::BufWriter::with_capacity(8 * 1024 * 1024, file);

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
        let client = self.get_or_build_client(opts)?;
        let req = self
            .apply_auth(client.get(url), opts)
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
        method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let file_size = tokio::fs::metadata(source).await?.len();
        let body = tokio::fs::read(source).await?;

        let client = self.get_or_build_client(opts)?;
        let method_str = method.unwrap_or("PUT");
        let http_method = method_str
            .parse::<reqwest::Method>()
            .map_err(|_| AftError::Other(format!("Invalid HTTP method: {}", method_str)))?;

        let mut req = self
            .apply_auth(client.request(http_method, url), opts)
            .body(body);

        if let Some(ct) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, ct);
        }

        if let Some(ref cb) = progress {
            cb(0, Some(file_size));
        }

        let resp = req.send().await?;

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

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

        Ok(file_size)
    }

    async fn list(&self, _url: &str, _opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        Err(AftError::Other(
            "Directory listing is not supported over HTTP. Use FTP, SFTP, S3, or local paths."
                .to_string(),
        ))
    }
}
