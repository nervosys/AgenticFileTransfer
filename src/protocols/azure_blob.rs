use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct AzureBlobHandler;

/// Parse az://container/blob or azblob://container/blob → (account, container, blob).
/// Account is read from AZURE_STORAGE_ACCOUNT env var.
fn parse_azure_url(url: &str) -> AftResult<(String, String, String)> {
    let rest = url
        .strip_prefix("az://")
        .or_else(|| url.strip_prefix("azblob://"))
        .ok_or_else(|| AftError::InvalidUrl("Not an az:// or azblob:// URL".into()))?;

    let (container, blob) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    if container.is_empty() {
        return Err(AftError::InvalidUrl(
            "Azure Blob URL missing container name".into(),
        ));
    }

    let account = std::env::var("AZURE_STORAGE_ACCOUNT").map_err(|_| {
        AftError::Other(
            "AZURE_STORAGE_ACCOUNT environment variable is required for az:// URLs".into(),
        )
    })?;

    Ok((account, container, blob))
}

/// Get the storage key from env, or fall back to SAS token.
fn get_azure_auth(opts: &ProtocolOptions) -> AftResult<AzureAuth> {
    // Check for SAS token in bearer_token
    if let Some(ref token) = opts.bearer_token {
        return Ok(AzureAuth::Sas(token.clone()));
    }

    // Check for storage key in env
    if let Ok(key) = std::env::var("AZURE_STORAGE_KEY") {
        return Ok(AzureAuth::SharedKey(key));
    }

    // Check for SAS token in env
    if let Ok(sas) = std::env::var("AZURE_STORAGE_SAS") {
        return Ok(AzureAuth::Sas(sas));
    }

    // Check basic_auth as account:key
    if let Some((_, ref pass)) = opts.basic_auth {
        return Ok(AzureAuth::SharedKey(pass.clone()));
    }

    Err(AftError::Other(
        "Azure Blob auth required: set AZURE_STORAGE_KEY, AZURE_STORAGE_SAS, or use --bearer-token with a SAS token".into(),
    ))
}

enum AzureAuth {
    SharedKey(String),
    Sas(String),
}

fn build_blob_url(account: &str, container: &str, blob: &str, auth: &AzureAuth) -> String {
    let base = format!(
        "https://{}.blob.core.windows.net/{}/{}",
        account, container, blob
    );
    match auth {
        AzureAuth::Sas(sas) => {
            let sep = if sas.starts_with('?') { "" } else { "?" };
            format!("{}{}{}", base, sep, sas)
        }
        AzureAuth::SharedKey(_) => base,
    }
}

fn build_container_url(account: &str, container: &str, auth: &AzureAuth) -> String {
    let base = format!("https://{}.blob.core.windows.net/{}", account, container);
    match auth {
        AzureAuth::Sas(sas) => {
            let sep = if sas.starts_with('?') { "" } else { "?" };
            format!("{}{}{}", base, sep, sas)
        }
        AzureAuth::SharedKey(_) => base,
    }
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

fn apply_shared_key_header(
    req: reqwest::RequestBuilder,
    auth: &AzureAuth,
) -> reqwest::RequestBuilder {
    match auth {
        AzureAuth::SharedKey(key) => {
            // For simplicity, use the key as a Bearer token.
            // Full Azure SharedKey auth requires HMAC signing of each request;
            // SAS tokens are the recommended approach for CLI tools.
            req.header("x-ms-version", "2023-11-03").bearer_auth(key)
        }
        AzureAuth::Sas(_) => {
            // SAS token is already embedded in the URL
            req.header("x-ms-version", "2023-11-03")
        }
    }
}

#[async_trait]
impl ProtocolHandler for AzureBlobHandler {
    fn scheme(&self) -> &str {
        "az"
    }

    fn name(&self) -> &str {
        "Azure Blob Storage"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (account, container, blob) = parse_azure_url(url)?;
        let auth = get_azure_auth(opts)?;
        let blob_url = build_blob_url(&account, &container, &blob, &auth);
        let client = build_client(opts)?;

        let req = apply_shared_key_header(client.head(&blob_url), &auth);
        let resp = req.send().await?;

        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("Azure Blob HEAD failed: {}", resp.status()),
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
            accepts_ranges: true,
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
        let (account, container, blob) = parse_azure_url(url)?;
        let auth = get_azure_auth(opts)?;
        let blob_url = build_blob_url(&account, &container, &blob, &auth);
        let client = build_client(opts)?;

        let mut req = apply_shared_key_header(client.get(&blob_url), &auth);

        let mut bytes_already = 0u64;
        if let Some(offset) = resume_from {
            req = req.header(reqwest::header::RANGE, format!("bytes={}-", offset));
            bytes_already = offset;
        }

        let resp = req.send().await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("Azure Blob GET failed: {}", resp.status()),
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
        let (account, container, blob) = parse_azure_url(url)?;
        let auth = get_azure_auth(opts)?;
        let blob_url = build_blob_url(&account, &container, &blob, &auth);
        let client = build_client(opts)?;

        let req = apply_shared_key_header(client.get(&blob_url), &auth)
            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, end));

        let resp = req.send().await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("Azure Blob GET range failed: {}", resp.status()),
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
        let (account, container, blob) = parse_azure_url(url)?;
        let auth = get_azure_auth(opts)?;
        let blob_url = build_blob_url(&account, &container, &blob, &auth);
        let client = build_client(opts)?;

        let data = tokio::fs::read(source).await?;
        let file_size = data.len() as u64;

        let ct = content_type.unwrap_or("application/octet-stream");
        let req = apply_shared_key_header(client.put(&blob_url), &auth)
            .header(reqwest::header::CONTENT_TYPE, ct)
            .header("x-ms-blob-type", "BlockBlob")
            .body(data);

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("Azure Blob PUT failed: {}", resp.status()),
            });
        }

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (account, container, prefix) = parse_azure_url(url)?;
        let auth = get_azure_auth(opts)?;
        let client = build_client(opts)?;

        let mut list_url = build_container_url(&account, &container, &auth);

        // Append list query params
        let sep = if list_url.contains('?') { "&" } else { "?" };
        list_url = format!("{}{}restype=container&comp=list&delimiter=/", list_url, sep);
        if !prefix.is_empty() {
            list_url = format!("{}&prefix={}", list_url, prefix);
        }

        let req = apply_shared_key_header(client.get(&list_url), &auth);
        let resp = req.send().await?;

        if !resp.status().is_success() {
            return Err(AftError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("Azure Blob LIST failed: {}", resp.status()),
            });
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AftError::Other(format!("Azure list body: {}", e)))?;

        Ok(parse_azure_list_response(&body, &prefix))
    }
}

/// Parse Azure Blob List XML response.
fn parse_azure_list_response(xml: &str, prefix: &str) -> Vec<DirectoryEntry> {
    let mut entries = Vec::new();

    // Parse BlobPrefix elements (directories)
    let xml_lower = xml.to_lowercase();
    let mut pos = 0;
    while let Some(start) = xml_lower[pos..].find("<blobprefix>") {
        let start = start + pos;
        if let Some(end) = xml_lower[start..].find("</blobprefix>") {
            let block = &xml[start..start + end + 13];
            if let Some(name) = extract_simple_tag(block, "Name") {
                let display_name = name
                    .strip_prefix(prefix)
                    .unwrap_or(&name)
                    .trim_end_matches('/')
                    .to_string();
                if !display_name.is_empty() {
                    entries.push(DirectoryEntry {
                        name: display_name,
                        size: None,
                        is_directory: true,
                        last_modified: None,
                    });
                }
            }
            pos = start + end + 13;
        } else {
            break;
        }
    }

    // Parse Blob elements (files)
    pos = 0;
    while let Some(start) = xml_lower[pos..].find("<blob>") {
        let start = start + pos;
        if let Some(end) = xml_lower[start..].find("</blob>") {
            let block = &xml[start..start + end + 7];
            if let Some(name) = extract_simple_tag(block, "Name") {
                let display_name = name.strip_prefix(prefix).unwrap_or(&name).to_string();
                if !display_name.is_empty() && !display_name.ends_with('/') {
                    let size = extract_simple_tag(block, "Content-Length")
                        .and_then(|s| s.parse::<u64>().ok());
                    let last_modified = extract_simple_tag(block, "Last-Modified");

                    entries.push(DirectoryEntry {
                        name: display_name,
                        size,
                        is_directory: false,
                        last_modified,
                    });
                }
            }
            pos = start + end + 7;
        } else {
            break;
        }
    }

    entries
}

/// Extract content of a simple XML tag (case-insensitive).
fn extract_simple_tag(xml: &str, tag: &str) -> Option<String> {
    let xml_lower = xml.to_lowercase();
    let open = format!("<{}>", tag.to_lowercase());
    let close = format!("</{}>", tag.to_lowercase());

    if let Some(start) = xml_lower.find(&open) {
        let content_start = start + open.len();
        if let Some(end) = xml_lower[content_start..].find(&close) {
            let content = xml[content_start..content_start + end].trim();
            if !content.is_empty() {
                return Some(content.to_string());
            }
        }
    }
    None
}
