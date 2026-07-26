// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use s3::creds::Credentials;
use s3::Region;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct S3Handler;

/// Parse s3://bucket/key into (bucket, key).
/// Supports optional endpoint override via the S3_ENDPOINT env var.
fn parse_s3_url(url: &str) -> AftResult<(String, String)> {
    let rest = url
        .strip_prefix("s3://")
        .ok_or_else(|| AftError::InvalidUrl("Not an s3:// URL".into()))?;

    let (bucket, key) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    if bucket.is_empty() {
        return Err(AftError::InvalidUrl("S3 URL missing bucket name".into()));
    }

    Ok((bucket, key))
}

fn make_region() -> Region {
    if let Ok(endpoint) = std::env::var("S3_ENDPOINT") {
        let region_name = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        Region::Custom {
            region: region_name,
            endpoint,
        }
    } else {
        let region_name = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        region_name.parse().unwrap_or(Region::UsEast1)
    }
}

fn make_credentials(opts: &ProtocolOptions) -> AftResult<Credentials> {
    // Try bearer_token as a session token override, otherwise use env/profile
    if let Some(ref token) = opts.bearer_token {
        // Use explicit credentials if bearer_token looks like "ACCESS_KEY:SECRET_KEY"
        if let Some((ak, sk)) = token.split_once(':') {
            return Credentials::new(Some(ak), Some(sk), None, None, None)
                .map_err(|e| AftError::Other(format!("S3 credentials: {}", e)));
        }
    }

    if let Some((ref user, ref pass)) = opts.basic_auth {
        return Credentials::new(Some(user), Some(pass), None, None, None)
            .map_err(|e| AftError::Other(format!("S3 credentials: {}", e)));
    }

    // Fall back to default credential chain (env vars, AWS profile, instance metadata)
    Credentials::default().map_err(|e| AftError::Other(format!("S3 credentials: {}", e)))
}

async fn make_bucket(url: &str, opts: &ProtocolOptions) -> AftResult<(s3::Bucket, String)> {
    let (bucket_name, key) = parse_s3_url(url)?;
    let region = make_region();
    let creds = make_credentials(opts)?;

    let bucket = s3::Bucket::new(&bucket_name, region, creds)
        .map_err(|e| AftError::Other(format!("S3 bucket: {}", e)))?;

    Ok((*bucket, key))
}

#[async_trait]
impl ProtocolHandler for S3Handler {
    fn scheme(&self) -> &str {
        "s3"
    }

    fn name(&self) -> &str {
        "Amazon S3"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (bucket, key) = make_bucket(url, opts).await?;

        let (head, code) = bucket
            .head_object(&key)
            .await
            .map_err(|e| AftError::Other(format!("S3 HEAD: {}", e)))?;

        if code != 200 {
            return Err(AftError::HttpStatus {
                status: code,
                message: "S3 HEAD failed".to_string(),
            });
        }

        Ok(ResourceMetadata {
            content_length: head.content_length.map(|l| l as u64),
            content_type: head.content_type,
            last_modified: head.last_modified,
            etag: head.e_tag,
            accepts_ranges: true,
            headers: HashMap::new(),
        })
    }

    async fn download(
        &self,
        url: &str,
        dest: &Path,
        opts: &ProtocolOptions,
        _resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (bucket, key) = make_bucket(url, opts).await?;

        let response = bucket
            .get_object(&key)
            .await
            .map_err(|e| AftError::TransferFailed(format!("S3 GET: {}", e)))?;

        if response.status_code() != 200 {
            return Err(AftError::HttpStatus {
                status: response.status_code(),
                message: "S3 GET failed".to_string(),
            });
        }

        let data = response.bytes();
        let bytes_len = data.len() as u64;

        let mut file = tokio::fs::File::create(dest).await?;
        file.write_all(data).await?;
        file.flush().await?;

        if let Some(ref cb) = progress {
            cb(bytes_len, Some(bytes_len));
        }

        Ok(bytes_len)
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        let (bucket, key) = make_bucket(url, opts).await?;

        let range = format!("bytes={}-{}", start, end);
        let response = bucket
            .get_object_range(&key, start, Some(end))
            .await
            .map_err(|e| AftError::TransferFailed(format!("S3 GET range ({}): {}", range, e)))?;

        Ok(response.bytes().to_vec())
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
        let (bucket, key) = make_bucket(url, opts).await?;

        let data = tokio::fs::read(source).await?;
        let file_size = data.len() as u64;

        let ct = content_type.unwrap_or("application/octet-stream");
        let response = bucket
            .put_object_with_content_type(&key, &data, ct)
            .await
            .map_err(|e| AftError::TransferFailed(format!("S3 PUT: {}", e)))?;

        if response.status_code() != 200 {
            return Err(AftError::HttpStatus {
                status: response.status_code(),
                message: "S3 PUT failed".to_string(),
            });
        }

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (bucket, prefix) = make_bucket(url, opts).await?;

        let results = bucket
            .list(prefix.clone(), Some("/".to_string()))
            .await
            .map_err(|e| AftError::Other(format!("S3 LIST: {}", e)))?;

        let mut entries = Vec::new();

        for result in &results {
            // Common prefixes are "directories"
            if let Some(ref prefixes) = result.common_prefixes {
                for cp in prefixes {
                    let name = cp
                        .prefix
                        .strip_prefix(&prefix)
                        .unwrap_or(&cp.prefix)
                        .trim_end_matches('/')
                        .to_string();
                    if !name.is_empty() {
                        entries.push(DirectoryEntry {
                            name,
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

            // Objects are "files"
            for obj in &result.contents {
                let name = obj
                    .key
                    .strip_prefix(&prefix)
                    .unwrap_or(&obj.key)
                    .to_string();
                if !name.is_empty() && !name.ends_with('/') {
                    entries.push(DirectoryEntry {
                        name,
                        size: Some(obj.size),
                        is_directory: false,
                        last_modified: Some(obj.last_modified.clone()),
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
