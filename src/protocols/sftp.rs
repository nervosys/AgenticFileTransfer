use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use russh::client;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct SftpHandler {
    scheme: String,
}

impl SftpHandler {
    pub fn new(scheme: String) -> Self {
        Self { scheme }
    }
}

/// Parse sftp://user:pass@host:port/path
#[allow(clippy::type_complexity)]
fn parse_sftp_url(url: &str) -> AftResult<(String, u16, Option<String>, Option<String>, String)> {
    let parsed = url::Url::parse(url)
        .map_err(|e| AftError::InvalidUrl(format!("Invalid SFTP URL: {}", e)))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| AftError::InvalidUrl("SFTP URL missing host".into()))?
        .to_string();
    let port = parsed.port().unwrap_or(22);
    let user = if parsed.username().is_empty() {
        None
    } else {
        Some(parsed.username().to_string())
    };
    let pass = parsed.password().map(|s| s.to_string());
    let path = parsed.path().to_string();

    Ok((host, port, user, pass, path))
}

// Minimal SSH client handler for russh.
//
// russh 0.62's `client::Handler` is a native async-fn-in-trait (it only wears
// `#[async_trait]` when russh's `async-trait` feature is on, which we do not
// enable), so this impl uses a plain `async fn` and must NOT carry the
// `#[async_trait]` attribute — that would rewrite it to a boxed future and no
// longer match the trait.
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // WARNING: Host key verification is not yet implemented.
        // This is equivalent to StrictHostKeyChecking=no and is vulnerable to MITM.
        // TODO(security): implement known_hosts checking (~/.ssh/known_hosts)
        eprintln!("\x1b[33mWARNING: SSH host key verification is disabled — MITM risk\x1b[0m");
        Ok(true)
    }
}

async fn open_sftp(
    url: &str,
    opts: &ProtocolOptions,
) -> AftResult<(SftpSession, client::Handle<SshHandler>, String)> {
    let (host, port, user, pass, path) = parse_sftp_url(url)?;

    let config = client::Config::default();
    let config = Arc::new(config);
    let sh = SshHandler;

    let mut session = client::connect(config, (host.as_str(), port), sh)
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("SSH connect: {}", e)))?;

    // Determine credentials
    let ssh_user = user
        .or_else(|| opts.basic_auth.as_ref().map(|(u, _)| u.clone()))
        .unwrap_or_else(whoami::username);
    let ssh_pass = pass.or_else(|| opts.basic_auth.as_ref().map(|(_, p)| p.clone()));

    // Try key-based auth first, then password
    let mut authenticated = false;

    // Try SSH keys from standard locations
    if !authenticated {
        if let Some(home) = dirs::home_dir() {
            for key_name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
                let key_path = home.join(".ssh").join(key_name);
                if key_path.exists() {
                    if let Ok(key_pair) = load_secret_key(&key_path, None) {
                        // russh 0.62: authenticate_publickey takes a
                        // PrivateKeyWithHashAlg (None → default/legacy hash for
                        // RSA, ignored for other key types) and returns an
                        // AuthResult rather than a bool.
                        let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
                        if session
                            .authenticate_publickey(&ssh_user, key)
                            .await
                            .map(|r| r.success())
                            .unwrap_or(false)
                        {
                            authenticated = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Fall back to password auth
    if !authenticated {
        if let Some(ref password) = ssh_pass {
            authenticated = session
                .authenticate_password(&ssh_user, password)
                .await
                .map_err(|e| AftError::ConnectionFailed(format!("SSH auth: {}", e)))?
                .success();
        }
    }

    if !authenticated {
        return Err(AftError::PermissionDenied(
            "SSH authentication failed. Provide credentials via URL or --auth, or ensure SSH keys are available.".into(),
        ));
    }

    // Open SFTP subsystem
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("SSH channel: {}", e)))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("SFTP subsystem: {}", e)))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("SFTP session: {}", e)))?;

    Ok((sftp, session, path))
}

#[async_trait]
impl ProtocolHandler for SftpHandler {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn name(&self) -> &str {
        "SFTP/SCP"
    }

    fn supports_ranges(&self) -> bool {
        false
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (sftp, _session, path) = open_sftp(url, opts).await?;

        let meta = sftp
            .metadata(&path)
            .await
            .map_err(|e| AftError::FileNotFound(format!("SFTP stat: {}", e)))?;

        Ok(ResourceMetadata {
            content_length: meta.size,
            content_type: None,
            last_modified: meta.mtime.map(|t| t.to_string()),
            etag: None,
            accepts_ranges: false,
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
        let (sftp, _session, path) = open_sftp(url, opts).await?;

        let data = sftp
            .read(&path)
            .await
            .map_err(|e| AftError::TransferFailed(format!("SFTP read: {}", e)))?;

        let bytes_len = data.len() as u64;

        let mut file = tokio::fs::File::create(dest).await?;
        file.write_all(&data).await?;
        file.flush().await?;

        if let Some(ref cb) = progress {
            cb(bytes_len, Some(bytes_len));
        }

        Ok(bytes_len)
    }

    async fn download_range(
        &self,
        _url: &str,
        _start: u64,
        _end: u64,
        _opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        Err(AftError::UnsupportedProtocol(
            "SFTP does not support range downloads".into(),
        ))
    }

    async fn upload(
        &self,
        source: &Path,
        url: &str,
        opts: &ProtocolOptions,
        _content_type: Option<&str>,
        _method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (sftp, _session, path) = open_sftp(url, opts).await?;

        let data = tokio::fs::read(source).await?;
        let file_size = data.len() as u64;

        sftp.write(&path, &data)
            .await
            .map_err(|e| AftError::TransferFailed(format!("SFTP write: {}", e)))?;

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (sftp, _session, path) = open_sftp(url, opts).await?;

        let dir_path = if path.is_empty() { "/" } else { &path };

        let entries = sftp
            .read_dir(dir_path)
            .await
            .map_err(|e| AftError::Other(format!("SFTP readdir: {}", e)))?;

        let result = entries
            .into_iter()
            .filter(|e| e.file_name() != "." && e.file_name() != "..")
            .map(|e| {
                let meta = e.metadata();
                DirectoryEntry {
                    name: e.file_name(),
                    size: meta.size,
                    is_directory: meta.is_dir(),
                    last_modified: meta.mtime.map(|t| t.to_string()),
                    relative_path: None,
                    is_symlink: None,
                    permissions: None,
                }
            })
            .collect();

        Ok(result)
    }
}
