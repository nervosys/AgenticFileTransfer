//! AFTP client: connects to an AFTP server and performs file operations.
//!
//! Each public method opens a fresh TCP connection, performs the HELLO
//! handshake (1 RTT), executes the operation, and closes the connection.
//! This is simple and correct; for parallel chunked downloads the engine
//! spawns multiple calls to `download_range` which run concurrently.
//!
//! Supports plain `aftp://` and TLS-encrypted `aftps://` connections.

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use colored::*;
use sha2::Digest;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

use crate::error::{AftError, AftResult};

use super::frame::*;

const BUF_SIZE: usize = DEFAULT_MAX_FRAME as usize + 1024;

// Boxed async I/O types for TLS/plain abstraction
type BoxRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

// ── Public types ────────────────────────────────────────────────────────────

pub struct AftpFileInfo {
    pub size: u64,
    pub modified_secs: u64,
    pub content_type: String,
}

pub struct AftpDirEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified_secs: u64,
}

pub struct AftpClient {
    host: String,
    port: u16,
    auth_token: Option<String>,
    use_tls: bool,
    insecure: bool,
    use_challenge_auth: bool,
}

// ── URL parsing ─────────────────────────────────────────────────────────────

/// Parse `aftp://host:port/path` or `aftps://host:port/path` → (host, port, path, use_tls).
pub fn parse_aftp_url(url: &str) -> AftResult<(String, u16, String, bool)> {
    let (rest, use_tls) = if let Some(r) = url.strip_prefix("aftps://") {
        (r, true)
    } else if let Some(r) = url.strip_prefix("aftp://") {
        (r, false)
    } else {
        return Err(AftError::InvalidUrl(
            "Not an aftp:// or aftps:// URL".into(),
        ));
    };

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = if let Some(i) = host_port.rfind(':') {
        (
            host_port[..i].to_string(),
            host_port[i + 1..]
                .parse::<u16>()
                .map_err(|_| AftError::InvalidUrl("Invalid port in AFTP URL".into()))?,
        )
    } else {
        (host_port.to_string(), DEFAULT_PORT)
    };

    if host.is_empty() {
        return Err(AftError::InvalidUrl("Empty host in AFTP URL".into()));
    }

    Ok((host, port, path.to_string(), use_tls))
}

// ── Client impl ─────────────────────────────────────────────────────────────

impl AftpClient {
    pub fn new(
        host: String,
        port: u16,
        auth_token: Option<String>,
        use_tls: bool,
        insecure: bool,
    ) -> Self {
        Self {
            host,
            port,
            auth_token,
            use_tls,
            insecure,
            use_challenge_auth: false,
        }
    }

    /// Enable HMAC-SHA256 challenge/response authentication.
    #[allow(dead_code)]
    pub fn with_challenge_auth(mut self, enable: bool) -> Self {
        self.use_challenge_auth = enable;
        self
    }

    /// Open connection and perform HELLO handshake.
    /// Returns (reader, writer, negotiated_max_frame, use_compression, use_crc32, session_id).
    async fn connect(
        &self,
    ) -> AftResult<(
        BufReader<BoxRead>,
        BufWriter<BoxWrite>,
        u32,
        bool,
        bool,
        String,
    )> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("AFTP connect to {}: {}", addr, e)))?;
        stream.set_nodelay(true).ok();

        let (mut reader, mut writer) = if self.use_tls {
            let config = make_client_tls_config(self.insecure)?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| AftError::Other(format!("Invalid TLS server name: {}", self.host)))?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| AftError::ConnectionFailed(format!("AFTP TLS handshake: {}", e)))?;
            let (rd, wr) = tokio::io::split(tls_stream);
            (
                BufReader::with_capacity(BUF_SIZE, Box::new(rd) as BoxRead),
                BufWriter::with_capacity(BUF_SIZE, Box::new(wr) as BoxWrite),
            )
        } else {
            let (rd, wr) = stream.into_split();
            (
                BufReader::with_capacity(BUF_SIZE, Box::new(rd) as BoxRead),
                BufWriter::with_capacity(BUF_SIZE, Box::new(wr) as BoxWrite),
            )
        };

        // Send HELLO
        let mut caps = CAP_COMPRESSION | CAP_CHECKSUM | CAP_CRC32_FRAMES;
        if self.use_challenge_auth {
            caps |= CAP_AUTH_CHALLENGE;
        }
        let hello_payload = build_hello(caps, self.auth_token.as_deref());
        write_frame(&mut writer, &Frame::new(FRAME_HELLO, hello_payload)).await?;
        writer.flush().await?;

        // Read next frame — could be HELLO_ACK or AUTH_CHALLENGE
        let next = read_frame(&mut reader, INITIAL_MAX_PAYLOAD).await?;

        let ack = if next.frame_type == FRAME_AUTH_CHALLENGE {
            // Server wants challenge/response
            let challenge = parse_auth_challenge(&next.payload)?;

            let token = self
                .auth_token
                .as_deref()
                .ok_or_else(|| AftError::AuthFailed("Auth token required for challenge".into()))?;

            // Compute HMAC-SHA256(token, nonce)
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC key length");
            mac.update(&challenge.nonce);
            let result = mac.finalize().into_bytes();

            let resp_payload = build_auth_response(&result);
            write_frame(&mut writer, &Frame::new(FRAME_AUTH_RESPONSE, resp_payload)).await?;
            writer.flush().await?;

            // Now expect HELLO_ACK
            read_frame(&mut reader, INITIAL_MAX_PAYLOAD).await?
        } else {
            next
        };

        if ack.frame_type == FRAME_ERROR {
            let e = parse_error(&ack.payload)?;
            return Err(AftError::ConnectionFailed(format!(
                "Server rejected HELLO: {}",
                e.message
            )));
        }
        if ack.frame_type != FRAME_HELLO_ACK {
            return Err(AftError::Other(format!(
                "Expected HELLO_ACK, got 0x{:02x}",
                ack.frame_type
            )));
        }

        let ack_data = parse_hello_ack(&ack.payload)?;
        let use_compression = ack_data.capabilities & CAP_COMPRESSION != 0;
        let use_crc32 = ack_data.capabilities & CAP_CRC32_FRAMES != 0;
        let session_id = ack_data.session_id;

        Ok((
            reader,
            writer,
            ack_data.max_frame_size,
            use_compression,
            use_crc32,
            session_id,
        ))
    }

    /// Open connection and resume a previous session.
    /// Returns (reader, writer, max_frame, use_compression, use_crc32, resume_offset, resume_path).
    #[allow(dead_code)]
    async fn resume_connect(
        &self,
        session_id: &str,
    ) -> AftResult<(
        BufReader<BoxRead>,
        BufWriter<BoxWrite>,
        u32,
        bool,
        bool,
        u64,
        String,
    )> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("AFTP connect to {}: {}", addr, e)))?;
        stream.set_nodelay(true).ok();

        let (mut reader, mut writer) = if self.use_tls {
            let config = make_client_tls_config(self.insecure)?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| AftError::Other(format!("Invalid TLS server name: {}", self.host)))?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| AftError::ConnectionFailed(format!("AFTP TLS handshake: {}", e)))?;
            let (rd, wr) = tokio::io::split(tls_stream);
            (
                BufReader::with_capacity(BUF_SIZE, Box::new(rd) as BoxRead),
                BufWriter::with_capacity(BUF_SIZE, Box::new(wr) as BoxWrite),
            )
        } else {
            let (rd, wr) = stream.into_split();
            (
                BufReader::with_capacity(BUF_SIZE, Box::new(rd) as BoxRead),
                BufWriter::with_capacity(BUF_SIZE, Box::new(wr) as BoxWrite),
            )
        };

        // Send RESUME frame
        let mut caps = CAP_COMPRESSION | CAP_CHECKSUM | CAP_SESSION_RESUME | CAP_CRC32_FRAMES;
        if self.use_challenge_auth {
            caps |= CAP_AUTH_CHALLENGE;
        }
        let resume_payload = build_resume(session_id, caps, self.auth_token.as_deref());
        write_frame(&mut writer, &Frame::new(FRAME_RESUME, resume_payload)).await?;
        writer.flush().await?;

        let ack = read_frame(&mut reader, INITIAL_MAX_PAYLOAD).await?;
        if ack.frame_type == FRAME_ERROR {
            let e = parse_error(&ack.payload)?;
            return Err(AftError::ConnectionFailed(format!(
                "Server rejected RESUME: {}",
                e.message
            )));
        }
        if ack.frame_type != FRAME_RESUME_ACK {
            return Err(AftError::Other(format!(
                "Expected RESUME_ACK, got 0x{:02x}",
                ack.frame_type
            )));
        }

        let ack_data = parse_resume_ack(&ack.payload)?;
        if !ack_data.accepted {
            return Err(AftError::Other("Server rejected session resume".into()));
        }

        // Inherit compression setting from the original connection
        let use_compression = true; // server advertised in original HELLO_ACK
        let use_crc32 = true; // CRC32 always available
                              // Use the server's max frame as a safe default
        let max_frame = DEFAULT_MAX_FRAME;

        Ok((
            reader,
            writer,
            max_frame,
            use_compression,
            use_crc32,
            ack_data.bytes_received,
            ack_data.path,
        ))
    }

    /// Upload a file, resuming from `byte_offset` when reconnecting after a
    /// dropped connection. This is used by the engine retry logic.
    #[allow(dead_code)]
    pub async fn upload_resume(
        &self,
        source: &Path,
        remote_path: &str,
        session_id: &str,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        let file_meta = tokio::fs::metadata(source).await?;
        let file_size = file_meta.len();

        let (mut reader, mut writer, max_frame, use_compress, _use_crc32, byte_offset, _path) =
            self.resume_connect(session_id).await?;

        // Seek past what the server already has
        let mut file = tokio::fs::File::open(source).await?;
        if byte_offset > 0 {
            tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(byte_offset)).await?;
        }

        // Send PUT request for the resumed transfer
        let payload = build_put(remote_path, file_size);
        write_frame(&mut writer, &Frame::new(FRAME_PUT, payload)).await?;
        writer.flush().await?;

        let ack = Self::expect_frame(&mut reader, FRAME_PUT_ACK, INITIAL_MAX_PAYLOAD).await?;
        let ack_data = parse_put_ack(&ack.payload)?;
        if ack_data.complete {
            return Err(AftError::Other(
                "Server sent complete-ACK before data transfer".into(),
            ));
        }

        // Stream remaining data from byte_offset
        let frame_buf_size = max_frame as usize;
        let mut buf = vec![0u8; frame_buf_size];
        let mut hasher = sha2::Sha256::new();
        let mut total_sent = byte_offset;

        // Hash the already-sent portion so the final checksum is correct
        // Re-read from the beginning and hash just the skipped portion
        if byte_offset > 0 {
            let mut pre_file = tokio::fs::File::open(source).await?;
            let mut pre_buf = vec![0u8; 65_536];
            let mut remaining = byte_offset;
            while remaining > 0 {
                let to_read = remaining.min(pre_buf.len() as u64) as usize;
                let n =
                    tokio::io::AsyncReadExt::read(&mut pre_file, &mut pre_buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&pre_buf[..n]);
                remaining -= n as u64;
            }
        }

        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);

            if use_compress {
                if let Ok(compressed) = zstd::encode_all(std::io::Cursor::new(&buf[..n]), 1) {
                    if compressed.len() < n {
                        write_frame(
                            &mut writer,
                            &Frame::with_flags(FRAME_DATA, FLAG_COMPRESSED, compressed),
                        )
                        .await?;
                        total_sent += n as u64;
                        if let Some(cb) = &progress {
                            cb(total_sent, Some(file_size));
                        }
                        continue;
                    }
                }
            }

            write_frame_header(&mut writer, FRAME_DATA, 0, n as u32).await?;
            writer.write_all(&buf[..n]).await?;
            total_sent += n as u64;
            if let Some(cb) = &progress {
                cb(total_sent, Some(file_size));
            }
        }

        // DATA_END with checksum over the entire file
        let hash = hasher.finalize();
        let end_payload = build_data_end(file_size, CHECKSUM_SHA256, &hash);
        write_frame(&mut writer, &Frame::new(FRAME_DATA_END, end_payload)).await?;
        writer.flush().await?;

        let final_ack = Self::expect_frame(&mut reader, FRAME_PUT_ACK, INITIAL_MAX_PAYLOAD).await?;
        let final_ack_data = parse_put_ack(&final_ack.payload)?;
        if !final_ack_data.complete {
            return Err(AftError::Other(
                "Server did not confirm PUT completion".into(),
            ));
        }

        Ok(total_sent)
    }

    /// Read the next frame hoping for `expected`; surface ERROR frames as errors.
    async fn expect_frame(
        reader: &mut BufReader<BoxRead>,
        expected: u8,
        max_payload: u32,
    ) -> AftResult<Frame> {
        let frame = read_frame(reader, max_payload).await?;
        if frame.frame_type == FRAME_ERROR {
            let e = parse_error(&frame.payload)?;
            return Err(AftError::Other(format!("Server error: {}", e.message)));
        }
        if frame.frame_type != expected {
            return Err(AftError::Other(format!(
                "Expected frame 0x{:02x}, got 0x{:02x}",
                expected, frame.frame_type
            )));
        }
        Ok(frame)
    }

    // ── HEAD ────────────────────────────────────────────────────────────────

    pub async fn head(&self, path: &str) -> AftResult<AftpFileInfo> {
        let (mut reader, mut writer, max_frame, _, _, _session_id) = self.connect().await?;

        let payload = build_head(path);
        write_frame(&mut writer, &Frame::new(FRAME_HEAD, payload)).await?;
        writer.flush().await?;

        let resp = Self::expect_frame(&mut reader, FRAME_HEAD_RESP, max_frame + 1024).await?;
        let meta = parse_head_resp(&resp.payload)?;

        Ok(AftpFileInfo {
            size: meta.file_size,
            modified_secs: meta.modified_secs,
            content_type: meta.content_type,
        })
    }

    // ── DOWNLOAD (full file) ────────────────────────────────────────────────

    pub async fn download(
        &self,
        path: &str,
        dest: &Path,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        let (mut reader, mut writer, max_frame, _use_compress, use_crc32, _session_id) =
            self.connect().await?;

        // Send GET (full file)
        let payload = build_get(path, 0, 0);
        write_frame(&mut writer, &Frame::new(FRAME_GET, payload)).await?;
        writer.flush().await?;

        // Receive HEAD_RESP
        let head = Self::expect_frame(&mut reader, FRAME_HEAD_RESP, max_frame + 1024).await?;
        let meta = parse_head_resp(&head.payload)?;

        if let Some(parent) = dest.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                eprintln!("Warning: failed to create directory {:?}: {}", parent, e);
            }
        }
        let mut file = tokio::fs::File::create(dest).await?;
        let mut hasher = sha2::Sha256::new();
        let mut received = 0u64;

        // Receive DATA frames
        loop {
            let frame = read_frame(&mut reader, max_frame + 1024).await?;
            match frame.frame_type {
                FRAME_DATA => {
                    // Verify per-frame CRC32 if present (hardware-accelerated)
                    let raw_payload = if use_crc32 && frame.flags & FLAG_CRC32 != 0 {
                        let data_len = verify_frame_crc32(&frame.payload)?;
                        frame.payload[..data_len].to_vec()
                    } else {
                        frame.payload
                    };
                    let data = if frame.flags & FLAG_COMPRESSED != 0 {
                        zstd::decode_all(Cursor::new(&raw_payload))
                            .map_err(|e| AftError::Other(format!("zstd error: {}", e)))?
                    } else {
                        raw_payload
                    };
                    hasher.update(&data);
                    tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                    received += data.len() as u64;
                    if let Some(cb) = &progress {
                        cb(received, Some(meta.file_size));
                    }
                }
                FRAME_DATA_END => {
                    let end_data = parse_data_end(&frame.payload)?;
                    // Verify
                    if end_data.total_bytes != received {
                        return Err(AftError::Other(format!(
                            "Byte count mismatch: expected {}, got {}",
                            end_data.total_bytes, received
                        )));
                    }
                    if end_data.checksum_algo == CHECKSUM_SHA256 && !end_data.checksum.is_empty() {
                        let hash = hasher.finalize();
                        if hash.as_slice() != end_data.checksum.as_slice() {
                            return Err(AftError::ChecksumMismatch {
                                expected: hex::encode(&end_data.checksum),
                                actual: hex::encode(hash),
                            });
                        }
                    }
                    break;
                }
                FRAME_ERROR => {
                    let e = parse_error(&frame.payload)?;
                    return Err(AftError::Other(format!("Server error: {}", e.message)));
                }
                _ => {
                    return Err(AftError::Other(format!(
                        "Unexpected frame 0x{:02x}",
                        frame.frame_type
                    )));
                }
            }
        }

        file.flush().await?;
        Ok(received)
    }

    // ── DOWNLOAD RANGE ──────────────────────────────────────────────────────

    pub async fn download_range(&self, path: &str, start: u64, end: u64) -> AftResult<Vec<u8>> {
        let (mut reader, mut writer, max_frame, _, use_crc32, _session_id) = self.connect().await?;

        let payload = build_get(path, start, end);
        write_frame(&mut writer, &Frame::new(FRAME_GET, payload)).await?;
        writer.flush().await?;

        // HEAD_RESP
        let _head = Self::expect_frame(&mut reader, FRAME_HEAD_RESP, max_frame + 1024).await?;

        let expected_len = (end - start + 1) as usize;
        let mut result = Vec::with_capacity(expected_len);

        loop {
            let frame = read_frame(&mut reader, max_frame + 1024).await?;
            match frame.frame_type {
                FRAME_DATA => {
                    // Verify per-frame CRC32 if present (hardware-accelerated)
                    let raw_payload = if use_crc32 && frame.flags & FLAG_CRC32 != 0 {
                        let data_len = verify_frame_crc32(&frame.payload)?;
                        frame.payload[..data_len].to_vec()
                    } else {
                        frame.payload
                    };
                    let data = if frame.flags & FLAG_COMPRESSED != 0 {
                        zstd::decode_all(Cursor::new(&raw_payload))
                            .map_err(|e| AftError::Other(format!("zstd error: {}", e)))?
                    } else {
                        raw_payload
                    };
                    result.extend_from_slice(&data);
                }
                FRAME_DATA_END => break,
                FRAME_ERROR => {
                    let e = parse_error(&frame.payload)?;
                    return Err(AftError::Other(format!("Server error: {}", e.message)));
                }
                _ => {
                    return Err(AftError::Other(format!(
                        "Unexpected frame 0x{:02x}",
                        frame.frame_type
                    )));
                }
            }
        }

        Ok(result)
    }

    // ── UPLOAD ──────────────────────────────────────────────────────────────

    pub async fn upload(
        &self,
        source: &Path,
        remote_path: &str,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        let file_meta = tokio::fs::metadata(source).await?;
        let file_size = file_meta.len();

        let (mut reader, mut writer, max_frame, use_compress, use_crc32, _session_id) =
            self.connect().await?;

        // Send PUT request
        let payload = build_put(remote_path, file_size);
        write_frame(&mut writer, &Frame::new(FRAME_PUT, payload)).await?;
        writer.flush().await?;

        // Wait for PUT_ACK (ready)
        let ack = Self::expect_frame(&mut reader, FRAME_PUT_ACK, INITIAL_MAX_PAYLOAD).await?;
        let ack_data = parse_put_ack(&ack.payload)?;
        if ack_data.complete {
            return Err(AftError::Other(
                "Server sent complete-ACK before data transfer".into(),
            ));
        }

        // Stream data
        let mut file = tokio::fs::File::open(source).await?;
        let frame_buf_size = max_frame as usize;
        let mut buf = vec![0u8; frame_buf_size];
        let mut hasher = sha2::Sha256::new();
        let mut total_sent = 0u64;

        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);

            if use_compress {
                if let Ok(compressed) = zstd::encode_all(Cursor::new(&buf[..n]), 1) {
                    if compressed.len() < n {
                        if use_crc32 {
                            let crc = crc32fast::hash(&compressed);
                            let mut payload = compressed;
                            payload.extend_from_slice(&crc.to_le_bytes());
                            write_frame(
                                &mut writer,
                                &Frame::with_flags(
                                    FRAME_DATA,
                                    FLAG_COMPRESSED | FLAG_CRC32,
                                    payload,
                                ),
                            )
                            .await?;
                        } else {
                            write_frame(
                                &mut writer,
                                &Frame::with_flags(FRAME_DATA, FLAG_COMPRESSED, compressed),
                            )
                            .await?;
                        }
                        total_sent += n as u64;
                        if let Some(cb) = &progress {
                            cb(total_sent, Some(file_size));
                        }
                        continue;
                    }
                }
            }

            if use_crc32 {
                let crc = crc32fast::hash(&buf[..n]);
                let frame_len = n as u32 + 4;
                write_frame_header(&mut writer, FRAME_DATA, FLAG_CRC32, frame_len).await?;
                writer.write_all(&buf[..n]).await?;
                writer.write_all(&crc.to_le_bytes()).await?;
            } else {
                write_frame_header(&mut writer, FRAME_DATA, 0, n as u32).await?;
                writer.write_all(&buf[..n]).await?;
            }
            total_sent += n as u64;
            if let Some(cb) = &progress {
                cb(total_sent, Some(file_size));
            }
        }

        // DATA_END
        let hash = hasher.finalize();
        let end_payload = build_data_end(total_sent, CHECKSUM_SHA256, &hash);
        write_frame(&mut writer, &Frame::new(FRAME_DATA_END, end_payload)).await?;
        writer.flush().await?;

        // Wait for final PUT_ACK (complete)
        let final_ack = Self::expect_frame(&mut reader, FRAME_PUT_ACK, INITIAL_MAX_PAYLOAD).await?;
        let final_ack_data = parse_put_ack(&final_ack.payload)?;
        if !final_ack_data.complete {
            return Err(AftError::Other(
                "Server did not confirm PUT completion".into(),
            ));
        }

        Ok(total_sent)
    }

    // ── LIST ────────────────────────────────────────────────────────────────

    pub async fn list(&self, path: &str) -> AftResult<Vec<AftpDirEntry>> {
        let (mut reader, mut writer, max_frame, _, _, _session_id) = self.connect().await?;

        let payload = build_list(path);
        write_frame(&mut writer, &Frame::new(FRAME_LIST, payload)).await?;
        writer.flush().await?;

        let resp = Self::expect_frame(&mut reader, FRAME_LIST_RESP, max_frame + 65536).await?;
        let entries = parse_list_resp(&resp.payload)?;

        Ok(entries
            .into_iter()
            .map(|e| AftpDirEntry {
                name: e.name,
                size: e.size,
                is_dir: e.is_dir,
                modified_secs: e.modified_secs,
            })
            .collect())
    }
}

// ── TLS helpers ─────────────────────────────────────────────────────────────

fn make_client_tls_config(insecure: bool) -> AftResult<Arc<rustls::ClientConfig>> {
    // Restrict to TLS 1.2+ and FIPS-compatible cipher suites
    let tls_versions = &[&rustls::version::TLS13, &rustls::version::TLS12];
    let cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites,
        ..rustls::crypto::ring::default_provider()
    };
    let provider = Arc::new(provider);

    if insecure {
        eprintln!(
            "  {} TLS certificate verification DISABLED (--insecure). Do NOT use in production.",
            "WARNING:".red().bold()
        );
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(tls_versions)
            .map_err(|e| AftError::Other(format!("TLS version config error: {}", e)))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth();
        Ok(Arc::new(config))
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(tls_versions)
            .map_err(|e| AftError::Other(format!("TLS version config error: {}", e)))?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

/// Certificate verifier that accepts any server certificate (for `--insecure` mode).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
