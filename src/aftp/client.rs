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
    /// Offer the fountain-coded data plane during the handshake.
    fec_enabled: bool,
    /// Prefer QUIC unreliable datagrams over a bare UDP socket for the FEC data
    /// plane. Only meaningful alongside `fec_enabled`; negotiated via
    /// `CAP_FEC_QUIC` and falls back to UDP against a server without it.
    fec_quic: bool,
    /// Explicit consent to use the FEC data plane on an *unauthenticated*
    /// connection (no auth token → CRC32-only symbols, no encryption). Without
    /// it, the client refuses an unauthenticated FEC offer and stays on the
    /// reliable path, even if the server advertised the data plane.
    fec_allow_unauthenticated: bool,
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
            fec_enabled: false,
            fec_quic: false,
            fec_allow_unauthenticated: false,
        }
    }

    /// Enable HMAC-SHA256 challenge/response authentication.
    #[allow(dead_code)]
    pub fn with_challenge_auth(mut self, enable: bool) -> Self {
        self.use_challenge_auth = enable;
        self
    }

    /// Offer the fountain-coded UDP data plane.
    ///
    /// Advertising it is always safe: a server that does not support it omits
    /// `CAP_FEC` from its acknowledgement and the transfer proceeds over the
    /// ordinary reliable frame path.
    #[allow(dead_code)]
    pub fn with_fec(mut self, enable: bool) -> Self {
        self.fec_enabled = enable;
        self
    }

    /// Prefer QUIC unreliable datagrams for the FEC data plane (implies
    /// [`with_fec`](Self::with_fec)). Negotiated via `CAP_FEC_QUIC`; a server
    /// without it falls the data plane back to a bare UDP socket.
    #[allow(dead_code)]
    pub fn with_fec_quic(mut self, enable: bool) -> Self {
        self.fec_quic = enable;
        if enable {
            self.fec_enabled = true;
        }
        self
    }

    /// Consent to run the FEC data plane on an *unauthenticated* connection,
    /// where symbols are CRC32-only (no encryption or authenticity). The
    /// client-side counterpart to the server's `--fec-insecure`: without it,
    /// the client refuses such a data plane and falls back to the reliable
    /// path. Trusted lab links only; never for sensitive data.
    #[allow(dead_code)]
    pub fn with_unauthenticated_fec(mut self, allow: bool) -> Self {
        self.fec_allow_unauthenticated = allow;
        self
    }

    /// Open connection and perform HELLO handshake.
    /// Returns (reader, writer, negotiated_max_frame, use_compression, use_crc32,
    /// session_id, use_fec, use_fec_quic).
    async fn connect(
        &self,
    ) -> AftResult<(
        BufReader<BoxRead>,
        BufWriter<BoxWrite>,
        u32,
        bool,
        bool,
        String,
        bool,
        bool,
    )> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("AFTP connect to {}: {}", addr, e)))?;
        stream.set_nodelay(true).ok();
        // Enlarge socket buffers to the target BDP; without this the kernel
        // default caps throughput on high-latency links.
        super::transport::tune_tcp_socket(&stream);

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
        // Decide FEC consent *before* advertising the capability. With no auth
        // token the symbol key cannot be derived, so symbols would be CRC32-only
        // — cleartext, no authenticity — and the operator must opt in
        // (`--fec-insecure`). If we advertised CAP_FEC and then refused after the
        // server agreed, the server would still open a data plane we won't use and
        // strand the transfer; gating here keeps the server from ever agreeing.
        let fec_consented =
            self.fec_enabled && (self.auth_token.is_some() || self.fec_allow_unauthenticated);
        if self.fec_enabled && !fec_consented {
            eprintln!(
                "{}",
                "  note: refused FEC on an unauthenticated connection (symbols would be \
                 unencrypted); use --auth-token, or --fec-insecure for a trusted link"
                    .dimmed()
            );
        }
        if fec_consented {
            caps |= CAP_FEC;
        }
        if fec_consented && self.fec_quic {
            caps |= CAP_FEC_QUIC;
        }
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
        // Only when *both* ends advertise it; a v1 server simply omits the bit
        // and we stay on the reliable frame path.
        // We only advertised CAP_FEC after passing the consent gate above, so a
        // server bit here already implies a data plane we agreed to run.
        let use_fec = ack_data.capabilities & CAP_FEC != 0;
        // QUIC datagrams require the base FEC plane too; only when both ends
        // advertise CAP_FEC_QUIC. Otherwise the data plane stays on UDP.
        let use_fec_quic = use_fec && (ack_data.capabilities & CAP_FEC_QUIC != 0);
        let session_id = ack_data.session_id;

        Ok((
            reader,
            writer,
            ack_data.max_frame_size,
            use_compression,
            use_crc32,
            session_id,
            use_fec,
            use_fec_quic,
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
        // Enlarge socket buffers to the target BDP; without this the kernel
        // default caps throughput on high-latency links.
        super::transport::tune_tcp_socket(&stream);

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
        let (mut reader, mut writer, max_frame, _, _, _session_id, _, _) = self.connect().await?;

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
        let (
            mut reader,
            mut writer,
            max_frame,
            _use_compress,
            use_crc32,
            _session_id,
            use_fec,
            use_fec_quic,
        ) = self.connect().await?;

        // Send GET (full file)
        let payload = build_get(path, 0, 0);
        write_frame(&mut writer, &Frame::new(FRAME_GET, payload)).await?;
        writer.flush().await?;

        // Time the GET → HEAD_RESP exchange: one control-plane round trip,
        // measured on this very connection right before the data plane starts.
        // It seeds the receiver's patience timer far better than a fixed guess —
        // a 50 ms default asks for repair after 100 ms on a 400 ms-RTT path,
        // long before the answer to the spray can arrive, provoking spurious
        // NeedMore rounds and inflated loss estimates. See `download_fec`.
        let ctrl_sent = std::time::Instant::now();
        // Receive HEAD_RESP
        let head = Self::expect_frame(&mut reader, FRAME_HEAD_RESP, max_frame + 1024).await?;
        let meta = parse_head_resp(&head.payload)?;
        let ctrl_rtt = ctrl_sent.elapsed();

        if let Some(parent) = dest.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                eprintln!("Warning: failed to create directory {:?}: {}", parent, e);
            }
        }
        // Peek the first response frame. A server that wants to use the
        // fountain data plane answers with FEC_OFFER here instead of DATA;
        // anything else means we are on the ordinary reliable path.
        let first = read_frame(&mut reader, max_frame + 1024).await?;
        if first.frame_type == FRAME_FEC_OFFER {
            if !use_fec {
                return Err(AftError::Other(
                    "Server offered the FEC data plane without it being negotiated".into(),
                ));
            }
            return self
                .download_fec(
                    reader,
                    writer,
                    &first,
                    dest,
                    meta.file_size,
                    use_fec_quic,
                    ctrl_rtt,
                    progress,
                )
                .await;
        }

        let mut file = tokio::fs::File::create(dest).await?;
        let mut hasher = sha2::Sha256::new();
        let mut received = 0u64;

        // Receive DATA frames
        let mut pending = Some(first);
        loop {
            let frame = match pending.take() {
                Some(f) => f,
                None => read_frame(&mut reader, max_frame + 1024).await?,
            };
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

    // ── FEC UPLOAD ──────────────────────────────────────────────────────────

    /// Push a file over the fountain-coded UDP data plane.
    ///
    /// The mirror of [`Self::download_fec`] with the roles swapped: here the
    /// *client* is the symbol sender, so it makes the offer, and the server
    /// answers with the port to spray at and streams feedback back.
    ///
    /// Blocks are read from disk one window at a time, so pushing a 5 GB file
    /// costs the same memory as pushing 50 MB.
    async fn upload_fec(
        &self,
        reader: BufReader<BoxRead>,
        writer: BufWriter<BoxWrite>,
        source: &Path,
        file_size: u64,
        use_fec_quic: bool,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        use super::fec::transfer::FileBlocks;
        let blocks = FileBlocks::new(source.to_path_buf(), 0);
        self.spray_fec_object(
            reader,
            writer,
            &blocks,
            file_size,
            false,
            use_fec_quic,
            progress,
        )
        .await
    }

    /// Push a whole directory tree over the fountain data plane as one packed
    /// object. The tree is walked into a Merkle manifest ([`super::fec::manifest`]),
    /// the manifest rides at the front of the packed stream, and the file bytes
    /// follow — all sprayed by the same scheduler a single file uses, so a tree
    /// of many small files gets the data plane's loss tolerance that per-file
    /// transfers (each below the FEC floor) would never see.
    ///
    /// Requires the FEC data plane to be negotiated: tree packing has no reliable
    /// fallback of its own (callers wanting one decompose the tree file by file).
    pub async fn upload_tree(
        &self,
        source: &Path,
        remote_path: &str,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        use super::fec::manifest::{build_manifest, manifest_prefix, PackedTreeReader};

        let built = build_manifest(source).await?;
        let manifest = built.manifest;
        if built.symlinks_skipped > 0 {
            eprintln!(
                "  note: skipped {} symlink(s) — links are not packed across the transfer",
                built.symlinks_skipped
            );
        }
        let prefix = manifest_prefix(&manifest);
        let reader_blocks = PackedTreeReader::new(source.to_path_buf(), &manifest, prefix);
        let total_len = reader_blocks.total_len();

        let (
            mut reader,
            mut writer,
            _max_frame,
            _use_compress,
            _use_crc32,
            _session_id,
            use_fec,
            use_fec_quic,
        ) = self.connect().await?;
        if !use_fec {
            return Err(AftError::Other(
                "Whole-tree packing requires the FEC data plane, which this server did not negotiate"
                    .into(),
            ));
        }

        // Announce the packed object with a PUT to the destination directory,
        // then hand off to the shared FEC spray (which sends the tree marker
        // and the offer). The declared size is the whole packed length.
        let payload = build_put(remote_path, total_len);
        write_frame(&mut writer, &Frame::new(FRAME_PUT, payload)).await?;
        writer.flush().await?;

        let ack = Self::expect_frame(&mut reader, FRAME_PUT_ACK, INITIAL_MAX_PAYLOAD).await?;
        let ack_data = parse_put_ack(&ack.payload)?;
        if ack_data.complete {
            return Err(AftError::Other(
                "Server sent complete-ACK before tree transfer".into(),
            ));
        }

        self.spray_fec_object(
            reader,
            writer,
            &reader_blocks,
            total_len,
            true,
            use_fec_quic,
            progress,
        )
        .await
    }

    /// Shared core for pushing an object over the fountain data plane, used by
    /// both single-file (`upload_fec`) and whole-tree (`upload_tree`) pushes.
    ///
    /// `blocks` supplies the packed bytes on demand (a file, or the virtual
    /// packed-tree stream), so sender memory stays bounded by the window. When
    /// `is_tree` is set a one-byte tree marker precedes the offer, telling the
    /// server to unpack rather than rename. The closing DATA_END digest is
    /// computed by streaming `blocks` once after the spray — a page-cache-warm
    /// re-read that keeps peak memory at the window, not the object.
    #[allow(clippy::too_many_arguments)]
    async fn spray_fec_object(
        &self,
        mut reader: BufReader<BoxRead>,
        mut writer: BufWriter<BoxWrite>,
        blocks: &dyn super::fec::transfer::BlockReader,
        total_len: u64,
        is_tree: bool,
        use_fec_quic: bool,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        use super::fec::transfer::{send_blocks, FecParams, Feedback, SymbolSink, DEFAULT_WINDOW};
        use super::fec::udp::DataPlane;

        // A random session id, sent to the server in the offer below so both
        // ends agree on it. It must NOT be derived from public transfer
        // parameters: the per-session symbol key is derived from it, so a
        // predictable id (e.g. hash(host, port, file_size)) would yield a
        // predictable, reused key and let symbols captured from one upload be
        // replayed into a later same-size one.
        let session_id: u64 = super::fec::random_session_id();

        let key = super::fec::derive_symbol_key(self.auth_token.as_deref(), session_id);
        let authenticated = key.is_some();
        // A QUIC datagram is smaller than the UDP MTU, and the offer must fix the
        // symbol size before the QUIC path exists — so size to the conservative
        // QUIC floor when the data plane will ride datagrams.
        let symbol_size = if use_fec_quic {
            super::fec::quic_dgram::max_symbol_size_for(
                super::fec::quic_dgram::QUIC_DATAGRAM_MTU as usize,
                authenticated,
            )
        } else {
            super::fec::max_symbol_size(super::fec::DEFAULT_MTU, authenticated)
        };
        let block_size = super::fec::DEFAULT_BLOCK_SIZE as u32;
        let blocks_n = super::fec::block_count(total_len, block_size as usize);

        // A tree push announces itself before the offer so the server routes to
        // its unpacking receiver.
        if is_tree {
            write_frame(
                &mut writer,
                &Frame::new(FRAME_FEC_TREE, vec![super::fec::manifest::MANIFEST_VERSION]),
            )
            .await?;
        }

        write_frame(
            &mut writer,
            &Frame::new(
                FRAME_FEC_OFFER,
                build_fec_offer(
                    session_id,
                    total_len,
                    block_size,
                    symbol_size,
                    blocks_n,
                    authenticated,
                ),
            ),
        )
        .await?;
        writer.flush().await?;

        let accept_frame = Self::expect_frame(&mut reader, FRAME_FEC_ACCEPT, 64 * 1024).await?;
        let accept = parse_fec_accept(&accept_frame.payload)?;
        if !accept.accepted {
            return Err(AftError::Other(format!(
                "Server declined the FEC data plane: {}",
                accept.reason
            )));
        }

        // Resolve the server so we can dial its data-plane port (UDP socket or
        // QUIC listener, per negotiation).
        let server_ip: std::net::IpAddr = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .ok()
            .and_then(|mut it| it.next())
            .map(|a| a.ip())
            .ok_or_else(|| AftError::Other(format!("Cannot resolve {}", self.host)))?;
        let peer = std::net::SocketAddr::new(server_ip, accept.udp_port);

        // The sender is always the data-plane *connector*: it dials the port the
        // receiver advertised in the accept. Over QUIC that is a datagram
        // connection; over UDP a connected socket. Both implement `SymbolSink`.
        let plane: Box<dyn SymbolSink> = if use_fec_quic {
            Box::new(super::fec::quic_dgram::connect_plane(peer, key, session_id).await?)
        } else {
            let udp = DataPlane::bind_for_session("0.0.0.0:0", key, session_id).await?;
            udp.connect(peer).await?;
            Box::new(udp)
        };

        // Feedback arrives as control frames while we spray.
        let (fb_tx, mut fb_rx) = tokio::sync::mpsc::channel::<Feedback>(1024);

        let params = FecParams {
            session_id,
            total_len,
            block_size: block_size as usize,
            symbol_size,
            window: DEFAULT_WINDOW,
            initial_loss_hint: 0.0,
        };

        // `read_frame` is NOT cancellation-safe: it reads a 10-byte header and
        // then the payload, so a `select!` that drops it mid-frame silently
        // eats bytes and desynchronizes the control stream. Give the reader
        // its own task and select on a channel, which is cancellation-safe.
        let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<AftResult<Frame>>(64);
        let reader_task = tokio::spawn(async move {
            loop {
                let f = read_frame(&mut reader, 64 * 1024).await;
                let failed = f.is_err();
                if ctrl_tx.send(f).await.is_err() || failed {
                    break;
                }
            }
            reader
        });

        let send_fut = send_blocks(blocks, &*plane, &mut fb_rx, &params);
        tokio::pin!(send_fut);

        loop {
            tokio::select! {
                result = &mut send_fut => { result?; break; }
                incoming = ctrl_rx.recv() => {
                    let Some(frame) = incoming else { break };
                    let frame = frame?;
                    let msg = match frame.frame_type {
                        FRAME_FEC_NEEDMORE => {
                            let f = parse_fec_needmore(&frame.payload)?;
                            Feedback::NeedMore {
                                block_id: f.block_id,
                                symbols_needed: f.symbols_needed,
                                symbols_received: f.symbols_received,
                            }
                        }
                        FRAME_FEC_BLOCK_OK => {
                            let f = parse_fec_block_ok(&frame.payload)?;
                            Feedback::BlockOk {
                                block_id: f.block_id,
                                symbols_used: f.symbols_used,
                            }
                        }
                        FRAME_ERROR => {
                            let e = parse_error(&frame.payload)?;
                            return Err(AftError::Other(format!("Server error: {}", e.message)));
                        }
                        other => {
                            return Err(AftError::Other(format!(
                                "Unexpected frame 0x{:02x} during FEC upload",
                                other
                            )))
                        }
                    };
                    if fb_tx.send(msg).await.is_err() {
                        continue; // scheduler finished; select will pick it up
                    }
                }
            }
        }

        // Digest the whole packed object for the closing DATA_END by streaming
        // it back through the same reader. For a file this re-reads it (page
        // cache warm); for a tree it re-reads the manifest prefix and files.
        // Either way peak memory stays at one block.
        let digest = {
            let mut hasher = sha2::Sha256::new();
            let mut pos = 0u64;
            let chunk = block_size as u64;
            while pos < total_len {
                let want = chunk.min(total_len - pos) as usize;
                let bytes = blocks.read_block(pos, want).await?;
                hasher.update(&bytes);
                pos += want as u64;
            }
            hasher.finalize()
        };

        write_frame(
            &mut writer,
            &Frame::new(
                FRAME_DATA_END,
                build_data_end(total_len, CHECKSUM_SHA256, &digest),
            ),
        )
        .await?;
        writer.flush().await?;

        // The server verifies and commits, then acknowledges. The final ack
        // comes back through the same reader task, so drain any feedback still
        // in flight until it arrives.
        let ack = loop {
            match ctrl_rx.recv().await {
                Some(Ok(f)) if f.frame_type == FRAME_PUT_ACK => break f,
                Some(Ok(f)) if f.frame_type == FRAME_ERROR => {
                    let e = parse_error(&f.payload)?;
                    return Err(AftError::Other(format!("Server error: {}", e.message)));
                }
                // Trailing NEEDMORE/BLOCK_OK for already-finished blocks.
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e),
                None => {
                    return Err(AftError::Other(
                        "Control plane closed before the FEC upload was acknowledged".into(),
                    ))
                }
            }
        };
        reader_task.abort();
        let ack_data = parse_put_ack(&ack.payload)?;
        if !ack_data.complete {
            return Err(AftError::Other(
                "Server did not confirm the FEC upload".into(),
            ));
        }

        if let Some(cb) = &progress {
            cb(total_len, Some(total_len));
        }
        Ok(total_len)
    }

    // ── FEC DOWNLOAD ────────────────────────────────────────────────────────

    /// Receive a file over the fountain-coded UDP data plane.
    ///
    /// The control connection stays open throughout: we answer the offer on
    /// it, stream feedback over it while symbols arrive on UDP, and read the
    /// closing `DATA_END` (with the authoritative SHA-256) from it at the end.
    ///
    /// Nothing is written to `dest` until every block has decoded and the
    /// whole-file digest matches, so an aborted or corrupted transfer cannot
    /// leave partial data behind.
    #[allow(clippy::too_many_arguments)]
    async fn download_fec(
        &self,
        mut reader: BufReader<BoxRead>,
        mut writer: BufWriter<BoxWrite>,
        offer_frame: &Frame,
        dest: &Path,
        declared_size: u64,
        use_fec_quic: bool,
        ctrl_rtt: std::time::Duration,
        progress: Option<&(dyn Fn(u64, Option<u64>) + Send + Sync)>,
    ) -> AftResult<u64> {
        use super::fec::transfer::{
            recv_object_into, FecParams, Feedback, FileBlockWriter, SymbolSource, DEFAULT_WINDOW,
        };
        use super::fec::udp::DataPlane;

        let offer = parse_fec_offer(&offer_frame.payload)?;
        if offer.total_len != declared_size {
            return Err(AftError::Other(format!(
                "FEC offer declares {} bytes but HEAD_RESP said {}",
                offer.total_len, declared_size
            )));
        }

        let key = super::fec::derive_symbol_key(self.auth_token.as_deref(), offer.session_id);
        if offer.authenticated && key.is_none() {
            return Err(AftError::Other(
                "Server requires authenticated FEC symbols but this connection has no token".into(),
            ));
        }

        // The receiver is the data-plane *listener*: it binds a port and puts it
        // in the accept for the sender to dial. Over QUIC that is a datagram
        // listener whose incoming connection is accepted once the port is out;
        // over UDP a connectionless socket. Bind (and learn the port) before
        // sending the accept either way.
        let mut udp_plane: Option<DataPlane> = None;
        let mut quic_endpoint: Option<quinn::Endpoint> = None;
        let port = if use_fec_quic {
            let (ep, port) = super::fec::quic_dgram::bind_listener().await?;
            quic_endpoint = Some(ep);
            port
        } else {
            let udp =
                DataPlane::bind_for_session("0.0.0.0:0", key.clone(), offer.session_id).await?;
            let port = udp.local_addr()?.port();
            udp_plane = Some(udp);
            port
        };

        write_frame(
            &mut writer,
            &Frame::new(FRAME_FEC_ACCEPT, build_fec_accept(true, port, "")),
        )
        .await?;
        writer.flush().await?;

        // Feedback runs on its own task so the receive loop never blocks on
        // the control socket, and the control socket is never written from two
        // places at once.
        let (fb_tx, mut fb_rx) = tokio::sync::mpsc::channel::<Feedback>(1024);
        let fb_task = tokio::spawn(async move {
            while let Some(msg) = fb_rx.recv().await {
                let frame = match msg {
                    Feedback::NeedMore {
                        block_id,
                        symbols_needed,
                        symbols_received,
                    } => Frame::new(
                        FRAME_FEC_NEEDMORE,
                        build_fec_needmore(block_id, symbols_needed, symbols_received),
                    ),
                    Feedback::BlockOk {
                        block_id,
                        symbols_used,
                    } => Frame::new(
                        FRAME_FEC_BLOCK_OK,
                        build_fec_block_ok(block_id, symbols_used),
                    ),
                };
                write_frame(&mut writer, &frame).await?;
                writer.flush().await?;
            }
            Ok::<_, AftError>(writer)
        });

        let params = FecParams {
            session_id: offer.session_id,
            total_len: offer.total_len,
            block_size: offer.block_size as usize,
            symbol_size: offer.symbol_size,
            window: DEFAULT_WINDOW,
            initial_loss_hint: 0.0,
        };

        // Stream each block straight to a temporary file as it decodes, so peak
        // memory is the decoder working set (window × block size), not the
        // whole transfer. A malicious or buggy server therefore cannot exhaust
        // client memory by declaring a huge `total_len`. The real file is only
        // materialized after the SHA-256 check, so a failed transfer never
        // leaves a partial file at the destination.
        let tmp = {
            let mut name = dest
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            name.push(".aftp-part");
            dest.with_file_name(name)
        };
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        // Materialize the symbol source. For QUIC this accepts the sender's now
        // in-flight datagram connection (the accept went out above, so the peer
        // is dialing); for UDP the socket is already listening.
        let plane: Box<dyn SymbolSource> = if let Some(ep) = quic_endpoint.take() {
            Box::new(super::fec::quic_dgram::accept_plane(ep, key, offer.session_id).await?)
        } else {
            Box::new(udp_plane.take().expect("one plane is always bound"))
        };

        // Seed the receiver's patience from the control-plane RTT we just
        // measured (GET → HEAD_RESP), not a fixed guess. The receiver still
        // adapts from its own NeedMore round-trips, but starting near the real
        // RTT avoids a burst of premature repair asks on a high-latency path
        // before that adaptation converges. Clamp to a sane band: never below
        // the old 50 ms default (a sub-millisecond LAN measurement should not
        // make us ask for repair on a scheduler hiccup), never so high that the
        // first repair round waits seconds on a fluke reading.
        let rtt = ctrl_rtt.clamp(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(500),
        );
        let recv_result = match FileBlockWriter::create(&tmp, offer.total_len).await {
            Ok(mut sink) => {
                let r = recv_object_into(&*plane, &mut sink, &fb_tx, &params, rtt).await;
                if r.is_ok() {
                    let _ = sink.finish().await;
                }
                r
            }
            Err(e) => Err(e),
        };

        // Close the feedback channel so the writer task can finish and hand
        // the control stream back, even if the receive failed.
        drop(fb_tx);
        let writer = fb_task
            .await
            .map_err(|e| AftError::Other(format!("FEC feedback task: {}", e)))??;

        if let Err(e) = recv_result {
            let _ = tokio::fs::remove_file(&tmp).await;
            drop(writer);
            return Err(e);
        }
        if let Some(cb) = &progress {
            cb(offer.total_len, Some(offer.total_len));
        }

        // The server sends DATA_END on the control plane once every block is
        // acknowledged. Its digest is authoritative.
        let end_frame = Self::expect_frame(&mut reader, FRAME_DATA_END, 64 * 1024).await?;
        let end_data = parse_data_end(&end_frame.payload)?;

        let cleanup_and = |e: AftError| async {
            let _ = tokio::fs::remove_file(&tmp).await;
            e
        };

        if end_data.total_bytes != offer.total_len {
            return Err(cleanup_and(AftError::Other(format!(
                "FEC byte count mismatch: expected {}, got {}",
                end_data.total_bytes, offer.total_len
            )))
            .await);
        }
        if end_data.checksum_algo == CHECKSUM_SHA256 && !end_data.checksum.is_empty() {
            // Stream the temp file through SHA-256 rather than loading it, so
            // verification is also bounded memory.
            let mut f = tokio::fs::File::open(&tmp).await?;
            let mut hasher = sha2::Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut f, &mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let hash = hasher.finalize();
            if hash.as_slice() != end_data.checksum.as_slice() {
                return Err(cleanup_and(AftError::ChecksumMismatch {
                    expected: hex::encode(&end_data.checksum),
                    actual: hex::encode(hash),
                })
                .await);
            }
        }

        // Verified — atomically move the completed temp file into place.
        tokio::fs::rename(&tmp, dest).await?;

        // Keep the writer alive to this point so the control connection is not
        // torn down before the server has finished sending.
        drop(writer);
        Ok(offer.total_len)
    }

    // ── DOWNLOAD RANGE ──────────────────────────────────────────────────────

    pub async fn download_range(&self, path: &str, start: u64, end: u64) -> AftResult<Vec<u8>> {
        let (mut reader, mut writer, max_frame, _, use_crc32, _session_id, _, _) =
            self.connect().await?;

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

        let (
            mut reader,
            mut writer,
            max_frame,
            use_compress,
            use_crc32,
            _session_id,
            use_fec,
            use_fec_quic,
        ) = self.connect().await?;

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

        // Push over the fountain data plane when both ends agreed to it and
        // the file is large enough to be worth the setup.
        if use_fec && file_size >= super::fec::FEC_MIN_TRANSFER {
            return self
                .upload_fec(reader, writer, source, file_size, use_fec_quic, progress)
                .await;
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
        let (mut reader, mut writer, max_frame, _, _, _session_id, _, _) = self.connect().await?;

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
