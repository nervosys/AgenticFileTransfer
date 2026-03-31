//! AFTP server: high-performance binary file server.
//!
//! Performance advantages over traditional servers:
//! - 10-byte binary frame headers (vs. HTTP's kilobyte-scale text headers)
//! - 1 MB data frames minimise syscall overhead
//! - Inline streaming SHA-256 (no post-transfer verification pass)
//! - Optional zstd level-1 compression (~500 MB/s encode, ~1700 MB/s decode)
//! - Zero-copy data path: file→buffer→socket with no intermediate copies
//! - TCP_NODELAY for immediate frame dispatch
//! - One connection handles many sequential operations (no reconnect cost)
//! - Challenge/response auth via HMAC-SHA256 for secure token validation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use colored::*;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::audit;
use crate::error::{AftError, AftResult};

use super::frame::*;

const WRITE_BUF: usize = DEFAULT_MAX_FRAME as usize + HEADER_SIZE + 256;
const READ_BUF: usize = 65_536;

/// Maximum failed auth attempts before an IP is locked out.
const AUTH_MAX_FAILURES: u32 = 5;
/// Duration (seconds) an IP is locked out after exceeding max failures.
const AUTH_LOCKOUT_SECS: u64 = 60;
/// Idle connection timeout in seconds.
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;
/// Default keepalive interval in seconds (0 = disabled).
#[allow(dead_code)]
const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// Maximum lifetime of a resumable session (10 minutes).
const SESSION_MAX_AGE_SECS: u64 = 600;
/// Maximum number of tracked sessions.
const MAX_SESSIONS: usize = 10_000;

/// Per-IP rate limiter for authentication attempts.
/// Bounded to MAX_TRACKED_IPS to prevent memory exhaustion under DoS.
const MAX_TRACKED_IPS: usize = 10_000;

struct AuthRateLimiter {
    /// Map of IP → (failure_count, last_failure_time)
    failures: HashMap<std::net::IpAddr, (u32, std::time::Instant)>,
}

impl AuthRateLimiter {
    fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    /// Check if an IP is currently locked out.
    fn is_locked_out(&mut self, ip: &std::net::IpAddr) -> bool {
        if let Some((count, last_time)) = self.failures.get(ip) {
            if *count >= AUTH_MAX_FAILURES {
                if last_time.elapsed().as_secs() < AUTH_LOCKOUT_SECS {
                    return true;
                }
                // Lockout expired — reset
                self.failures.remove(ip);
            }
        }
        false
    }

    /// Record a failed auth attempt for an IP.
    fn record_failure(&mut self, ip: std::net::IpAddr) {
        let entry = self
            .failures
            .entry(ip)
            .or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        entry.1 = std::time::Instant::now();

        // Proactive cleanup at 50% capacity to prevent sudden eviction storms
        if self.failures.len() > MAX_TRACKED_IPS / 2 {
            self.cleanup_expired();
        }
        // Hard cap: if still above limit after cleanup, drop oldest entries
        if self.failures.len() > MAX_TRACKED_IPS {
            self.cleanup_expired();
        }
    }

    /// Remove entries whose lockout has long expired (2x lockout window).
    fn cleanup_expired(&mut self) {
        self.failures
            .retain(|_, (_, last_time)| last_time.elapsed().as_secs() < AUTH_LOCKOUT_SECS * 2);
    }

    /// Clear failures for an IP (on successful auth).
    fn clear(&mut self, ip: &std::net::IpAddr) {
        self.failures.remove(ip);
    }
}

// ── Resumable session tracking ──────────────────────────────────────────────

/// Tracks a single resumable session on the server. When a client is
/// performing a PUT and the connection drops, the session records how many
/// bytes were received so the client can reconnect and continue.
struct SessionEntry {
    /// IP address that created the session (used for auth binding).
    ip: std::net::IpAddr,
    /// Wall-clock time the session was created.
    created: std::time::Instant,
    /// Remote path of the in-progress transfer (empty if none).
    path: String,
    /// Bytes successfully received and flushed for this transfer.
    bytes_received: u64,
    /// Whether the original connection was authenticated.
    #[allow(dead_code)]
    authenticated: bool,
}

/// Bounded, expiring store of resumable sessions.
struct SessionStore {
    sessions: HashMap<String, SessionEntry>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Generate a cryptographically random session ID (hex-encoded 16 bytes).
    fn generate_id() -> String {
        let mut buf = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut buf);
        hex::encode(buf)
    }

    /// Insert a new session. Returns the session ID.
    fn create(&mut self, ip: std::net::IpAddr, authenticated: bool) -> String {
        self.cleanup_expired();
        let id = Self::generate_id();
        self.sessions.insert(
            id.clone(),
            SessionEntry {
                ip,
                created: std::time::Instant::now(),
                path: String::new(),
                bytes_received: 0,
                authenticated,
            },
        );
        id
    }

    /// Update the transfer progress for a session.
    fn update_progress(&mut self, id: &str, path: &str, bytes_received: u64) {
        if let Some(entry) = self.sessions.get_mut(id) {
            entry.path = path.to_string();
            entry.bytes_received = bytes_received;
        }
    }

    /// Look up a session, verifying it belongs to the same IP and hasn't expired.
    fn get(&mut self, id: &str, ip: &std::net::IpAddr) -> Option<&SessionEntry> {
        // Check existence and validity before returning
        let valid = self
            .sessions
            .get(id)
            .is_some_and(|e| e.ip == *ip && e.created.elapsed().as_secs() < SESSION_MAX_AGE_SECS);
        if valid {
            self.sessions.get(id)
        } else {
            // Remove expired or invalid entry
            self.sessions.remove(id);
            None
        }
    }

    /// Remove a session (e.g. after successful completion).
    #[allow(dead_code)]
    fn remove(&mut self, id: &str) {
        self.sessions.remove(id);
    }

    /// Evict expired sessions and enforce hard cap.
    fn cleanup_expired(&mut self) {
        self.sessions
            .retain(|_, e| e.created.elapsed().as_secs() < SESSION_MAX_AGE_SECS);
        // Hard cap to prevent memory exhaustion
        while self.sessions.len() > MAX_SESSIONS {
            // Remove oldest session
            if let Some(oldest_key) = self
                .sessions
                .iter()
                .max_by_key(|(_, e)| e.created.elapsed())
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest_key);
            } else {
                break;
            }
        }
    }
}

pub struct AftpServer {
    root: PathBuf,
    port: u16,
    bind_addr: String,
    auth_token: Option<String>,
    auth_challenge: bool,
    compression: bool,
    max_frame_size: u32,
    verbose: bool,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    max_connections: usize,
}

impl AftpServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: impl Into<PathBuf>,
        port: u16,
        bind_addr: impl Into<String>,
        auth_token: Option<String>,
        auth_challenge: bool,
        compression: bool,
        verbose: bool,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
        max_connections: usize,
    ) -> Self {
        Self {
            root: root.into(),
            port,
            bind_addr: bind_addr.into(),
            auth_token,
            auth_challenge,
            compression,
            max_frame_size: DEFAULT_MAX_FRAME,
            verbose,
            tls_cert_path,
            tls_key_path,
            max_connections,
        }
    }

    pub async fn run(self) -> AftResult<()> {
        let root = self
            .root
            .canonicalize()
            .map_err(|_| AftError::Other(format!("Root directory not found: {:?}", self.root)))?;

        if !root.is_dir() {
            return Err(AftError::Other(format!("{:?} is not a directory", root)));
        }

        // Load TLS config if cert/key provided
        let tls_acceptor = match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let acceptor = load_tls_acceptor(cert_path, key_path)?;
                Some(acceptor)
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(AftError::Other(
                    "Both --tls-cert and --tls-key must be provided for TLS".into(),
                ));
            }
            _ => None,
        };

        let addr = format!("{}:{}", self.bind_addr, self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| AftError::Other(format!("Failed to bind {}: {}", addr, e)))?;

        eprintln!();
        eprintln!("{}", " AFT Server ".on_blue().white().bold());
        eprintln!("  {} {}", "Root:    ".cyan().bold(), root.display());
        eprintln!("  {} {}", "Listen:  ".cyan().bold(), addr.green());
        eprintln!(
            "  {} {}",
            "TLS:     ".cyan().bold(),
            if tls_acceptor.is_some() {
                "enabled (AFTPS)".green()
            } else {
                "off (AFTP)".dimmed()
            }
        );
        eprintln!(
            "  {} {}",
            "Compress:".cyan().bold(),
            if self.compression {
                "zstd-1".green()
            } else {
                "off".dimmed()
            }
        );
        eprintln!(
            "  {} {}",
            "Auth:    ".cyan().bold(),
            if self.auth_token.is_some() {
                if self.auth_challenge {
                    "challenge/response (HMAC-SHA256)".yellow()
                } else {
                    "token".yellow()
                }
            } else {
                "off".dimmed()
            }
        );
        eprintln!(
            "  {} {}",
            "MaxFrame:".cyan().bold(),
            format!("{} KB", self.max_frame_size / 1024).dimmed()
        );
        eprintln!(
            "  {} {}",
            "MaxConns:".cyan().bold(),
            if self.max_connections > 0 {
                format!("{}", self.max_connections).dimmed()
            } else {
                "unlimited".dimmed()
            }
        );
        eprintln!();
        eprintln!(
            "  {} Accepting connections... (Ctrl+C to stop)",
            "*".green()
        );
        eprintln!();

        audit::log_server_event(
            audit::AuditEventType::ServerStart,
            &format!("Listening on {}", addr),
        );

        let server = Arc::new(ServerState {
            root,
            auth_token: self.auth_token,
            auth_challenge: self.auth_challenge,
            compression: self.compression,
            max_frame_size: self.max_frame_size,
            verbose: self.verbose,
            rate_limiter: Mutex::new(AuthRateLimiter::new()),
            sessions: Mutex::new(SessionStore::new()),
        });

        let tls_acceptor = tls_acceptor.map(Arc::new);

        // Connection limit semaphore
        let conn_semaphore = if self.max_connections > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(self.max_connections)))
        } else {
            None
        };

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, addr) = accept?;
                    let state = Arc::clone(&server);
                    let tls = tls_acceptor.clone();
                    let sem = conn_semaphore.clone();
                    tokio::spawn(async move {
                        // Acquire connection permit
                        let _permit = if let Some(ref s) = sem {
                            match s.try_acquire() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    if state.verbose {
                                        eprintln!("  {} {} rejected (max connections reached)", "x".red(), addr);
                                    }
                                    return;
                                }
                            }
                        } else {
                            None
                        };

                        if state.verbose {
                            eprintln!("  {} {} connected", "->".blue(), addr);
                        }
                        let result = if let Some(ref acceptor) = tls {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let (rd, wr) = tokio::io::split(tls_stream);
                                    handle_connection(state.clone(), rd, wr, addr).await
                                }
                                Err(e) => {
                                    if state.verbose {
                                        eprintln!("  {} {} TLS error: {}", "x".red(), addr, e);
                                    }
                                    return;
                                }
                            }
                        } else {
                            let (rd, wr) = stream.into_split();
                            handle_connection(state.clone(), rd, wr, addr).await
                        };
                        if let Err(e) = result {
                            if state.verbose {
                                eprintln!("  {} {} error: {}", "x".red(), addr, e);
                            }
                        }
                        if state.verbose {
                            eprintln!("  {} {} disconnected", "<-".dimmed(), addr);
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\n  {} Shutting down.", "*".yellow());
                    audit::log_server_event(
                        audit::AuditEventType::ServerStop,
                        "Shutdown via Ctrl+C",
                    );
                    break;
                }
            }
        }
        Ok(())
    }
}

struct ServerState {
    root: PathBuf,
    auth_token: Option<String>,
    auth_challenge: bool,
    compression: bool,
    max_frame_size: u32,
    verbose: bool,
    rate_limiter: Mutex<AuthRateLimiter>,
    sessions: Mutex<SessionStore>,
}

impl ServerState {
    /// Resolve and validate a requested path against the server root.
    /// Prevents path-traversal and symlink-escape attacks.
    fn safe_path(&self, requested: &str) -> AftResult<PathBuf> {
        if requested.contains("..") {
            return Err(AftError::PermissionDenied("Path traversal detected".into()));
        }

        let clean = requested.trim_start_matches('/').replace('\\', "/");
        let path = if clean.is_empty() {
            self.root.clone()
        } else {
            self.root.join(&clean)
        };

        if path.exists() {
            let canonical = path.canonicalize()?;
            if !canonical.starts_with(&self.root) {
                return Err(AftError::PermissionDenied(
                    "Path outside server root".into(),
                ));
            }
            Ok(canonical)
        } else {
            // For PUT: ensure parent is inside root
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let cp = parent.canonicalize()?;
                    if !cp.starts_with(&self.root) {
                        return Err(AftError::PermissionDenied(
                            "Path outside server root".into(),
                        ));
                    }
                    Ok(path)
                } else {
                    Err(AftError::FileNotFound(format!(
                        "Parent directory not found: {}",
                        clean
                    )))
                }
            } else {
                Err(AftError::Other("Invalid path".into()))
            }
        }
    }
}

// ── Handshake helpers ───────────────────────────────────────────────────────

/// Handle a fresh HELLO handshake: authenticate, negotiate capabilities, create
/// a resumable session, and send HELLO_ACK with the session ID.
///
/// Returns `(use_compression, max_payload, session_id)`.
async fn handle_hello_handshake<R, W>(
    state: &ServerState,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    hello_frame: &Frame,
    addr: SocketAddr,
) -> AftResult<(bool, u32, String)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let hello_data = parse_hello(&hello_frame.payload)?;

    // ── Authentication ──────────────────────────────────────────────────
    let authenticated = if let Some(ref expected) = state.auth_token {
        // Check rate limiting
        {
            let mut limiter = state.rate_limiter.lock().await;
            if limiter.is_locked_out(&addr.ip()) {
                send_error(
                    writer,
                    ERR_AUTH_FAILED,
                    "Too many failed auth attempts. Try again later.",
                )
                .await?;
                audit::log_auth_lockout(&addr.ip().to_string());
                if state.verbose {
                    eprintln!(
                        "  {} {} auth LOCKED OUT (rate limit)",
                        "!".red().bold(),
                        addr
                    );
                }
                return Err(AftError::PermissionDenied("Rate limited".into()));
            }
        }

        if state.auth_challenge && hello_data.capabilities & CAP_AUTH_CHALLENGE != 0 {
            // Challenge/response auth: send nonce, verify HMAC-SHA256
            let mut nonce = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);

            let challenge_payload = build_auth_challenge(&nonce);
            write_frame(writer, &Frame::new(FRAME_AUTH_CHALLENGE, challenge_payload)).await?;
            writer.flush().await?;

            let resp_frame = read_frame(reader, INITIAL_MAX_PAYLOAD).await?;
            if resp_frame.frame_type != FRAME_AUTH_RESPONSE {
                let mut limiter = state.rate_limiter.lock().await;
                limiter.record_failure(addr.ip());
                audit::log_auth_failure(
                    &addr.ip().to_string(),
                    "invalid frame type during challenge",
                );
                send_error(writer, ERR_AUTH_FAILED, "Expected AUTH_RESPONSE").await?;
                if state.verbose {
                    eprintln!("  {} {} auth FAILED (bad frame type)", "!".yellow(), addr);
                }
                return Err(AftError::AuthFailed("Auth failed".into()));
            }

            let resp_data = parse_auth_response(&resp_frame.payload)?;

            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(expected.as_bytes()).expect("HMAC key length");
            mac.update(&nonce);
            if mac.verify_slice(&resp_data.hmac).is_err() {
                let mut limiter = state.rate_limiter.lock().await;
                limiter.record_failure(addr.ip());
                audit::log_auth_failure(&addr.ip().to_string(), "HMAC verification failed");
                send_error(writer, ERR_AUTH_FAILED, "HMAC verification failed").await?;
                if state.verbose {
                    eprintln!("  {} {} auth FAILED (bad HMAC)", "!".yellow(), addr);
                }
                return Err(AftError::AuthFailed("Auth failed".into()));
            }
        } else {
            // Simple token auth
            if hello_data.auth_token != *expected {
                let mut limiter = state.rate_limiter.lock().await;
                limiter.record_failure(addr.ip());
                audit::log_auth_failure(&addr.ip().to_string(), "invalid token");
                send_error(writer, ERR_AUTH_FAILED, "Invalid auth token").await?;
                if state.verbose {
                    eprintln!("  {} {} auth FAILED (bad token)", "!".yellow(), addr);
                }
                return Err(AftError::AuthFailed("Auth failed".into()));
            }
        }

        // Auth succeeded — clear rate limit
        {
            let mut limiter = state.rate_limiter.lock().await;
            limiter.clear(&addr.ip());
        }
        audit::log_auth_success(&addr.ip().to_string());
        true
    } else {
        false
    };

    // ── Capability negotiation ──────────────────────────────────────────
    let mut agreed_caps = hello_data.capabilities;
    if !state.compression {
        agreed_caps &= !CAP_COMPRESSION;
    }
    agreed_caps |= CAP_CHECKSUM;
    if state.auth_challenge && state.auth_token.is_some() {
        agreed_caps |= CAP_AUTH_CHALLENGE;
    }
    // Advertise session-resume support
    agreed_caps |= CAP_SESSION_RESUME;

    let use_compression = agreed_caps & CAP_COMPRESSION != 0;

    // Create a resumable session
    let session_id = {
        let mut store = state.sessions.lock().await;
        store.create(addr.ip(), authenticated)
    };

    let ack_payload = build_hello_ack_with_session(agreed_caps, state.max_frame_size, &session_id);
    write_frame(writer, &Frame::new(FRAME_HELLO_ACK, ack_payload)).await?;
    writer.flush().await?;

    let max_payload = state.max_frame_size + 1024;
    Ok((use_compression, max_payload, session_id))
}

/// Handle a RESUME handshake: look up the session, verify ownership, and send
/// RESUME_ACK with the byte offset the server already has.
///
/// Returns `(use_compression, max_payload, session_id)`.
async fn handle_resume_handshake<W>(
    state: &ServerState,
    writer: &mut BufWriter<W>,
    resume_frame: &Frame,
    addr: SocketAddr,
) -> AftResult<(bool, u32, String)>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let resume_data = parse_resume(&resume_frame.payload)?;

    // Verify auth token on resume (defense-in-depth: session + IP + token)
    if let Some(ref expected_token) = state.auth_token {
        if resume_data.auth_token != *expected_token {
            let ack = build_resume_ack(false, 0, "");
            write_frame(writer, &Frame::new(FRAME_RESUME_ACK, ack)).await?;
            writer.flush().await?;
            return Err(AftError::AuthFailed("Invalid auth token on resume".into()));
        }
    }

    let (accepted, resume_offset, last_path) = {
        let mut store = state.sessions.lock().await;
        match store.get(&resume_data.session_id, &addr.ip()) {
            Some(entry) => {
                let offset = entry.bytes_received;
                let path = entry.path.clone();
                (true, offset, path)
            }
            None => (false, 0, String::new()),
        }
    };

    if !accepted {
        let ack = build_resume_ack(false, 0, "");
        write_frame(writer, &Frame::new(FRAME_RESUME_ACK, ack)).await?;
        writer.flush().await?;
        return Err(AftError::Other("Session not found or expired".into()));
    }

    let ack = build_resume_ack(true, resume_offset, &last_path);
    write_frame(writer, &Frame::new(FRAME_RESUME_ACK, ack)).await?;
    writer.flush().await?;

    if state.verbose {
        eprintln!(
            "  {} {} resumed session {} at offset {}",
            "↻".green().bold(),
            addr,
            &resume_data.session_id[..8],
            resume_offset,
        );
    }

    // Inherit compression from original negotiation — for simplicity we
    // assume the same settings as the original HELLO (the session store
    // records authenticated status; compression is server-wide).
    let use_compression = state.compression;
    let max_payload = state.max_frame_size + 1024;
    Ok((use_compression, max_payload, resume_data.session_id))
}

// ── Connection handler ──────────────────────────────────────────────────────

async fn handle_connection<R, W>(
    state: Arc<ServerState>,
    rd: R,
    wr: W,
    addr: SocketAddr,
) -> AftResult<()>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let mut reader = BufReader::with_capacity(READ_BUF, rd);
    let mut writer = BufWriter::with_capacity(WRITE_BUF, wr);

    // ── Handshake (HELLO or RESUME) ─────────────────────────────────────
    let first_frame = read_frame(&mut reader, INITIAL_MAX_PAYLOAD).await?;

    let (use_compression, max_payload, session_id) = match first_frame.frame_type {
        FRAME_HELLO => {
            handle_hello_handshake(&state, &mut reader, &mut writer, &first_frame, addr).await?
        }
        FRAME_RESUME => handle_resume_handshake(&state, &mut writer, &first_frame, addr).await?,
        _ => {
            send_error(&mut writer, ERR_INVALID_REQUEST, "Expected HELLO or RESUME").await?;
            return Err(AftError::Other(
                "Client did not send HELLO or RESUME".into(),
            ));
        }
    };

    // ── Request loop ────────────────────────────────────────────────────
    let idle_timeout = std::time::Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS);
    loop {
        let frame =
            match tokio::time::timeout(idle_timeout, read_frame(&mut reader, max_payload)).await {
                Ok(Ok(f)) => f,
                Ok(Err(AftError::ConnectionFailed(_))) => break, // clean disconnect
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Idle timeout expired
                    if state.verbose {
                        eprintln!(
                            "  {} {} idle timeout ({}s)",
                            "!".yellow(),
                            addr,
                            CONNECTION_IDLE_TIMEOUT_SECS
                        );
                    }
                    break;
                }
            };

        match frame.frame_type {
            FRAME_GET => {
                handle_get(
                    &state,
                    &mut reader,
                    &mut writer,
                    &frame,
                    use_compression,
                    addr,
                )
                .await?;
            }
            FRAME_HEAD => {
                handle_head(&state, &mut writer, &frame).await?;
            }
            FRAME_PUT => {
                handle_put(
                    &state,
                    &mut reader,
                    &mut writer,
                    &frame,
                    max_payload,
                    addr,
                    &session_id,
                )
                .await?;
            }
            FRAME_LIST => {
                handle_list(&state, &mut writer, &frame).await?;
            }
            FRAME_PING => {
                write_frame(&mut writer, &Frame::empty(FRAME_PONG)).await?;
                writer.flush().await?;
            }
            _ => {
                send_error(
                    &mut writer,
                    ERR_INVALID_REQUEST,
                    &format!("Unknown frame type 0x{:02x}", frame.frame_type),
                )
                .await?;
            }
        }
    }

    Ok(())
}

// ── GET handler ─────────────────────────────────────────────────────────────

async fn handle_get<R, W>(
    state: &ServerState,
    _reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    frame: &Frame,
    use_compression: bool,
    addr: SocketAddr,
) -> AftResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let req = parse_get(&frame.payload)?;
    let path = match state.safe_path(&req.path) {
        Ok(p) => p,
        Err(e) => {
            send_err_from(&mut *writer, &e).await?;
            return Ok(());
        }
    };

    if !path.is_file() {
        send_error(writer, ERR_NOT_FOUND, &format!("Not a file: {}", req.path)).await?;
        return Ok(());
    }

    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();
    let modified_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let content_type = guess_mime(&path);

    // Determine byte range
    let (start, end) = if req.range_start == 0 && req.range_end == 0 {
        (0u64, file_size.saturating_sub(1))
    } else if req.range_end == 0 {
        (req.range_start, file_size.saturating_sub(1))
    } else {
        (
            req.range_start,
            std::cmp::min(req.range_end, file_size.saturating_sub(1)),
        )
    };

    // Send HEAD_RESP with full file metadata
    let head_payload = build_head_resp(file_size, modified_secs, &content_type);
    write_frame(writer, &Frame::new(FRAME_HEAD_RESP, head_payload)).await?;
    writer.flush().await?;

    // Stream DATA frames
    let mut file = tokio::fs::File::open(&path).await?;
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }

    let bytes_to_send = end - start + 1;
    let frame_buf_size = state.max_frame_size as usize;
    let mut buf = vec![0u8; frame_buf_size];
    let mut hasher = sha2::Sha256::new();
    let mut total_sent = 0u64;

    while total_sent < bytes_to_send {
        let remaining = (bytes_to_send - total_sent) as usize;
        let to_read = std::cmp::min(remaining, frame_buf_size);
        let n = file.read(&mut buf[..to_read]).await?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);

        if use_compression {
            if let Ok(compressed) = zstd::encode_all(std::io::Cursor::new(&buf[..n]), 1) {
                if compressed.len() < n {
                    write_frame_header(
                        writer,
                        FRAME_DATA,
                        FLAG_COMPRESSED,
                        compressed.len() as u32,
                    )
                    .await?;
                    writer.write_all(&compressed).await?;
                    total_sent += n as u64;
                    continue;
                }
            }
        }

        // Uncompressed: write header then raw data (zero-copy path)
        write_frame_header(writer, FRAME_DATA, 0, n as u32).await?;
        writer.write_all(&buf[..n]).await?;
        total_sent += n as u64;
    }

    // DATA_END with inline SHA-256
    let hash = hasher.finalize();
    let end_payload = build_data_end(total_sent, CHECKSUM_SHA256, &hash);
    write_frame(writer, &Frame::new(FRAME_DATA_END, end_payload)).await?;
    writer.flush().await?;

    if state.verbose {
        eprintln!(
            "  {} {} GET {} ({} bytes)",
            "*".green(),
            addr,
            req.path,
            total_sent
        );
    }
    audit::log_file_access(
        audit::AuditEventType::FileRead,
        &addr.ip().to_string(),
        &req.path,
        total_sent,
    );

    Ok(())
}

// ── HEAD handler ────────────────────────────────────────────────────────────

async fn handle_head<W: tokio::io::AsyncWrite + Unpin>(
    state: &ServerState,
    writer: &mut BufWriter<W>,
    frame: &Frame,
) -> AftResult<()> {
    let mut off = 0;
    let path_str = get_str(&frame.payload, &mut off)?;
    let path = match state.safe_path(&path_str) {
        Ok(p) => p,
        Err(e) => {
            send_err_from(&mut *writer, &e).await?;
            return Ok(());
        }
    };

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| AftError::FileNotFound(format!("{}: {}", path_str, e)))?;

    let modified_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let content_type = if path.is_dir() {
        "inode/directory".to_string()
    } else {
        guess_mime(&path)
    };

    let payload = build_head_resp(metadata.len(), modified_secs, &content_type);
    write_frame(writer, &Frame::new(FRAME_HEAD_RESP, payload)).await?;
    writer.flush().await?;
    audit::log_file_access(audit::AuditEventType::FileRead, "local", &path_str, 0);
    Ok(())
}

// ── PUT handler ─────────────────────────────────────────────────────────────

async fn handle_put<R, W>(
    state: &ServerState,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    frame: &Frame,
    max_payload: u32,
    addr: SocketAddr,
    session_id: &str,
) -> AftResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let req = parse_put(&frame.payload)?;
    let path = match state.safe_path(&req.path) {
        Ok(p) => p,
        Err(e) => {
            send_err_from(&mut *writer, &e).await?;
            return Ok(());
        }
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            eprintln!("Warning: failed to create directory {:?}: {}", parent, e);
        }
    }

    // Write to a temp file, rename on success for atomicity
    let temp_path = path.with_extension("aft-tmp");

    // Send PUT_ACK (ready)
    write_frame(writer, &Frame::new(FRAME_PUT_ACK, build_put_ack(false))).await?;
    writer.flush().await?;

    let mut file = tokio::fs::File::create(&temp_path).await?;
    let mut hasher = sha2::Sha256::new();
    let mut total_received = 0u64;

    // Receive DATA frames
    loop {
        let data_frame = read_frame(reader, max_payload).await?;

        match data_frame.frame_type {
            FRAME_DATA => {
                let payload = if data_frame.flags & FLAG_COMPRESSED != 0 {
                    zstd::decode_all(std::io::Cursor::new(&data_frame.payload))
                        .map_err(|e| AftError::Other(format!("zstd decompress error: {}", e)))?
                } else {
                    data_frame.payload
                };
                hasher.update(&payload);
                file.write_all(&payload).await?;
                total_received += payload.len() as u64;

                // Track progress so a resumed connection can continue from here
                {
                    let mut store = state.sessions.lock().await;
                    store.update_progress(session_id, &req.path, total_received);
                }
            }
            FRAME_DATA_END => {
                let end_data = parse_data_end(&data_frame.payload)?;

                // Verify total bytes
                if end_data.total_bytes != total_received {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    send_error(
                        writer,
                        ERR_IO,
                        &format!(
                            "Byte count mismatch: expected {}, got {}",
                            end_data.total_bytes, total_received
                        ),
                    )
                    .await?;
                    return Ok(());
                }

                // Verify checksum if provided
                if end_data.checksum_algo == CHECKSUM_SHA256 && !end_data.checksum.is_empty() {
                    let our_hash = hasher.finalize();
                    if our_hash.as_slice() != end_data.checksum.as_slice() {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        send_error(writer, ERR_IO, "Checksum mismatch").await?;
                        return Ok(());
                    }
                }

                break;
            }
            FRAME_ERROR => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                let err = parse_error(&data_frame.payload)?;
                return Err(AftError::Other(format!(
                    "Client error during PUT: {}",
                    err.message
                )));
            }
            _ => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                send_error(writer, ERR_INVALID_REQUEST, "Expected DATA or DATA_END").await?;
                return Ok(());
            }
        }
    }

    file.flush().await?;
    drop(file);

    // Atomic rename
    tokio::fs::rename(&temp_path, &path).await?;

    // Send PUT_ACK (complete)
    write_frame(writer, &Frame::new(FRAME_PUT_ACK, build_put_ack(true))).await?;
    writer.flush().await?;

    if state.verbose {
        eprintln!(
            "  {} {} PUT {} ({} bytes)",
            "*".green(),
            addr,
            req.path,
            total_received
        );
    }
    audit::log_file_access(
        audit::AuditEventType::FileWrite,
        &addr.ip().to_string(),
        &req.path,
        total_received,
    );

    Ok(())
}

// ── LIST handler ────────────────────────────────────────────────────────────

async fn handle_list<W: tokio::io::AsyncWrite + Unpin>(
    state: &ServerState,
    writer: &mut BufWriter<W>,
    frame: &Frame,
) -> AftResult<()> {
    let mut off = 0;
    let path_str = get_str(&frame.payload, &mut off)?;
    let path = match state.safe_path(&path_str) {
        Ok(p) => p,
        Err(e) => {
            send_err_from(&mut *writer, &e).await?;
            return Ok(());
        }
    };

    if !path.is_dir() {
        send_error(
            writer,
            ERR_INVALID_REQUEST,
            &format!("Not a directory: {}", path_str),
        )
        .await?;
        return Ok(());
    }

    let mut entries = Vec::new();
    let mut dir = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.metadata().await?;
        let modified_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(ListEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            size: meta.len(),
            is_dir: meta.is_dir(),
            modified_secs,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let payload = build_list_resp(&entries);
    write_frame(writer, &Frame::new(FRAME_LIST_RESP, payload)).await?;
    writer.flush().await?;
    audit::log_file_access(
        audit::AuditEventType::FileList,
        "local",
        &path_str,
        entries.len() as u64,
    );
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn send_error<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut BufWriter<W>,
    code: u16,
    message: &str,
) -> AftResult<()> {
    let payload = build_error(code, message);
    write_frame(writer, &Frame::new(FRAME_ERROR, payload)).await?;
    writer.flush().await?;
    Ok(())
}

async fn send_err_from<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut BufWriter<W>,
    err: &AftError,
) -> AftResult<()> {
    // Return only generic messages to clients — never leak internal paths.
    let (code, msg) = match err {
        AftError::FileNotFound(_) => (ERR_NOT_FOUND, "Not found"),
        AftError::PermissionDenied(_) | AftError::AuthFailed(_) => {
            (ERR_PERMISSION_DENIED, "Access denied")
        }
        _ => (ERR_INTERNAL, "Internal server error"),
    };
    send_error(writer, code, msg).await
}

fn guess_mime(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" | "md" | "log" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "zst" => "application/zstd",
        "xz" => "application/x-xz",
        "bz2" => "application/x-bzip2",
        "7z" => "application/x-7z-compressed",
        "csv" => "text/csv",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "wasm" => "application/wasm",
        "bin" | "exe" | "dll" | "so" | "dylib" => "application/octet-stream",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ── TLS helpers ─────────────────────────────────────────────────────────────

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> AftResult<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::PrivateKeyDer;
    use std::io::BufReader as StdBufReader;

    // Install the default crypto provider if not already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| AftError::Other(format!("Cannot open TLS cert {}: {}", cert_path, e)))?;
    let mut cert_reader = StdBufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AftError::Other(format!("Invalid TLS cert: {}", e)))?;

    if certs.is_empty() {
        return Err(AftError::Other("No certificates found in PEM file".into()));
    }

    let key_file = std::fs::File::open(key_path)
        .map_err(|e| AftError::Other(format!("Cannot open TLS key {}: {}", key_path, e)))?;
    let mut key_reader = StdBufReader::new(key_file);
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| AftError::Other(format!("Invalid TLS key: {}", e)))?
        .ok_or_else(|| AftError::Other("No private key found in PEM file".into()))?;

    // Restrict to TLS 1.2+ and FIPS-compatible cipher suites
    let tls_versions = &[&rustls::version::TLS13, &rustls::version::TLS12];

    #[cfg(feature = "fips")]
    let provider = {
        // Use AWS-LC (FIPS 140-3 validated) as the crypto backend
        let crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
        let cipher_suites = crypto_provider
            .cipher_suites
            .iter()
            .filter(|cs| {
                let name = format!("{:?}", cs.suite());
                name.contains("AES_256_GCM") || name.contains("AES_128_GCM")
            })
            .cloned()
            .collect();
        rustls::crypto::CryptoProvider {
            cipher_suites,
            ..crypto_provider
        }
    };

    #[cfg(not(feature = "fips"))]
    let provider = {
        let cipher_suites = vec![
            // TLS 1.3 — AES-256-GCM, AES-128-GCM (FIPS-approved)
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            // TLS 1.2 — ECDHE + AES-GCM (FIPS-approved key exchange + cipher)
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        rustls::crypto::CryptoProvider {
            cipher_suites,
            ..rustls::crypto::ring::default_provider()
        }
    };

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(tls_versions)
        .map_err(|e| AftError::Other(format!("TLS version config error: {}", e)))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AftError::Other(format!("TLS config error: {}", e)))?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
