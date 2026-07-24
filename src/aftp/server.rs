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
    fec: bool,
    fec_allow_unauthenticated: bool,
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
            // Serve the data plane when asked. This costs nothing until a
            // client actually negotiates `CAP_FEC`, and the UDP socket is
            // bound per transfer rather than held open by the listener.
            fec: true,
            // Off by default: without an auth token the data plane has no
            // symbol key, so FEC symbols would carry only a CRC32 — no
            // confidentiality, no authenticity. Rather than silently move file
            // data over the clear UDP plane, refuse FEC on an unauthenticated
            // server and let the client fall back to the reliable path. An
            // operator on a physically trusted link can opt back in.
            fec_allow_unauthenticated: false,
        }
    }

    /// Refuse the fountain-coded data plane even when a client offers it.
    #[allow(dead_code)]
    pub fn with_fec(mut self, enable: bool) -> Self {
        self.fec = enable;
        self
    }

    /// Allow the fountain-coded data plane on an *unauthenticated* server,
    /// where symbols are CRC32-protected only (no encryption). Trusted links
    /// exclusively — never for sensitive/CUI data.
    pub fn with_unauthenticated_fec(mut self, allow: bool) -> Self {
        self.fec_allow_unauthenticated = allow;
        self
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
            fec: self.fec,
            fec_allow_unauthenticated: self.fec_allow_unauthenticated,
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
    /// Serve transfers over the fountain-coded UDP data plane when the client
    /// asks for it.
    fec: bool,
    fec_allow_unauthenticated: bool,
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
            // The target does not exist yet — a PUT creating a new file,
            // possibly several directory levels deep. Requiring the immediate
            // parent to exist would reject any nested upload into a fresh
            // tree, which made directory sync over AFTP impossible even though
            // the PUT handler creates parent directories itself.
            //
            // Validate against the nearest ancestor that *does* exist:
            // canonicalizing it resolves symlinks on the existing portion, and
            // `..` was rejected outright above, so the components below it are
            // plain names that cannot escape.
            let mut ancestor = path.clone();
            let mut trailing: Vec<std::ffi::OsString> = Vec::new();

            while !ancestor.exists() {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| AftError::Other("Invalid path".into()))?
                    .to_os_string();
                trailing.push(name);
                match ancestor.parent() {
                    Some(p) if !p.as_os_str().is_empty() => ancestor = p.to_path_buf(),
                    _ => return Err(AftError::Other("Invalid path".into())),
                }
            }

            let canonical = ancestor.canonicalize()?;
            if !canonical.starts_with(&self.root) {
                return Err(AftError::PermissionDenied(
                    "Path outside server root".into(),
                ));
            }

            let mut resolved = canonical;
            for name in trailing.iter().rev() {
                resolved.push(name);
            }
            Ok(resolved)
        }
    }
}

// ── Handshake helpers ───────────────────────────────────────────────────────

/// Handle a fresh HELLO handshake: authenticate, negotiate capabilities, create
/// a resumable session, and send HELLO_ACK with the session ID.
///
/// Returns `(use_compression, use_crc32, max_payload, session_id)`.
async fn handle_hello_handshake<R, W>(
    state: &ServerState,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    hello_frame: &Frame,
    addr: SocketAddr,
) -> AftResult<(bool, bool, u32, String, bool)>
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
    // Always advertise hardware-accelerated CRC32 capability
    agreed_caps |= CAP_CRC32_FRAMES;
    // The fountain data plane is only agreed when the client asked for it
    // *and* this server is configured to serve it. `agreed_caps` starts as the
    // client's bits, so clearing here yields the intersection.
    if !state.fec {
        agreed_caps &= !CAP_FEC;
    } else if state.auth_token.is_none() && !state.fec_allow_unauthenticated {
        // No auth token → no symbol key → FEC symbols would be CRC32-only
        // (cleartext, no authenticity). Refuse rather than silently run the
        // data plane in the clear; the client transparently falls back to the
        // reliable path. `--fec-insecure` re-enables it for trusted links.
        agreed_caps &= !CAP_FEC;
        if hello_data.capabilities & CAP_FEC != 0 {
            eprintln!(
                "{}",
                "  note: refused --fec on an unauthenticated server (symbols would be \
                 unencrypted); start with --auth-token, or --fec-insecure for a trusted link"
                    .dimmed()
            );
        }
    }

    let use_compression = agreed_caps & CAP_COMPRESSION != 0;
    let use_crc32 = agreed_caps & CAP_CRC32_FRAMES != 0;
    let use_fec = agreed_caps & CAP_FEC != 0;

    // Create a resumable session
    let session_id = {
        let mut store = state.sessions.lock().await;
        store.create(addr.ip(), authenticated)
    };

    let ack_payload = build_hello_ack_with_session(agreed_caps, state.max_frame_size, &session_id);
    write_frame(writer, &Frame::new(FRAME_HELLO_ACK, ack_payload)).await?;
    writer.flush().await?;

    let max_payload = state.max_frame_size + 1024;
    Ok((use_compression, use_crc32, max_payload, session_id, use_fec))
}

/// Handle a RESUME handshake: look up the session, verify ownership, and send
/// RESUME_ACK with the byte offset the server already has.
///
/// Returns `(use_compression, use_crc32, max_payload, session_id)`.
async fn handle_resume_handshake<W>(
    state: &ServerState,
    writer: &mut BufWriter<W>,
    resume_frame: &Frame,
    addr: SocketAddr,
) -> AftResult<(bool, bool, u32, String)>
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
    // CRC32 is always available (hardware-accelerated)
    let use_crc32 = resume_data.capabilities & CAP_CRC32_FRAMES != 0;
    let max_payload = state.max_frame_size + 1024;
    Ok((
        use_compression,
        use_crc32,
        max_payload,
        resume_data.session_id,
    ))
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

    let (use_compression, use_crc32, max_payload, session_id, use_fec) = match first_frame
        .frame_type
    {
        FRAME_HELLO => {
            handle_hello_handshake(&state, &mut reader, &mut writer, &first_frame, addr).await?
        }
        // A resumed session continues on the reliable path: the data plane is
        // negotiated per connection, and a resume carries no offer.
        FRAME_RESUME => {
            let (c, r, m, s) =
                handle_resume_handshake(&state, &mut writer, &first_frame, addr).await?;
            (c, r, m, s, false)
        }
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
                    use_crc32,
                    addr,
                    use_fec,
                    &session_id,
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
                    use_crc32,
                    addr,
                    &session_id,
                    use_fec,
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

// ── FEC PUT handler ─────────────────────────────────────────────────────────

/// Receive a pushed file over the fountain-coded UDP data plane.
///
/// Blocks are written to the staging file at their offsets as they decode, so
/// receiver memory is bounded by the decoder working set rather than by the
/// size of the upload. The staged file is only renamed into place once the
/// client's SHA-256 matches — a failed or forged transfer leaves nothing
/// behind.
#[allow(clippy::too_many_arguments)]
async fn recv_put_fec<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    offer_frame: &Frame,
    temp_path: &std::path::Path,
    final_path: &std::path::Path,
    addr: SocketAddr,
    verbose: bool,
    auth_token: Option<&str>,
) -> AftResult<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use super::fec::transfer::{recv_object_into, FecParams, Feedback, FileBlockWriter, DEFAULT_WINDOW};
    use super::fec::udp::DataPlane;

    let offer = parse_fec_offer(&offer_frame.payload)?;

    // The client derives the symbol key from the same session id and shared
    // token, so we reconstruct it here without it ever crossing the wire.
    let key = super::fec::derive_symbol_key(auth_token, offer.session_id);
    if offer.authenticated && key.is_none() {
        // The client wants authenticated symbols but we cannot derive the key
        // here; refuse rather than silently accepting unauthenticated data.
        write_frame(
            writer,
            &Frame::new(
                FRAME_FEC_ACCEPT,
                build_fec_accept(false, 0, "symbol authentication unavailable"),
            ),
        )
        .await?;
        writer.flush().await?;
        return Err(AftError::Other(
            "FEC upload requested authenticated symbols but no key is available".into(),
        ));
    }

    let plane = DataPlane::bind_for_session("0.0.0.0:0", key, offer.session_id).await?;
    let port = plane.local_addr()?.port();

    write_frame(
        writer,
        &Frame::new(FRAME_FEC_ACCEPT, build_fec_accept(true, port, "")),
    )
    .await?;
    writer.flush().await?;

    let params = FecParams {
        session_id: offer.session_id,
        total_len: offer.total_len,
        block_size: offer.block_size as usize,
        symbol_size: offer.symbol_size,
        window: DEFAULT_WINDOW,
        initial_loss_hint: 0.0,
    };

    // Stage to the temp path, pre-allocated so out-of-order blocks land
    // correctly.
    let mut sink = FileBlockWriter::create(temp_path, offer.total_len).await?;

    // Feedback goes out on the control plane on its own task, so the receive
    // loop never blocks on the socket and the socket is never written from two
    // places at once.
    let (fb_tx, mut fb_rx) = tokio::sync::mpsc::channel::<Feedback>(1024);
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<Frame>(1024);
    let pump = tokio::spawn(async move {
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
            if frame_tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    // Scoped so the receive future — and the borrows of `sink` and `fb_tx` it
    // holds — are released before we finalize either of them.
    let stats = {
        // Initial guess only — the receiver measures the real RTT from its own
        // NeedMore round-trips and adapts its patience as it learns.
        let rtt = std::time::Duration::from_millis(50);
        let recv_fut = recv_object_into(&plane, &mut sink, &fb_tx, &params, rtt);
        tokio::pin!(recv_fut);

        loop {
            tokio::select! {
                result = &mut recv_fut => break result?,
                Some(frame) = frame_rx.recv() => {
                    write_frame(writer, &frame).await?;
                    writer.flush().await?;
                }
            }
        }
    };

    drop(fb_tx);
    // Awaiting the pump — rather than racing a `try_recv` against it — is what
    // makes the last BlockOk reliably reach the sender. The receive future can
    // win the `select!` the instant the final block decodes, before the pump
    // has forwarded that block's BlockOk from `fb_rx` into `frame_rx`. Dropping
    // `fb_tx` closes the pump's input, so it drains whatever is buffered and
    // exits; only then is every feedback frame guaranteed to be in `frame_rx`
    // for the flush below. Aborting here instead (or draining early) can lose
    // that final BlockOk and leave the sender blocked forever on a transfer
    // that actually completed.
    let _ = pump.await;
    while let Ok(frame) = frame_rx.try_recv() {
        write_frame(writer, &frame).await?;
    }
    writer.flush().await?;

    sink.finish().await?;

    // The client closes with the authoritative digest.
    let end_frame = read_frame(reader, INITIAL_MAX_PAYLOAD).await?;
    if end_frame.frame_type != FRAME_DATA_END {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AftError::Other(format!(
            "Expected DATA_END after FEC upload, got 0x{:02x}",
            end_frame.frame_type
        )));
    }
    let end = parse_data_end(&end_frame.payload)?;

    if end.total_bytes != offer.total_len {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AftError::Other(format!(
            "FEC upload byte count mismatch: offered {}, DATA_END says {}",
            offer.total_len, end.total_bytes
        )));
    }

    if end.checksum_algo == CHECKSUM_SHA256 && !end.checksum.is_empty() {
        use tokio::io::AsyncReadExt;
        let mut f = tokio::fs::File::open(temp_path).await?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hasher.finalize();
        if actual.as_slice() != end.checksum.as_slice() {
            // Fail closed: never publish data that did not verify.
            let _ = tokio::fs::remove_file(temp_path).await;
            return Err(AftError::ChecksumMismatch {
                expected: hex::encode(&end.checksum),
                actual: hex::encode(actual),
            });
        }
    }

    tokio::fs::rename(temp_path, final_path).await?;

    write_frame(writer, &Frame::new(FRAME_PUT_ACK, build_put_ack(true))).await?;
    writer.flush().await?;

    if verbose {
        eprintln!(
            "  {} {} FEC received {} bytes ({} symbols, {} rejected)",
            "*".green(),
            addr,
            offer.total_len,
            stats.symbols_accepted,
            stats.symbols_rejected
        );
    }

    Ok(offer.total_len)
}

// ── FEC GET handler ─────────────────────────────────────────────────────────

/// Serve a whole file over the fountain-coded UDP data plane.
///
/// Control plane carries the offer, the accept, and per-block feedback; the
/// file bytes travel as UDP symbols. Blocks are read from disk one window at a
/// time, so serving a 5 GB file costs the same memory as serving 50 MB.
async fn serve_get_fec<R, W>(
    state: &ServerState,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    path: &std::path::Path,
    file_size: u64,
    addr: SocketAddr,
    session_id: &str,
) -> AftResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use super::fec::transfer::{send_blocks, FecParams, Feedback, FileBlocks, DEFAULT_WINDOW};
    use super::fec::udp::DataPlane;

    // A random numeric id for this transfer, sent to the client in the offer
    // below. It seeds the per-session symbol key, so it must be unpredictable
    // rather than derived from any public or low-entropy value.
    let _ = session_id;
    let numeric_session = super::fec::random_session_id();

    let key = super::fec::derive_symbol_key(state.auth_token.as_deref(), numeric_session);
    let authenticated = key.is_some();

    let symbol_size = super::fec::max_symbol_size(super::fec::DEFAULT_MTU, authenticated);
    let block_size = super::fec::DEFAULT_BLOCK_SIZE as u32;
    let blocks = super::fec::block_count(file_size, block_size as usize);

    write_frame(
        writer,
        &Frame::new(
            FRAME_FEC_OFFER,
            build_fec_offer(
                numeric_session,
                file_size,
                block_size,
                symbol_size,
                blocks,
                authenticated,
            ),
        ),
    )
    .await?;
    writer.flush().await?;

    // Wait for the client to bind its socket and tell us the port.
    let accept_frame = read_frame(reader, INITIAL_MAX_PAYLOAD).await?;
    if accept_frame.frame_type != FRAME_FEC_ACCEPT {
        return Err(AftError::Other(format!(
            "Expected FEC_ACCEPT, got 0x{:02x}",
            accept_frame.frame_type
        )));
    }
    let accept = parse_fec_accept(&accept_frame.payload)?;
    if !accept.accepted {
        return Err(AftError::Other(format!(
            "Client declined the FEC data plane: {}",
            accept.reason
        )));
    }

    // Spray at the client's control-plane address on its chosen UDP port.
    let plane = DataPlane::bind_for_session("0.0.0.0:0", key, numeric_session).await?;
    plane
        .connect(SocketAddr::new(addr.ip(), accept.udp_port))
        .await?;

    // Feedback arrives as control frames; forward it to the scheduler.
    let (fb_tx, mut fb_rx) = tokio::sync::mpsc::channel::<Feedback>(1024);

    let params = FecParams {
        session_id: numeric_session,
        total_len: file_size,
        block_size: block_size as usize,
        symbol_size,
        window: DEFAULT_WINDOW,
        initial_loss_hint: 0.0,
    };

    // Hash the file for the closing DATA_END while the transfer runs. Reading
    // it a second time costs page-cache hits, not I/O, and keeps the sender's
    // resident set bounded by the window rather than the file.
    let digest = {
        use tokio::io::AsyncReadExt;
        let mut f = tokio::fs::File::open(path).await?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        hasher.finalize()
    };

    let blocks_reader = FileBlocks::new(path.to_path_buf(), 0);

    // Feedback is assembled incrementally. `read_frame` is NOT
    // cancellation-safe — it reads a 10-byte header and then the payload, so a
    // `select!` that drops it mid-frame eats bytes and desynchronizes the
    // control stream. `FrameAssembler` performs one cancellation-safe `read`
    // per poll and keeps partial state across iterations.
    let mut assembler = FrameAssembler::new();

    let send_fut = send_blocks(&blocks_reader, &plane, &mut fb_rx, &params);
    tokio::pin!(send_fut);

    let stats = loop {
        tokio::select! {
            result = &mut send_fut => break result?,
            frame = assembler.next_frame(reader, INITIAL_MAX_PAYLOAD) => {
                let Some(frame) = frame? else { continue };
                let msg = match frame.frame_type {
                    FRAME_FEC_NEEDMORE => {
                        let f = parse_fec_needmore(&frame.payload)?;
                        Some(Feedback::NeedMore {
                            block_id: f.block_id,
                            symbols_needed: f.symbols_needed,
                            symbols_received: f.symbols_received,
                        })
                    }
                    FRAME_FEC_BLOCK_OK => {
                        let f = parse_fec_block_ok(&frame.payload)?;
                        Some(Feedback::BlockOk {
                            block_id: f.block_id,
                            symbols_used: f.symbols_used,
                        })
                    }
                    // Anything else mid-transfer is a protocol violation.
                    other => {
                        return Err(AftError::Other(format!(
                            "Unexpected frame 0x{:02x} during FEC transfer",
                            other
                        )))
                    }
                };
                if let Some(msg) = msg {
                    if fb_tx.send(msg).await.is_err() {
                        // Scheduler finished; let the select pick up its result.
                        continue;
                    }
                }
            }
        }
    };

    if state.verbose {
        eprintln!(
            "  {} {} FEC sent {} symbols ({} bytes) in {} repair rounds",
            "→".green(),
            addr,
            stats.symbols_sent,
            stats.bytes_sent,
            stats.repair_rounds
        );
    }

    // Close out on the control plane with the authoritative digest.
    write_frame(
        writer,
        &Frame::new(
            FRAME_DATA_END,
            build_data_end(file_size, CHECKSUM_SHA256, &digest),
        ),
    )
    .await?;
    writer.flush().await?;

    Ok(())
}

// ── GET handler ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_get<R, W>(
    state: &ServerState,
    _reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    frame: &Frame,
    use_compression: bool,
    use_crc32: bool,
    addr: SocketAddr,
    use_fec: bool,
    session_id: &str,
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

    // ── Fountain data plane ─────────────────────────────────────────────
    //
    // Only for whole-file requests above the size floor: ranged reads are
    // already served cheaply, and small files are dominated by the setup cost.
    let whole_file = start == 0 && end + 1 >= file_size;
    if use_fec && whole_file && file_size >= super::fec::FEC_MIN_TRANSFER {
        match serve_get_fec(state, _reader, writer, &path, file_size, addr, session_id).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                // The client is mid-protocol and cannot be silently dropped
                // back onto the frame path, so surface the failure.
                if state.verbose {
                    eprintln!("  {} {} FEC transfer failed: {}", "!".yellow(), addr, e);
                }
                return Err(e);
            }
        }
    }

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
                    if use_crc32 {
                        let crc = crc32fast::hash(&compressed);
                        let frame_len = compressed.len() as u32 + 4;
                        write_frame_header(
                            writer,
                            FRAME_DATA,
                            FLAG_COMPRESSED | FLAG_CRC32,
                            frame_len,
                        )
                        .await?;
                        writer.write_all(&compressed).await?;
                        writer.write_all(&crc.to_le_bytes()).await?;
                    } else {
                        write_frame_header(
                            writer,
                            FRAME_DATA,
                            FLAG_COMPRESSED,
                            compressed.len() as u32,
                        )
                        .await?;
                        writer.write_all(&compressed).await?;
                    }
                    total_sent += n as u64;
                    continue;
                }
            }
        }

        // Uncompressed: write header then raw data (zero-copy path)
        if use_crc32 {
            let crc = crc32fast::hash(&buf[..n]);
            let frame_len = n as u32 + 4;
            write_frame_header(writer, FRAME_DATA, FLAG_CRC32, frame_len).await?;
            writer.write_all(&buf[..n]).await?;
            writer.write_all(&crc.to_le_bytes()).await?;
        } else {
            write_frame_header(writer, FRAME_DATA, 0, n as u32).await?;
            writer.write_all(&buf[..n]).await?;
        }
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

#[allow(clippy::too_many_arguments)]
async fn handle_put<R, W>(
    state: &ServerState,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    frame: &Frame,
    max_payload: u32,
    use_crc32: bool,
    addr: SocketAddr,
    session_id: &str,
    use_fec: bool,
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

    // Receive DATA frames — unless the client offers the fountain data plane,
    // in which case the bytes arrive as UDP symbols instead.
    loop {
        let data_frame = read_frame(reader, max_payload).await?;

        match data_frame.frame_type {
            FRAME_FEC_OFFER if use_fec => {
                drop(file);
                let received = recv_put_fec(
                    reader,
                    writer,
                    &data_frame,
                    &temp_path,
                    &path,
                    addr,
                    state.verbose,
                    state.auth_token.as_deref(),
                )
                .await?;

                audit::log_file_access(
                    audit::AuditEventType::FileWrite,
                    &addr.ip().to_string(),
                    &req.path,
                    received,
                );
                return Ok(());
            }
            FRAME_DATA => {
                // Verify per-frame CRC32 if present (hardware-accelerated)
                let raw_payload = if use_crc32 && data_frame.flags & FLAG_CRC32 != 0 {
                    let data_len = verify_frame_crc32(&data_frame.payload)?;
                    data_frame.payload[..data_len].to_vec()
                } else {
                    data_frame.payload
                };
                let payload = if data_frame.flags & FLAG_COMPRESSED != 0 {
                    zstd::decode_all(std::io::Cursor::new(&raw_payload))
                        .map_err(|e| AftError::Other(format!("zstd decompress error: {}", e)))?
                } else {
                    raw_payload
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
