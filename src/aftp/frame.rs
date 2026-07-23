//! AFTP wire protocol: binary framing with minimal overhead.
//!
//! Frame layout (10-byte header):
//! ```text
//!   [0-1]  Magic: 0xAF 0x54
//!   [2]    Version: 1
//!   [3]    Frame type
//!   [4]    Flags
//!   [5]    Reserved (0)
//!   [6-9]  Payload length (u32 LE)
//! ```
//!
//! Designed for maximum throughput: 10 bytes of overhead per 1 MB data frame
//! yields 0.001% framing cost, compared to HTTP's 0.02–0.08%.
//!
//! ## Hardware acceleration
//!
//! - **CRC32**: Per-frame integrity via `crc32fast` — auto-detects SSE4.2 (x86_64)
//!   and CRC32 (aarch64) hardware instructions (~30 GB/s).
//! - **SHA-256**: Transfer-level integrity via `sha2` — auto-detects SHA-NI (x86_64)
//!   and SHA2 (aarch64) extensions.
//! - **AES-256-GCM**: Crypto subsystem via `aes-gcm` — auto-detects AES-NI.
//! - **Zstd**: Compression via libzstd C library — uses SIMD internally.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AftError, AftResult};

// ── Wire constants ──────────────────────────────────────────────────────────

pub const MAGIC: [u8; 2] = [0xAF, 0x54];
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 10;

// Frame types
pub const FRAME_HELLO: u8 = 0x01;
pub const FRAME_HELLO_ACK: u8 = 0x02;
pub const FRAME_GET: u8 = 0x03;
pub const FRAME_HEAD: u8 = 0x04;
pub const FRAME_HEAD_RESP: u8 = 0x05;
pub const FRAME_PUT: u8 = 0x06;
pub const FRAME_PUT_ACK: u8 = 0x07;
pub const FRAME_LIST: u8 = 0x08;
pub const FRAME_LIST_RESP: u8 = 0x09;
pub const FRAME_DATA: u8 = 0x0A;
pub const FRAME_DATA_END: u8 = 0x0B;
pub const FRAME_ERROR: u8 = 0x0C;
pub const FRAME_PING: u8 = 0x0D;
pub const FRAME_PONG: u8 = 0x0E;
pub const FRAME_AUTH_CHALLENGE: u8 = 0x0F;
pub const FRAME_AUTH_RESPONSE: u8 = 0x10;
pub const FRAME_STREAM_OPEN: u8 = 0x11;
pub const FRAME_STREAM_CLOSE: u8 = 0x12;
pub const FRAME_STREAM_DATA: u8 = 0x13;
pub const FRAME_RESUME: u8 = 0x14;
pub const FRAME_RESUME_ACK: u8 = 0x15;

// ── FEC data-plane control frames (AFTP v2) ─────────────────────────────────
//
// These negotiate and steer the fountain-coded data plane. They travel on the
// reliable control stream; the symbols themselves travel as UDP datagrams.

/// Sender → receiver: proposed data-plane parameters for a transfer.
pub const FRAME_FEC_OFFER: u8 = 0x16;
/// Receiver → sender: accepted parameters and the UDP port to spray at.
pub const FRAME_FEC_ACCEPT: u8 = 0x17;
/// Receiver → sender: a block is short; send this many more symbols.
pub const FRAME_FEC_NEEDMORE: u8 = 0x18;
/// Receiver → sender: a block decoded and verified; release its buffers.
pub const FRAME_FEC_BLOCK_OK: u8 = 0x19;

// Flags
pub const FLAG_COMPRESSED: u8 = 0x01;
/// Per-frame CRC32 integrity check (hardware-accelerated via SSE4.2 / ARM CRC32).
/// When set, the last 4 bytes of the payload are a CRC32 of the preceding bytes.
pub const FLAG_CRC32: u8 = 0x02;

// Capabilities (bitmask in HELLO/HELLO_ACK)
pub const CAP_COMPRESSION: u32 = 0x01;
pub const CAP_CHECKSUM: u32 = 0x02;
pub const CAP_AUTH_CHALLENGE: u32 = 0x04;
// Protocol-defined capability bits (CAP_MULTIPLEX reserved for mux feature)
#[allow(dead_code)] // Protocol spec
pub const CAP_MULTIPLEX: u32 = 0x08;
pub const CAP_SESSION_RESUME: u32 = 0x10;
/// Hardware-accelerated per-frame CRC32 integrity (SSE4.2 / ARM CRC32C).
pub const CAP_CRC32_FRAMES: u32 = 0x20;

/// Peer can carry a transfer over the fountain-coded UDP data plane.
///
/// Negotiation is fail-safe: when either side omits this bit the transfer uses
/// the ordinary reliable frame path, so v1 and v2 peers interoperate.
pub const CAP_FEC: u32 = 0x40;

// Defaults
pub const DEFAULT_PORT: u16 = 2600;
/// 1 MB data frames — maximises throughput, minimises syscall count
pub const DEFAULT_MAX_FRAME: u32 = 1_048_576;
/// Limit for control frames before negotiation (64 KB)
pub const INITIAL_MAX_PAYLOAD: u32 = 65_536;

// Checksum algorithm identifiers in DATA_END
#[allow(dead_code)] // Protocol spec — reserved for negotiated checksum selection
pub const CHECKSUM_NONE: u8 = 0;
pub const CHECKSUM_SHA256: u8 = 1;
#[allow(dead_code)] // Protocol spec — reserved for SHA-512 checksum support
pub const CHECKSUM_SHA512: u8 = 2;
/// Hardware-accelerated CRC32 checksum (non-cryptographic, ~30 GB/s).
#[allow(dead_code)] // Protocol spec — available for negotiated fast-path integrity
pub const CHECKSUM_CRC32: u8 = 3;

// Error codes in ERROR frames
pub const ERR_NOT_FOUND: u16 = 1;
pub const ERR_PERMISSION_DENIED: u16 = 2;
pub const ERR_INVALID_REQUEST: u16 = 3;
pub const ERR_AUTH_FAILED: u16 = 4;
pub const ERR_INTERNAL: u16 = 5;
pub const ERR_IO: u16 = 6;
#[allow(dead_code)] // Protocol spec — sent by server on resume with expired session
pub const ERR_SESSION_EXPIRED: u16 = 7;

// ── Frame types ─────────────────────────────────────────────────────────────

pub struct FrameHeader {
    pub frame_type: u8,
    pub flags: u8,
    pub payload_len: u32,
}

pub struct Frame {
    pub frame_type: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            flags: 0,
            payload,
        }
    }

    pub fn with_flags(frame_type: u8, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            flags,
            payload,
        }
    }

    pub fn empty(frame_type: u8) -> Self {
        Self {
            frame_type,
            flags: 0,
            payload: Vec::new(),
        }
    }
}

// ── Frame I/O ───────────────────────────────────────────────────────────────

pub async fn read_frame_header<R: AsyncRead + Unpin>(r: &mut R) -> AftResult<FrameHeader> {
    let mut buf = [0u8; HEADER_SIZE];
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            AftError::ConnectionFailed("Connection closed".into())
        } else {
            AftError::Io(e)
        }
    })?;

    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
        return Err(AftError::Other("Invalid AFTP magic bytes".into()));
    }
    if buf[2] != VERSION {
        return Err(AftError::Other(format!(
            "Unsupported AFTP version: {}",
            buf[2]
        )));
    }

    Ok(FrameHeader {
        frame_type: buf[3],
        flags: buf[4],
        payload_len: u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]),
    })
}

/// Read a complete frame. `max_payload` prevents memory bombs from malicious peers.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max_payload: u32) -> AftResult<Frame> {
    let hdr = read_frame_header(r).await?;
    if hdr.payload_len > max_payload {
        return Err(AftError::Other(format!(
            "AFTP payload too large: {} bytes (limit {})",
            hdr.payload_len, max_payload
        )));
    }
    let mut payload = vec![0u8; hdr.payload_len as usize];
    if hdr.payload_len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok(Frame {
        frame_type: hdr.frame_type,
        flags: hdr.flags,
        payload,
    })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> AftResult<()> {
    let len = frame.payload.len() as u32;
    let mut hdr = [0u8; HEADER_SIZE];
    hdr[0] = MAGIC[0];
    hdr[1] = MAGIC[1];
    hdr[2] = VERSION;
    hdr[3] = frame.frame_type;
    hdr[4] = frame.flags;
    // hdr[5] reserved = 0
    hdr[6..10].copy_from_slice(&len.to_le_bytes());

    w.write_all(&hdr).await?;
    if !frame.payload.is_empty() {
        w.write_all(&frame.payload).await?;
    }
    Ok(())
}

/// Verify per-frame CRC32: the last 4 payload bytes must equal the CRC32 of the
/// preceding bytes. Returns the data length (payload.len() - 4) on success.
pub fn verify_frame_crc32(payload: &[u8]) -> AftResult<usize> {
    if payload.len() < 4 {
        return Err(AftError::Other("Frame too short for CRC32 trailer".into()));
    }
    let data_len = payload.len() - 4;
    let expected = u32::from_le_bytes([
        payload[data_len],
        payload[data_len + 1],
        payload[data_len + 2],
        payload[data_len + 3],
    ]);
    let actual = crc32fast::hash(&payload[..data_len]);
    if expected != actual {
        return Err(AftError::Other(format!(
            "Frame CRC32 mismatch: expected 0x{:08X}, got 0x{:08X}",
            expected, actual
        )));
    }
    Ok(data_len)
}

/// Write only the header — caller writes payload bytes separately for zero-copy.
pub async fn write_frame_header<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame_type: u8,
    flags: u8,
    payload_len: u32,
) -> AftResult<()> {
    let mut hdr = [0u8; HEADER_SIZE];
    hdr[0] = MAGIC[0];
    hdr[1] = MAGIC[1];
    hdr[2] = VERSION;
    hdr[3] = frame_type;
    hdr[4] = flags;
    hdr[6..10].copy_from_slice(&payload_len.to_le_bytes());
    w.write_all(&hdr).await?;
    Ok(())
}

// ── Binary encoding helpers ─────────────────────────────────────────────────

pub fn put_u8(buf: &mut Vec<u8>, val: u8) {
    buf.push(val);
}

pub fn put_u16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_le_bytes());
}

pub fn put_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

pub fn put_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    assert!(
        s.len() <= u16::MAX as usize,
        "put_str: string length {} exceeds u16::MAX",
        s.len()
    );
    put_u16(buf, s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

pub fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    assert!(
        data.len() <= u16::MAX as usize,
        "put_bytes: data length {} exceeds u16::MAX",
        data.len()
    );
    put_u16(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

// ── Binary decoding helpers (with bounds checking) ──────────────────────────

pub fn get_u8(buf: &[u8], off: &mut usize) -> AftResult<u8> {
    if *off + 1 > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (u8)".into()));
    }
    let v = buf[*off];
    *off += 1;
    Ok(v)
}

pub fn get_u16(buf: &[u8], off: &mut usize) -> AftResult<u16> {
    if *off + 2 > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (u16)".into()));
    }
    let v = u16::from_le_bytes([buf[*off], buf[*off + 1]]);
    *off += 2;
    Ok(v)
}

pub fn get_u32(buf: &[u8], off: &mut usize) -> AftResult<u32> {
    if *off + 4 > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (u32)".into()));
    }
    let v = u32::from_le_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Ok(v)
}

pub fn get_u64(buf: &[u8], off: &mut usize) -> AftResult<u64> {
    if *off + 8 > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (u64)".into()));
    }
    let v = u64::from_le_bytes([
        buf[*off],
        buf[*off + 1],
        buf[*off + 2],
        buf[*off + 3],
        buf[*off + 4],
        buf[*off + 5],
        buf[*off + 6],
        buf[*off + 7],
    ]);
    *off += 8;
    Ok(v)
}

pub fn get_str(buf: &[u8], off: &mut usize) -> AftResult<String> {
    let len = get_u16(buf, off)? as usize;
    if *off + len > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (string)".into()));
    }
    let s = String::from_utf8_lossy(&buf[*off..*off + len]).to_string();
    *off += len;
    Ok(s)
}

pub fn get_bytes(buf: &[u8], off: &mut usize) -> AftResult<Vec<u8>> {
    let len = get_u16(buf, off)? as usize;
    if *off + len > buf.len() {
        return Err(AftError::Other("AFTP frame truncated (bytes)".into()));
    }
    let data = buf[*off..*off + len].to_vec();
    *off += len;
    Ok(data)
}

// ── Payload builders ────────────────────────────────────────────────────────

/// Build HELLO payload: `[capabilities:4][auth_token_len:2][auth_token:N]`
pub fn build_hello(capabilities: u32, auth_token: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    put_u32(&mut buf, capabilities);
    put_str(&mut buf, auth_token.unwrap_or(""));
    buf
}

/// Build HELLO_ACK payload: `[capabilities:4][max_frame_size:4][session_id_len:2][session_id:N]`
#[allow(dead_code)] // Public API — used for non-resume connections
pub fn build_hello_ack(capabilities: u32, max_frame_size: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    put_u32(&mut buf, capabilities);
    put_u32(&mut buf, max_frame_size);
    put_str(&mut buf, ""); // no session_id for non-session connections
    buf
}

/// Build HELLO_ACK payload with a session ID for resumable connections.
pub fn build_hello_ack_with_session(
    capabilities: u32,
    max_frame_size: u32,
    session_id: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + session_id.len());
    put_u32(&mut buf, capabilities);
    put_u32(&mut buf, max_frame_size);
    put_str(&mut buf, session_id);
    buf
}

/// Build GET payload: `[path_len:2][path:N][range_start:8][range_end:8]`
pub fn build_get(path: &str, range_start: u64, range_end: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 20);
    put_str(&mut buf, path);
    put_u64(&mut buf, range_start);
    put_u64(&mut buf, range_end);
    buf
}

/// Build HEAD payload: `[path_len:2][path:N]`
pub fn build_head(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 4);
    put_str(&mut buf, path);
    buf
}

/// Build HEAD_RESP payload: `[file_size:8][modified_secs:8][content_type_len:2][content_type:N]`
pub fn build_head_resp(file_size: u64, modified_secs: u64, content_type: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(content_type.len() + 20);
    put_u64(&mut buf, file_size);
    put_u64(&mut buf, modified_secs);
    put_str(&mut buf, content_type);
    buf
}

/// Build PUT payload: `[path_len:2][path:N][file_size:8]`
pub fn build_put(path: &str, file_size: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 12);
    put_str(&mut buf, path);
    put_u64(&mut buf, file_size);
    buf
}

/// Build PUT_ACK payload: `[status:1]`  (0 = ready, 1 = complete)
pub fn build_put_ack(complete: bool) -> Vec<u8> {
    vec![if complete { 1 } else { 0 }]
}

/// Build LIST payload: `[path_len:2][path:N]`
pub fn build_list(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 4);
    put_str(&mut buf, path);
    buf
}

/// Build DATA_END payload: `[total_bytes:8][checksum_algo:1][checksum_len:1][checksum:N]`
pub fn build_data_end(total_bytes: u64, algo: u8, checksum: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + checksum.len());
    put_u64(&mut buf, total_bytes);
    put_u8(&mut buf, algo);
    put_u8(&mut buf, checksum.len() as u8);
    buf.extend_from_slice(checksum);
    buf
}

/// Build ERROR payload: `[error_code:2][message_len:2][message:N]`
pub fn build_error(code: u16, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(message.len() + 8);
    put_u16(&mut buf, code);
    put_str(&mut buf, message);
    buf
}

// ── Payload parsers ─────────────────────────────────────────────────────────

pub struct HelloPayload {
    pub capabilities: u32,
    pub auth_token: String,
}

pub fn parse_hello(payload: &[u8]) -> AftResult<HelloPayload> {
    let mut off = 0;
    let capabilities = get_u32(payload, &mut off)?;
    let auth_token = get_str(payload, &mut off)?;
    Ok(HelloPayload {
        capabilities,
        auth_token,
    })
}

pub struct HelloAckPayload {
    pub capabilities: u32,
    pub max_frame_size: u32,
    pub session_id: String,
}

pub fn parse_hello_ack(payload: &[u8]) -> AftResult<HelloAckPayload> {
    let mut off = 0;
    let capabilities = get_u32(payload, &mut off)?;
    let max_frame_size = get_u32(payload, &mut off)?;
    // session_id is optional for backward compatibility
    let session_id = if off < payload.len() {
        get_str(payload, &mut off).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(HelloAckPayload {
        capabilities,
        max_frame_size,
        session_id,
    })
}

pub struct GetPayload {
    pub path: String,
    pub range_start: u64,
    pub range_end: u64,
}

pub fn parse_get(payload: &[u8]) -> AftResult<GetPayload> {
    let mut off = 0;
    let path = get_str(payload, &mut off)?;
    let range_start = get_u64(payload, &mut off)?;
    let range_end = get_u64(payload, &mut off)?;
    Ok(GetPayload {
        path,
        range_start,
        range_end,
    })
}

pub struct HeadRespPayload {
    pub file_size: u64,
    pub modified_secs: u64,
    pub content_type: String,
}

pub fn parse_head_resp(payload: &[u8]) -> AftResult<HeadRespPayload> {
    let mut off = 0;
    let file_size = get_u64(payload, &mut off)?;
    let modified_secs = get_u64(payload, &mut off)?;
    let content_type = get_str(payload, &mut off)?;
    Ok(HeadRespPayload {
        file_size,
        modified_secs,
        content_type,
    })
}

#[allow(dead_code)] // Public API — fields consumed by protocol handlers
pub struct PutPayload {
    pub path: String,
    pub file_size: u64,
}

pub fn parse_put(payload: &[u8]) -> AftResult<PutPayload> {
    let mut off = 0;
    let path = get_str(payload, &mut off)?;
    let file_size = get_u64(payload, &mut off)?;
    Ok(PutPayload { path, file_size })
}

pub struct DataEndPayload {
    pub total_bytes: u64,
    pub checksum_algo: u8,
    pub checksum: Vec<u8>,
}

pub fn parse_data_end(payload: &[u8]) -> AftResult<DataEndPayload> {
    let mut off = 0;
    let total_bytes = get_u64(payload, &mut off)?;
    let algo = get_u8(payload, &mut off)?;
    let len = get_u8(payload, &mut off)? as usize;
    if off + len > payload.len() {
        return Err(AftError::Other("DATA_END checksum truncated".into()));
    }
    let checksum = payload[off..off + len].to_vec();
    Ok(DataEndPayload {
        total_bytes,
        checksum_algo: algo,
        checksum,
    })
}

#[allow(dead_code)] // Public API — fields consumed by protocol handlers
pub struct ErrorPayload {
    pub code: u16,
    pub message: String,
}

pub fn parse_error(payload: &[u8]) -> AftResult<ErrorPayload> {
    let mut off = 0;
    let code = get_u16(payload, &mut off)?;
    let message = get_str(payload, &mut off)?;
    Ok(ErrorPayload { code, message })
}

pub struct PutAckPayload {
    pub complete: bool,
}

pub fn parse_put_ack(payload: &[u8]) -> AftResult<PutAckPayload> {
    let mut off = 0;
    let status = get_u8(payload, &mut off)?;
    Ok(PutAckPayload {
        complete: status != 0,
    })
}

pub struct ListEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified_secs: u64,
}

pub fn parse_list_resp(payload: &[u8]) -> AftResult<Vec<ListEntry>> {
    let mut off = 0;
    let count = get_u32(payload, &mut off)? as usize;
    // Cap allocation to prevent OOM from malicious count values.
    // Each list entry is at least 19 bytes (2+1 name + 8 size + 1 is_dir + 8 mtime).
    let max_entries = (payload.len() - off) / 19;
    let mut entries = Vec::with_capacity(count.min(max_entries));
    for _ in 0..count {
        let name = get_str(payload, &mut off)?;
        let size = get_u64(payload, &mut off)?;
        let is_dir = get_u8(payload, &mut off)? != 0;
        let modified_secs = get_u64(payload, &mut off)?;
        entries.push(ListEntry {
            name,
            size,
            is_dir,
            modified_secs,
        });
    }
    Ok(entries)
}

pub fn build_list_resp(entries: &[ListEntry]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entries.len() * 64);
    put_u32(&mut buf, entries.len() as u32);
    for e in entries {
        put_str(&mut buf, &e.name);
        put_u64(&mut buf, e.size);
        put_u8(&mut buf, if e.is_dir { 1 } else { 0 });
        put_u64(&mut buf, e.modified_secs);
    }
    buf
}

// ── Auth frame builders/parsers ─────────────────────────────────────────────

/// Build AUTH_CHALLENGE payload: `[nonce_len:2][nonce:N]`
pub fn build_auth_challenge(nonce: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(nonce.len() + 2);
    put_bytes(&mut buf, nonce);
    buf
}

pub struct AuthChallengePayload {
    pub nonce: Vec<u8>,
}

pub fn parse_auth_challenge(payload: &[u8]) -> AftResult<AuthChallengePayload> {
    let mut off = 0;
    let nonce = get_bytes(payload, &mut off)?;
    Ok(AuthChallengePayload { nonce })
}

/// Build AUTH_RESPONSE payload: `[hmac_len:2][hmac:N]`
pub fn build_auth_response(hmac: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(hmac.len() + 2);
    put_bytes(&mut buf, hmac);
    buf
}

pub struct AuthResponsePayload {
    pub hmac: Vec<u8>,
}

pub fn parse_auth_response(payload: &[u8]) -> AftResult<AuthResponsePayload> {
    let mut off = 0;
    let hmac = get_bytes(payload, &mut off)?;
    Ok(AuthResponsePayload { hmac })
}

// ── Mux frame builders/parsers ──────────────────────────────────────────────

/// Build STREAM_OPEN payload: `[stream_id:2]`
pub fn build_stream_open(stream_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    put_u16(&mut buf, stream_id);
    buf
}

/// Build STREAM_CLOSE payload: `[stream_id:2]`
pub fn build_stream_close(stream_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    put_u16(&mut buf, stream_id);
    buf
}

/// Build STREAM_DATA payload: `[stream_id:2][inner_frame_type:1][data_len:4][data:N]`
pub fn build_stream_data(stream_id: u16, inner_frame_type: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7 + data.len());
    put_u16(&mut buf, stream_id);
    put_u8(&mut buf, inner_frame_type);
    put_u32(&mut buf, data.len() as u32);
    buf.extend_from_slice(data);
    buf
}

pub struct StreamOpenPayload {
    pub stream_id: u16,
}

pub fn parse_stream_open(payload: &[u8]) -> AftResult<StreamOpenPayload> {
    let mut off = 0;
    let stream_id = get_u16(payload, &mut off)?;
    Ok(StreamOpenPayload { stream_id })
}

pub struct StreamClosePayload {
    pub stream_id: u16,
}

pub fn parse_stream_close(payload: &[u8]) -> AftResult<StreamClosePayload> {
    let mut off = 0;
    let stream_id = get_u16(payload, &mut off)?;
    Ok(StreamClosePayload { stream_id })
}

pub struct StreamDataPayload {
    pub stream_id: u16,
    pub inner_frame_type: u8,
    pub data: Vec<u8>,
}

pub fn parse_stream_data(payload: &[u8]) -> AftResult<StreamDataPayload> {
    let mut off = 0;
    let stream_id = get_u16(payload, &mut off)?;
    let inner_frame_type = get_u8(payload, &mut off)?;
    let data_len = get_u32(payload, &mut off)? as usize;
    if off + data_len > payload.len() {
        return Err(AftError::Other("STREAM_DATA truncated".into()));
    }
    let data = payload[off..off + data_len].to_vec();
    Ok(StreamDataPayload {
        stream_id,
        inner_frame_type,
        data,
    })
}

// ── Session resume frame builders/parsers ───────────────────────────────────

/// Build RESUME payload: `[session_id_len:2][session_id:N][capabilities:4][auth_token_len:2][auth_token:N]`
pub fn build_resume(session_id: &str, capabilities: u32, auth_token: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(session_id.len() + 64);
    put_str(&mut buf, session_id);
    put_u32(&mut buf, capabilities);
    put_str(&mut buf, auth_token.unwrap_or(""));
    buf
}

#[allow(dead_code)] // Public API — fields consumed by resume handlers
pub struct ResumePayload {
    pub session_id: String,
    pub capabilities: u32,
    pub auth_token: String,
}

pub fn parse_resume(payload: &[u8]) -> AftResult<ResumePayload> {
    let mut off = 0;
    let session_id = get_str(payload, &mut off)?;
    let capabilities = get_u32(payload, &mut off)?;
    let auth_token = get_str(payload, &mut off)?;
    Ok(ResumePayload {
        session_id,
        capabilities,
        auth_token,
    })
}

/// Build RESUME_ACK payload: `[accepted:1][bytes_received:8][path_len:2][path:N]`
/// If accepted=0, the server rejects the resume (session expired/unknown).
/// If accepted=1, bytes_received is the amount the server already has for the
/// in-progress transfer, allowing the client to seek forward and resume.
pub fn build_resume_ack(accepted: bool, bytes_received: u64, path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 12);
    put_u8(&mut buf, if accepted { 1 } else { 0 });
    put_u64(&mut buf, bytes_received);
    put_str(&mut buf, path);
    buf
}

pub struct ResumeAckPayload {
    pub accepted: bool,
    pub bytes_received: u64,
    pub path: String,
}

pub fn parse_resume_ack(payload: &[u8]) -> AftResult<ResumeAckPayload> {
    let mut off = 0;
    let accepted = get_u8(payload, &mut off)? != 0;
    let bytes_received = get_u64(payload, &mut off)?;
    let path = get_str(payload, &mut off)?;
    Ok(ResumeAckPayload {
        accepted,
        bytes_received,
        path,
    })
}

// ── Cancellation-safe incremental frame reader ──────────────────────────────

/// Reads frames one `read()` at a time, keeping partial state between calls.
///
/// [`read_frame`] is **not** cancellation-safe: it reads a 10-byte header and
/// then the payload as separate awaits, so a `select!` branch that drops it
/// after the header has been consumed loses those bytes permanently and every
/// subsequent frame is misparsed. That is exactly what a bidirectional FEC
/// transfer does — it must send symbols and read feedback concurrently.
///
/// `next_frame` instead performs a single `AsyncReadExt::read` per call, which
/// *is* cancellation-safe (it either consumes bytes and returns, or is dropped
/// having consumed none), and holds the partially-assembled frame in `self`.
/// Dropping the returned future therefore loses nothing.
pub struct FrameAssembler {
    header: [u8; HEADER_SIZE],
    header_filled: usize,
    parsed: Option<FrameHeader>,
    payload: Vec<u8>,
    payload_filled: usize,
}

impl Default for FrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            header: [0u8; HEADER_SIZE],
            header_filled: 0,
            parsed: None,
            payload: Vec::new(),
            payload_filled: 0,
        }
    }

    /// Advance by one read. Returns `Ok(Some(frame))` when a whole frame has
    /// been assembled, `Ok(None)` when more bytes are still needed.
    pub async fn next_frame<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        max_payload: u32,
    ) -> AftResult<Option<Frame>> {
        use tokio::io::AsyncReadExt;

        // Phase 1: the fixed-size header.
        if self.parsed.is_none() {
            let n = r.read(&mut self.header[self.header_filled..]).await?;
            if n == 0 {
                return Err(AftError::ConnectionFailed("Connection closed".into()));
            }
            self.header_filled += n;
            if self.header_filled < HEADER_SIZE {
                return Ok(None);
            }

            if self.header[0..2] != MAGIC {
                return Err(AftError::Other("AFTP bad magic".into()));
            }
            if self.header[2] != VERSION {
                return Err(AftError::Other(format!(
                    "AFTP version mismatch: got {}, expected {}",
                    self.header[2], VERSION
                )));
            }
            let payload_len = u32::from_le_bytes([
                self.header[6],
                self.header[7],
                self.header[8],
                self.header[9],
            ]);
            if payload_len > max_payload {
                return Err(AftError::Other(format!(
                    "AFTP frame payload {} exceeds maximum {}",
                    payload_len, max_payload
                )));
            }
            self.parsed = Some(FrameHeader {
                frame_type: self.header[3],
                flags: self.header[4],
                payload_len,
            });
            self.payload = vec![0u8; payload_len as usize];
            self.payload_filled = 0;
        }

        // Phase 2: the payload.
        let hdr = self.parsed.as_ref().expect("header parsed above");
        if self.payload_filled < hdr.payload_len as usize {
            let n = r.read(&mut self.payload[self.payload_filled..]).await?;
            if n == 0 {
                return Err(AftError::ConnectionFailed("Connection closed".into()));
            }
            self.payload_filled += n;
            if self.payload_filled < hdr.payload_len as usize {
                return Ok(None);
            }
        }

        let hdr = self.parsed.take().expect("header parsed above");
        self.header_filled = 0;
        Ok(Some(Frame {
            frame_type: hdr.frame_type,
            flags: hdr.flags,
            payload: std::mem::take(&mut self.payload),
        }))
    }
}

// ── FEC data-plane frame builders/parsers ───────────────────────────────────
//
// The control plane never carries file bytes for a FEC transfer — only the
// parameters needed to build matching encoders and decoders, and the feedback
// that tells the sender when to stop.

/// Build FEC_OFFER: `[session_id:8][total_len:8][block_size:4][symbol_size:2]`
/// `[block_count:4][authenticated:1]`
pub fn build_fec_offer(
    session_id: u64,
    total_len: u64,
    block_size: u32,
    symbol_size: u16,
    block_count: u32,
    authenticated: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(27);
    put_u64(&mut buf, session_id);
    put_u64(&mut buf, total_len);
    put_u32(&mut buf, block_size);
    put_u16(&mut buf, symbol_size);
    put_u32(&mut buf, block_count);
    put_u8(&mut buf, u8::from(authenticated));
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecOfferPayload {
    pub session_id: u64,
    pub total_len: u64,
    pub block_size: u32,
    pub symbol_size: u16,
    pub block_count: u32,
    pub authenticated: bool,
}

pub fn parse_fec_offer(payload: &[u8]) -> AftResult<FecOfferPayload> {
    let mut off = 0;
    let session_id = get_u64(payload, &mut off)?;
    let total_len = get_u64(payload, &mut off)?;
    let block_size = get_u32(payload, &mut off)?;
    let symbol_size = get_u16(payload, &mut off)?;
    let block_count = get_u32(payload, &mut off)?;
    let authenticated = get_u8(payload, &mut off)? != 0;

    // Validate before any of this reaches an allocator or the codec. A peer
    // that offers a zero symbol size or a block count inconsistent with the
    // declared length is malformed or hostile, and either way must not be
    // allowed to drive our buffer sizing.
    if symbol_size == 0 {
        return Err(AftError::Other("FEC offer has zero symbol size".into()));
    }
    if block_size == 0 {
        return Err(AftError::Other("FEC offer has zero block size".into()));
    }
    if symbol_size as u32 > block_size {
        return Err(AftError::Other(
            "FEC offer symbol size exceeds block size".into(),
        ));
    }
    let expected = total_len.div_ceil(block_size as u64);
    if expected != block_count as u64 {
        return Err(AftError::Other(format!(
            "FEC offer block count {} disagrees with {} bytes at {} per block (expected {})",
            block_count, total_len, block_size, expected
        )));
    }

    Ok(FecOfferPayload {
        session_id,
        total_len,
        block_size,
        symbol_size,
        block_count,
        authenticated,
    })
}

/// Build FEC_ACCEPT: `[accepted:1][udp_port:2][reason_len:2][reason:N]`
///
/// A receiver that cannot or will not use the data plane answers with
/// `accepted = 0`, and the sender falls back to the reliable frame path.
pub fn build_fec_accept(accepted: bool, udp_port: u16, reason: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(reason.len() + 8);
    put_u8(&mut buf, u8::from(accepted));
    put_u16(&mut buf, udp_port);
    put_str(&mut buf, reason);
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecAcceptPayload {
    pub accepted: bool,
    pub udp_port: u16,
    pub reason: String,
}

pub fn parse_fec_accept(payload: &[u8]) -> AftResult<FecAcceptPayload> {
    let mut off = 0;
    let accepted = get_u8(payload, &mut off)? != 0;
    let udp_port = get_u16(payload, &mut off)?;
    let reason = get_str(payload, &mut off)?;
    if accepted && udp_port == 0 {
        return Err(AftError::Other(
            "FEC accept did not supply a data-plane port".into(),
        ));
    }
    Ok(FecAcceptPayload {
        accepted,
        udp_port,
        reason,
    })
}

/// Build FEC_NEEDMORE: `[block_id:4][symbols_needed:4][symbols_received:4]`
///
/// `symbols_received` lets the sender estimate the path's loss rate directly
/// (it knows how many it sent), which is what sizes the next repair round.
pub fn build_fec_needmore(block_id: u32, symbols_needed: u32, symbols_received: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    put_u32(&mut buf, block_id);
    put_u32(&mut buf, symbols_needed);
    put_u32(&mut buf, symbols_received);
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecNeedMorePayload {
    pub block_id: u32,
    pub symbols_needed: u32,
    pub symbols_received: u32,
}

pub fn parse_fec_needmore(payload: &[u8]) -> AftResult<FecNeedMorePayload> {
    let mut off = 0;
    let block_id = get_u32(payload, &mut off)?;
    let symbols_needed = get_u32(payload, &mut off)?;
    let symbols_received = get_u32(payload, &mut off)?;
    Ok(FecNeedMorePayload {
        block_id,
        symbols_needed,
        symbols_received,
    })
}

/// Build FEC_BLOCK_OK: `[block_id:4][symbols_used:4]`
pub fn build_fec_block_ok(block_id: u32, symbols_used: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    put_u32(&mut buf, block_id);
    put_u32(&mut buf, symbols_used);
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecBlockOkPayload {
    pub block_id: u32,
    pub symbols_used: u32,
}

pub fn parse_fec_block_ok(payload: &[u8]) -> AftResult<FecBlockOkPayload> {
    let mut off = 0;
    let block_id = get_u32(payload, &mut off)?;
    let symbols_used = get_u32(payload, &mut off)?;
    Ok(FecBlockOkPayload {
        block_id,
        symbols_used,
    })
}

#[cfg(test)]
mod assembler_tests {
    use super::*;

    /// Feed a stream one byte at a time. The assembler must survive being
    /// polled repeatedly with insufficient data and still yield the exact
    /// frames — the same situation a `select!` creates when it drops the
    /// future between reads.
    #[tokio::test]
    async fn assembles_frames_from_a_dribbling_stream() {
        let mut wire = Vec::new();
        let frames = [
            Frame::new(FRAME_FEC_BLOCK_OK, build_fec_block_ok(7, 42)),
            Frame::new(FRAME_FEC_NEEDMORE, build_fec_needmore(3, 9, 100)),
            Frame::empty(FRAME_PING),
        ];
        for f in &frames {
            write_frame(&mut wire, f).await.unwrap();
        }

        // A reader that returns at most one byte per call, forcing the
        // assembler through every possible partial state.
        struct Dribble<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl tokio::io::AsyncRead for Dribble<'_> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.pos < self.data.len() && buf.remaining() > 0 {
                    let b = self.data[self.pos];
                    self.pos += 1;
                    buf.put_slice(&[b]);
                }
                std::task::Poll::Ready(Ok(()))
            }
        }

        let mut r = Dribble {
            data: &wire,
            pos: 0,
        };
        let mut asm = FrameAssembler::new();
        let mut got = Vec::new();

        // Far more polls than bytes, so plenty return `None`.
        for _ in 0..(wire.len() * 4) {
            if let Some(f) = asm.next_frame(&mut r, 1 << 20).await.unwrap() {
                got.push(f);
            }
            if got.len() == frames.len() {
                break;
            }
        }

        assert_eq!(got.len(), frames.len(), "did not reassemble every frame");
        for (a, b) in got.iter().zip(frames.iter()) {
            assert_eq!(a.frame_type, b.frame_type);
            assert_eq!(a.payload, b.payload);
        }
    }

    /// An oversized declared payload must be refused rather than allocated.
    #[tokio::test]
    async fn rejects_payload_over_the_cap() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::new(FRAME_DATA, vec![0u8; 4096]))
            .await
            .unwrap();

        let mut asm = FrameAssembler::new();
        let mut cursor = std::io::Cursor::new(wire);
        let mut err = None;
        for _ in 0..64 {
            match asm.next_frame(&mut cursor, 128).await {
                Ok(Some(_)) => panic!("oversized frame was accepted"),
                Ok(None) => continue,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        assert!(err.is_some(), "no error for an over-cap payload");
    }
}
