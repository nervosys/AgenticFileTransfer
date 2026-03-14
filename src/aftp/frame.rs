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
#[allow(dead_code)]
pub const FRAME_STREAM_OPEN: u8 = 0x11;
#[allow(dead_code)]
pub const FRAME_STREAM_CLOSE: u8 = 0x12;
#[allow(dead_code)]
pub const FRAME_STREAM_DATA: u8 = 0x13;

// Flags
pub const FLAG_COMPRESSED: u8 = 0x01;

// Capabilities (bitmask in HELLO/HELLO_ACK)
pub const CAP_COMPRESSION: u32 = 0x01;
pub const CAP_CHECKSUM: u32 = 0x02;
pub const CAP_AUTH_CHALLENGE: u32 = 0x04;
#[allow(dead_code)]
pub const CAP_MULTIPLEX: u32 = 0x08;

// Defaults
pub const DEFAULT_PORT: u16 = 2600;
/// 1 MB data frames — maximises throughput, minimises syscall count
pub const DEFAULT_MAX_FRAME: u32 = 1_048_576;
/// Limit for control frames before negotiation (64 KB)
pub const INITIAL_MAX_PAYLOAD: u32 = 65_536;

// Checksum algorithm identifiers in DATA_END
#[allow(dead_code)]
pub const CHECKSUM_NONE: u8 = 0;
pub const CHECKSUM_SHA256: u8 = 1;
#[allow(dead_code)]
pub const CHECKSUM_SHA512: u8 = 2;

// Error codes in ERROR frames
pub const ERR_NOT_FOUND: u16 = 1;
pub const ERR_PERMISSION_DENIED: u16 = 2;
pub const ERR_INVALID_REQUEST: u16 = 3;
pub const ERR_AUTH_FAILED: u16 = 4;
pub const ERR_INTERNAL: u16 = 5;
pub const ERR_IO: u16 = 6;

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
    put_u16(buf, s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

#[allow(dead_code)]
pub fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
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

#[allow(dead_code)]
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

/// Build HELLO payload: [capabilities:4][auth_token_len:2][auth_token:N]
pub fn build_hello(capabilities: u32, auth_token: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    put_u32(&mut buf, capabilities);
    put_str(&mut buf, auth_token.unwrap_or(""));
    buf
}

/// Build HELLO_ACK payload: [capabilities:4][max_frame_size:4]
pub fn build_hello_ack(capabilities: u32, max_frame_size: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    put_u32(&mut buf, capabilities);
    put_u32(&mut buf, max_frame_size);
    buf
}

/// Build GET payload: [path_len:2][path:N][range_start:8][range_end:8]
pub fn build_get(path: &str, range_start: u64, range_end: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 20);
    put_str(&mut buf, path);
    put_u64(&mut buf, range_start);
    put_u64(&mut buf, range_end);
    buf
}

/// Build HEAD payload: [path_len:2][path:N]
pub fn build_head(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 4);
    put_str(&mut buf, path);
    buf
}

/// Build HEAD_RESP payload: [file_size:8][modified_secs:8][content_type_len:2][content_type:N]
pub fn build_head_resp(file_size: u64, modified_secs: u64, content_type: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(content_type.len() + 20);
    put_u64(&mut buf, file_size);
    put_u64(&mut buf, modified_secs);
    put_str(&mut buf, content_type);
    buf
}

/// Build PUT payload: [path_len:2][path:N][file_size:8]
pub fn build_put(path: &str, file_size: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 12);
    put_str(&mut buf, path);
    put_u64(&mut buf, file_size);
    buf
}

/// Build PUT_ACK payload: [status:1]  (0 = ready, 1 = complete)
pub fn build_put_ack(complete: bool) -> Vec<u8> {
    vec![if complete { 1 } else { 0 }]
}

/// Build LIST payload: [path_len:2][path:N]
pub fn build_list(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len() + 4);
    put_str(&mut buf, path);
    buf
}

/// Build DATA_END payload: [total_bytes:8][checksum_algo:1][checksum_len:1][checksum:N]
pub fn build_data_end(total_bytes: u64, algo: u8, checksum: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + checksum.len());
    put_u64(&mut buf, total_bytes);
    put_u8(&mut buf, algo);
    put_u8(&mut buf, checksum.len() as u8);
    buf.extend_from_slice(checksum);
    buf
}

/// Build ERROR payload: [error_code:2][message_len:2][message:N]
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
}

pub fn parse_hello_ack(payload: &[u8]) -> AftResult<HelloAckPayload> {
    let mut off = 0;
    let capabilities = get_u32(payload, &mut off)?;
    let max_frame_size = get_u32(payload, &mut off)?;
    Ok(HelloAckPayload {
        capabilities,
        max_frame_size,
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    let mut entries = Vec::with_capacity(count);
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

/// Build AUTH_CHALLENGE payload: [nonce_len:2][nonce:N]
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

/// Build AUTH_RESPONSE payload: [hmac_len:2][hmac:N]
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

#[allow(dead_code)]
/// Build STREAM_OPEN payload: [stream_id:2]
pub fn build_stream_open(stream_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    put_u16(&mut buf, stream_id);
    buf
}

#[allow(dead_code)]
/// Build STREAM_CLOSE payload: [stream_id:2]
pub fn build_stream_close(stream_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    put_u16(&mut buf, stream_id);
    buf
}

#[allow(dead_code)]
/// Build STREAM_DATA payload: [stream_id:2][inner_frame_type:1][data_len:4][data:N]
pub fn build_stream_data(stream_id: u16, inner_frame_type: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7 + data.len());
    put_u16(&mut buf, stream_id);
    put_u8(&mut buf, inner_frame_type);
    put_u32(&mut buf, data.len() as u32);
    buf.extend_from_slice(data);
    buf
}

#[allow(dead_code)]
pub struct StreamOpenPayload {
    pub stream_id: u16,
}

#[allow(dead_code)]
pub fn parse_stream_open(payload: &[u8]) -> AftResult<StreamOpenPayload> {
    let mut off = 0;
    let stream_id = get_u16(payload, &mut off)?;
    Ok(StreamOpenPayload { stream_id })
}

#[allow(dead_code)]
pub struct StreamClosePayload {
    pub stream_id: u16,
}

#[allow(dead_code)]
pub fn parse_stream_close(payload: &[u8]) -> AftResult<StreamClosePayload> {
    let mut off = 0;
    let stream_id = get_u16(payload, &mut off)?;
    Ok(StreamClosePayload { stream_id })
}

#[allow(dead_code)]
pub struct StreamDataPayload {
    pub stream_id: u16,
    pub inner_frame_type: u8,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
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
