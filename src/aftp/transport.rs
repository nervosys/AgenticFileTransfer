#![allow(dead_code)]
//! Transport abstraction for AFTP: TCP, WebSocket, and QUIC.
//!
//! Provides a unified `Transport` trait that abstracts the underlying
//! transport layer, allowing the AFTP server and client to operate
//! over plain TCP, WebSocket, or QUIC connections.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AftError, AftResult};

// ── Transport trait ─────────────────────────────────────────────────────────

/// A boxed async reader/writer pair from an accepted connection.
pub struct TransportStream {
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    pub peer_addr: SocketAddr,
}

/// Trait for transport listeners (server-side).
#[async_trait::async_trait]
pub trait TransportListener: Send + Sync {
    /// Accept the next incoming connection.
    async fn accept(&self) -> AftResult<TransportStream>;
}

/// Trait for transport connectors (client-side).
#[async_trait::async_trait]
pub trait TransportConnector: Send + Sync {
    /// Connect to the specified address.
    async fn connect(&self, addr: &str) -> AftResult<TransportStream>;
}

// ── TCP Transport ───────────────────────────────────────────────────────────

pub struct TcpTransportListener {
    listener: TcpListener,
}

impl TcpTransportListener {
    pub async fn bind(addr: &str) -> AftResult<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AftError::Other(format!("TCP bind {}: {}", addr, e)))?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> AftResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| AftError::Other(format!("local_addr: {}", e)))
    }
}

#[async_trait::async_trait]
impl TransportListener for TcpTransportListener {
    async fn accept(&self) -> AftResult<TransportStream> {
        let (stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true).ok();
        let (rd, wr) = stream.into_split();
        Ok(TransportStream {
            reader: Box::new(rd),
            writer: Box::new(wr),
            peer_addr: addr,
        })
    }
}

pub struct TcpTransportConnector;

#[async_trait::async_trait]
impl TransportConnector for TcpTransportConnector {
    async fn connect(&self, addr: &str) -> AftResult<TransportStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("TCP connect {}: {}", addr, e)))?;
        stream.set_nodelay(true).ok();
        let peer = stream.peer_addr().unwrap_or_else(|_| {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        });
        let (rd, wr) = stream.into_split();
        Ok(TransportStream {
            reader: Box::new(rd),
            writer: Box::new(wr),
            peer_addr: peer,
        })
    }
}

// ── WebSocket Transport ─────────────────────────────────────────────────────

pub struct WsTransportListener {
    listener: TcpListener,
}

impl WsTransportListener {
    pub async fn bind(addr: &str) -> AftResult<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AftError::Other(format!("WS bind {}: {}", addr, e)))?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> AftResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| AftError::Other(format!("local_addr: {}", e)))
    }
}

#[async_trait::async_trait]
impl TransportListener for WsTransportListener {
    async fn accept(&self) -> AftResult<TransportStream> {
        let (stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true).ok();

        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("WS handshake: {}", e)))?;

        let (wr, rd) = futures::StreamExt::split(ws);

        // Adapt WS read half to AsyncRead
        let rd = WsReadAdapter::new(rd);
        // Adapt WS write half to AsyncWrite
        let wr = WsWriteAdapter::new(wr);

        Ok(TransportStream {
            reader: Box::new(rd),
            writer: Box::new(wr),
            peer_addr: addr,
        })
    }
}

pub struct WsTransportConnector;

#[async_trait::async_trait]
impl TransportConnector for WsTransportConnector {
    async fn connect(&self, addr: &str) -> AftResult<TransportStream> {
        let url = format!("ws://{}", addr);
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("WS connect {}: {}", addr, e)))?;

        let peer = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

        let (wr, rd) = futures::StreamExt::split(ws);
        let rd = WsReadAdapter::new(rd);
        let wr = WsWriteAdapter::new(wr);

        Ok(TransportStream {
            reader: Box::new(rd),
            writer: Box::new(wr),
            peer_addr: peer,
        })
    }
}

/// Adapts a WebSocket read stream to tokio::io::AsyncRead.
struct WsReadAdapter<S> {
    inner: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S> WsReadAdapter<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl<S> AsyncRead for WsReadAdapter<S>
where
    S: futures::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain buffered data first
        if self.pos < self.buf.len() {
            let remaining = &self.buf[self.pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }

        // Poll for next WS message
        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(msg))) => {
                let data = msg.into_data();
                if data.is_empty() {
                    cx.waker().wake_by_ref();
                    return std::task::Poll::Pending;
                }
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.buf = data;
                    self.pos = to_copy;
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Adapts a WebSocket write sink to tokio::io::AsyncWrite.
struct WsWriteAdapter<S> {
    inner: S,
}

impl<S> WsWriteAdapter<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> AsyncWrite for WsWriteAdapter<S>
where
    S: futures::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.inner).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {
                let msg = tokio_tungstenite::tungstenite::Message::Binary(buf.to_vec());
                match std::pin::Pin::new(&mut self.inner).start_send(msg) {
                    Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e,
                    ))),
                }
            }
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.inner).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.inner).poll_close(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// ── QUIC Transport ──────────────────────────────────────────────────────────

pub struct QuicTransportListener {
    endpoint: quinn::Endpoint,
}

impl QuicTransportListener {
    pub fn new(endpoint: quinn::Endpoint) -> Self {
        Self { endpoint }
    }

    /// Create a QUIC listener with a self-signed certificate for development.
    pub async fn bind(addr: &str) -> AftResult<Self> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| AftError::Other(format!("Invalid address {}: {}", addr, e)))?;

        let (server_config, _cert) = Self::make_server_config()?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| AftError::Other(format!("QUIC bind {}: {}", addr, e)))?;

        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> AftResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| AftError::Other(format!("local_addr: {}", e)))
    }

    fn make_server_config() -> AftResult<(quinn::ServerConfig, Vec<u8>)> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| AftError::Other(format!("QUIC cert gen: {}", e)))?;
        let cert_der = cert.cert.der().to_vec();
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let mut server_config = quinn::ServerConfig::with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )
        .map_err(|e| AftError::Other(format!("QUIC server config: {}", e)))?;

        let transport_config = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| AftError::Other("QUIC transport config not exclusively owned".into()))?;
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(0u32.into());

        Ok((server_config, cert_der))
    }
}

#[async_trait::async_trait]
impl TransportListener for QuicTransportListener {
    async fn accept(&self) -> AftResult<TransportStream> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| AftError::ConnectionFailed("QUIC endpoint closed".into()))?;

        let connection = incoming
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("QUIC accept: {}", e)))?;

        let peer_addr = connection.remote_address();

        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("QUIC accept_bi: {}", e)))?;

        Ok(TransportStream {
            reader: Box::new(recv),
            writer: Box::new(send),
            peer_addr,
        })
    }
}

pub struct QuicTransportConnector {
    insecure: bool,
}

impl QuicTransportConnector {
    pub fn new(insecure: bool) -> Self {
        Self { insecure }
    }
}

#[async_trait::async_trait]
impl TransportConnector for QuicTransportConnector {
    async fn connect(&self, addr: &str) -> AftResult<TransportStream> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut client_config = if self.insecure {
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureQuicVerifier))
                .with_no_client_auth();
            quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                    .map_err(|e| AftError::Other(format!("QUIC client config: {}", e)))?,
            ))
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let crypto = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                    .map_err(|e| AftError::Other(format!("QUIC client config: {}", e)))?,
            ))
        };

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100u32.into());
        client_config.transport_config(Arc::new(transport));

        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| AftError::Other(format!("Invalid address {}: {}", addr, e)))?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|e| AftError::Other(format!("Invalid bind address: {}", e)))?)
            .map_err(|e| AftError::Other(format!("QUIC client endpoint: {}", e)))?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(socket_addr, "localhost")
            .map_err(|e| AftError::ConnectionFailed(format!("QUIC connect: {}", e)))?
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("QUIC connect: {}", e)))?;

        let peer = connection.remote_address();

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| AftError::ConnectionFailed(format!("QUIC open_bi: {}", e)))?;

        Ok(TransportStream {
            reader: Box::new(recv),
            writer: Box::new(send),
            peer_addr: peer,
        })
    }
}

/// Certificate verifier that accepts any server certificate for QUIC --insecure mode.
#[derive(Debug)]
struct InsecureQuicVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureQuicVerifier {
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

// ── Transport enum for CLI selection ────────────────────────────────────────

/// Transport type selectable via CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Tcp,
    WebSocket,
    Quic,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "tcp"),
            TransportType::WebSocket => write!(f, "ws"),
            TransportType::Quic => write!(f, "quic"),
        }
    }
}

impl std::str::FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(TransportType::Tcp),
            "ws" | "websocket" => Ok(TransportType::WebSocket),
            "quic" => Ok(TransportType::Quic),
            _ => Err(format!("Unknown transport: {}. Use tcp, ws, or quic.", s)),
        }
    }
}
