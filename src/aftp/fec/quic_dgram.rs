//! QUIC-datagram data plane: an alternative carrier for fountain symbols.
//!
//! [`super::udp`] sprays symbols over a bare UDP socket. This module carries the
//! very same symbols — same [`Envelope`], same per-symbol AES-GCM, same session
//! binding and replay/tamper rejection — over the *unreliable datagram*
//! extension of a QUIC connection (RFC 9221). Everything the scheduler and the
//! security model rely on is unchanged; only the wire underneath the envelope
//! differs.
//!
//! ## Why offer QUIC datagrams at all
//!
//! A raw UDP flow is invisible to the connection the control plane already has,
//! so it needs its own port, its own path through NAT, and its own hole to be
//! punched. A QUIC connection multiplexes unreliable datagrams onto the *same*
//! 4-tuple as its reliable streams: one handshake, one port, one NAT binding,
//! connection IDs that survive a path change. On networks that grudgingly pass
//! QUIC but mangle or block novel UDP flows — the middlebox-heavy reality of
//! the public internet — that is the difference between the data plane working
//! and not. QUIC's own loss recovery never touches datagrams (they are
//! delivered once or not at all), so the fountain code still does all the
//! repair; we get the reachability without giving up the loss tolerance.
//!
//! ## Datagram sizing
//!
//! A QUIC datagram is smaller than a bare UDP payload by the QUIC header and
//! packet-protection overhead, and its ceiling is discovered, not assumed:
//! [`QuicDataPlane::max_datagram_size`] reports what the current path admits.
//! A symbol whose envelope exceeds that is refused by the transport, so the
//! offer must size symbols to fit — see [`max_symbol_size_for`].

use std::sync::Arc;

use bytes::Bytes;

use crate::error::{AftError, AftResult};

use super::envelope::Envelope;
use super::transfer::{SymbolSink, SymbolSource};

/// One end of the fountain data plane, carried on a QUIC connection's
/// unreliable datagrams.
pub struct QuicDataPlane {
    conn: quinn::Connection,
    /// Kept alive so the endpoint's I/O driver keeps servicing `conn`; dropping
    /// the endpoint would stall the connection. `None` when the caller anchors
    /// the endpoint's lifetime elsewhere.
    _endpoint: Option<quinn::Endpoint>,
    key: Option<Vec<u8>>,
    session_id: u64,
}

impl QuicDataPlane {
    /// Wrap an established QUIC connection as a data plane. `key` is the
    /// per-session symbol key (`None` = CRC32-only, unauthenticated); it must
    /// match the peer's, exactly as for the UDP plane.
    pub fn new(conn: quinn::Connection, key: Option<Vec<u8>>, session_id: u64) -> Self {
        Self {
            conn,
            _endpoint: None,
            key,
            session_id,
        }
    }

    /// As [`new`](Self::new), but also takes ownership of the endpoint whose
    /// driver services this connection, tying its lifetime to the plane.
    pub fn with_endpoint(
        conn: quinn::Connection,
        endpoint: quinn::Endpoint,
        key: Option<Vec<u8>>,
        session_id: u64,
    ) -> Self {
        Self {
            conn,
            _endpoint: Some(endpoint),
            key,
            session_id,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = session_id;
    }

    /// The largest datagram the current path admits, or `None` if the peer did
    /// not advertise datagram support (in which case QUIC datagrams are
    /// unavailable and the caller must fall back to the UDP plane).
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Send one symbol as a QUIC datagram. Uses the capacity-waiting form so a
    /// momentarily full send buffer applies backpressure to the pacer rather
    /// than dropping the symbol before it ever hits the wire.
    pub async fn send(&self, block_id: u32, session_id: u64, symbol: &[u8]) -> AftResult<usize> {
        let wire =
            Envelope::new(session_id, block_id, symbol.to_vec()).encode(self.key.as_deref())?;
        let n = wire.len();
        self.conn
            .send_datagram_wait(Bytes::from(wire))
            .await
            .map_err(|e| AftError::Other(format!("FEC QUIC send_datagram: {}", e)))?;
        Ok(n)
    }

    /// Receive and verify one symbol. Like the UDP plane, a datagram that fails
    /// verification or belongs to another session yields `Ok(None)` — expected
    /// noise, not an error — while a genuine connection failure surfaces as
    /// `Err`.
    pub async fn recv(&self, expect_session: u64) -> AftResult<Option<(u32, Vec<u8>)>> {
        let dg = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| AftError::Other(format!("FEC QUIC read_datagram: {}", e)))?;
        match Envelope::decode(&dg, self.key.as_deref()) {
            Ok(env) if env.session_id == expect_session => Ok(Some((env.block_id, env.payload))),
            _ => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl SymbolSink for QuicDataPlane {
    async fn send_symbol(&self, block_id: u32, symbol: &[u8]) -> AftResult<()> {
        self.send(block_id, self.session_id, symbol).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SymbolSource for QuicDataPlane {
    async fn recv_symbol(&self) -> AftResult<Option<(u32, Vec<u8>)>> {
        self.recv(self.session_id).await
    }
}

/// Largest fountain symbol that fits a QUIC datagram of `max_datagram`, once the
/// envelope overhead is removed. Delegates to [`super::envelope::max_symbol_size`]
/// but is keyed off the QUIC path's *discovered* ceiling rather than the UDP MTU.
pub fn max_symbol_size_for(max_datagram: usize, authenticated: bool) -> u16 {
    let mtu = max_datagram.min(u16::MAX as usize) as u16;
    super::envelope::max_symbol_size(mtu, authenticated)
}

/// Conservative datagram size to assume when the offer must declare a symbol
/// size *before* the QUIC path is established.
///
/// QUIC guarantees a path can carry a 1200-byte *packet*, but the usable
/// DATAGRAM-frame payload is smaller — the QUIC short header, connection IDs,
/// packet number, frame header, and 16-byte AEAD tag all come out of that 1200,
/// and `Connection::max_datagram_size` is smaller still until path-MTU discovery
/// completes. Sizing symbols to a bare 1200 races that discovery and trips
/// "datagram too large" on the first sends. 1100 leaves comfortable headroom
/// (≈70+ bytes) under even the pre-validation ceiling, so a symbol sized to it
/// fits any path that admits QUIC; a wider path simply leaves the slack unused.
pub const QUIC_DATAGRAM_MTU: u16 = 1100;

// ── Data-plane role helpers ──────────────────────────────────────────────────
//
// A FEC data plane has a *listener* (the end that puts its port in the accept
// and waits to be reached) and a *connector* (the end that dials that port).
// Which AFTP peer plays which role alternates by transfer direction, but QUIC's
// own roles do not: the listener is always a QUIC *server* endpoint, the
// connector always a QUIC *client* endpoint. These helpers pin that mapping so
// the four transfer paths can each pick a role without touching cert plumbing.

/// Bind a QUIC listener for the data plane and report its port. Call before
/// sending the accept so the port can go in it; then [`accept_plane`] to take
/// the incoming connection.
pub async fn bind_listener() -> AftResult<(quinn::Endpoint, u16)> {
    let ep = dev_server_endpoint("0.0.0.0:0".parse().unwrap())?;
    let port = ep
        .local_addr()
        .map_err(|e| AftError::Other(format!("QUIC local_addr: {}", e)))?
        .port();
    Ok((ep, port))
}

/// Accept the single incoming data-plane connection on `endpoint` and wrap it,
/// anchoring the endpoint's lifetime to the returned plane.
pub async fn accept_plane(
    endpoint: quinn::Endpoint,
    key: Option<Vec<u8>>,
    session_id: u64,
) -> AftResult<QuicDataPlane> {
    let conn = endpoint
        .accept()
        .await
        .ok_or_else(|| AftError::ConnectionFailed("QUIC data plane endpoint closed".into()))?
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("QUIC data plane accept: {}", e)))?;
    Ok(QuicDataPlane::with_endpoint(
        conn, endpoint, key, session_id,
    ))
}

/// Dial the peer's data-plane listener and wrap the connection.
pub async fn connect_plane(
    peer: std::net::SocketAddr,
    key: Option<Vec<u8>>,
    session_id: u64,
) -> AftResult<QuicDataPlane> {
    let endpoint = dev_client_endpoint()?;
    let conn = endpoint
        .connect(peer, "localhost")
        .map_err(|e| AftError::ConnectionFailed(format!("QUIC data plane connect: {}", e)))?
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("QUIC data plane connect: {}", e)))?;
    Ok(QuicDataPlane::with_endpoint(
        conn, endpoint, key, session_id,
    ))
}

// ── Connection setup (dev/self-signed, mirrors aftp::transport) ──────────────

/// Build a server `Endpoint` bound to `addr` with a self-signed dev cert and
/// unreliable datagrams enabled. Development/lab helper — production would carry
/// the datagram plane over the same authenticated QUIC connection as the
/// control plane rather than a fresh self-signed one.
pub fn dev_server_endpoint(addr: std::net::SocketAddr) -> AftResult<quinn::Endpoint> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| AftError::Other(format!("QUIC cert gen: {}", e)))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = quinn::ServerConfig::with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
    .map_err(|e| AftError::Other(format!("QUIC server config: {}", e)))?;
    server_config.transport = Arc::new(datagram_transport());

    quinn::Endpoint::server(server_config, addr)
        .map_err(|e| AftError::Other(format!("QUIC server endpoint: {}", e)))
}

/// Build a client `Endpoint` that trusts the dev cert (insecure verifier) with
/// unreliable datagrams enabled. Development/lab helper.
pub fn dev_client_endpoint() -> AftResult<quinn::Endpoint> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| AftError::Other(format!("QUIC client config: {}", e)))?,
    ));
    client_config.transport_config(Arc::new(datagram_transport()));

    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| AftError::Other(format!("QUIC bind: {}", e)))?,
    )
    .map_err(|e| AftError::Other(format!("QUIC client endpoint: {}", e)))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// A transport config that enables incoming datagrams with a generous receive
/// buffer — a fountain sender bursts, so an undersized datagram buffer drops
/// symbols inside the receiver, the same self-inflicted loss the UDP plane
/// sizes its socket buffer to avoid.
fn datagram_transport() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    t.datagram_send_buffer_size(8 * 1024 * 1024);
    t
}

/// Certificate verifier that accepts anything — for the self-signed dev
/// endpoints only, exactly as `aftp::transport::InsecureQuicVerifier`.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const SESSION: u64 = 0x0f0e_0d0c_0b0a_0908;

    /// Stand up loopback QUIC endpoints, connect them, and return a data plane
    /// for each end. Each plane anchors its own endpoint so the connections
    /// keep being driven for the life of the planes.
    async fn loopback(key: Option<Vec<u8>>) -> (QuicDataPlane, QuicDataPlane) {
        let server_ep = dev_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let saddr = server_ep.local_addr().unwrap();
        let client_ep = dev_client_endpoint().unwrap();

        let connecting = client_ep.connect(saddr, "localhost").unwrap();
        let accept_ep = server_ep.clone();
        let (server_conn, client_conn) = tokio::join!(
            async move { accept_ep.accept().await.unwrap().await.unwrap() },
            async move { connecting.await.unwrap() },
        );

        (
            QuicDataPlane::with_endpoint(server_conn, server_ep, key.clone(), SESSION),
            QuicDataPlane::with_endpoint(client_conn, client_ep, key, SESSION),
        )
    }

    #[tokio::test]
    async fn symbol_round_trips_authenticated() {
        let (server, client) = loopback(Some(KEY.to_vec())).await;
        client.send(42, SESSION, b"the-symbol").await.unwrap();
        let (block_id, payload) = server.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 42);
        assert_eq!(payload, b"the-symbol");
    }

    #[tokio::test]
    async fn symbol_round_trips_unauthenticated() {
        let (server, client) = loopback(None).await;
        client.send(7, SESSION, b"plain").await.unwrap();
        let (block_id, payload) = server.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 7);
        assert_eq!(payload, b"plain");
    }

    /// A datagram for another session must be dropped, not fed to this
    /// transfer's decoder — the same guarantee the UDP plane makes.
    #[tokio::test]
    async fn foreign_session_is_dropped() {
        let (server, client) = loopback(Some(KEY.to_vec())).await;
        client.send(1, SESSION, b"wrong-session").await.unwrap();
        // The receiver expects a different session, so the one datagram it
        // reads is discarded and it reports nothing usable.
        assert!(server.recv(SESSION ^ 0xFF).await.unwrap().is_none());
    }

    /// A sender using the wrong key must not be able to inject symbols: the
    /// correctly-keyed receiver drops the forged datagram (returns `None`),
    /// then still accepts a genuine one — the envelope's authentication holds
    /// regardless of the carrier underneath it.
    #[tokio::test]
    async fn forged_symbol_is_rejected() {
        let (server, client) = loopback(Some(KEY.to_vec())).await;

        // Same client connection, but keyed wrongly: the datagram is delivered
        // by QUIC but must fail the envelope's GCM check on the server.
        let attacker = QuicDataPlane::new(
            client.conn.clone(),
            Some(b"ffffffffffffffffffffffffffffffff".to_vec()),
            SESSION,
        );
        attacker.send(1, SESSION, b"forged").await.unwrap();
        assert!(
            server.recv(SESSION).await.unwrap().is_none(),
            "forged datagram must not verify"
        );

        // The receiver still works afterwards with a genuine symbol.
        client.send(3, SESSION, b"after-forgery").await.unwrap();
        let (block_id, payload) = server.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 3);
        assert_eq!(payload, b"after-forgery");
    }

    #[tokio::test]
    async fn reports_a_datagram_ceiling() {
        let (server, _client) = loopback(None).await;
        // With datagrams enabled on both ends the path must admit some size.
        assert!(server.max_datagram_size().unwrap_or(0) > 0);
    }
}
