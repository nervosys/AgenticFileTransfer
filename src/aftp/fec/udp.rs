// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! UDP data plane: the socket that carries fountain symbols.
//!
//! This is deliberately thin. There is no retransmission, no ordering, no
//! acknowledgement, and no connection state — a datagram either arrives or it
//! does not, and the code layer above decides whether enough of them have.
//! Everything this module does is bounded by one `send_to`/`recv_from`.
//!
//! ## Socket sizing
//!
//! The receive buffer matters more here than on a TCP socket. A fountain
//! sender paces a burst at the bottleneck rate with no window to hold it back,
//! so if the kernel's receive queue is smaller than a burst, symbols are
//! dropped *inside the receiver* — loss we paid to transmit and then inflicted
//! on ourselves. We ask for a large buffer and proceed regardless if the OS
//! declines; over-asking is harmless, under-asking is not.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::{AftError, AftResult};

use super::envelope::{Envelope, DEFAULT_MTU};

/// Requested socket buffer for the data plane (8 MiB).
const DATA_PLANE_SOCK_BUF: u32 = 8 * 1024 * 1024;

/// Largest datagram we will ever read. Sized above the MTU so an oversized
/// datagram is detected and rejected rather than silently truncated.
const RECV_BUF: usize = 65_536;

/// One end of the fountain data plane.
pub struct DataPlane {
    socket: UdpSocket,
    key: Option<Vec<u8>>,
    mtu: u16,
    /// Session this socket belongs to. Datagrams carrying any other session id
    /// are discarded, so a stale or crossed transfer cannot feed our decoders.
    session_id: u64,
}

impl DataPlane {
    /// Bind a data-plane socket. Pass port 0 to let the OS choose, then read
    /// it back with [`local_addr`](Self::local_addr) to put in the accept.
    pub async fn bind(addr: &str, key: Option<Vec<u8>>) -> AftResult<Self> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| AftError::Other(format!("FEC UDP bind {}: {}", addr, e)))?;
        tune_udp_socket(&socket);
        Ok(Self {
            socket,
            key,
            mtu: DEFAULT_MTU,
            session_id: 0,
        })
    }

    /// Bind a socket already associated with a negotiated session.
    pub async fn bind_for_session(
        addr: &str,
        key: Option<Vec<u8>>,
        session_id: u64,
    ) -> AftResult<Self> {
        let mut plane = Self::bind(addr, key).await?;
        plane.session_id = session_id;
        Ok(plane)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = session_id;
    }

    pub fn local_addr(&self) -> AftResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| AftError::Other(format!("FEC UDP local_addr: {}", e)))
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }

    /// Pin the socket to one peer so later sends need no address and stray
    /// datagrams from other hosts are filtered by the kernel.
    pub async fn connect(&self, peer: SocketAddr) -> AftResult<()> {
        self.socket
            .connect(peer)
            .await
            .map_err(|e| AftError::Other(format!("FEC UDP connect {}: {}", peer, e)))
    }

    /// Send one symbol to the connected peer.
    pub async fn send(&self, block_id: u32, session_id: u64, symbol: &[u8]) -> AftResult<usize> {
        let wire =
            Envelope::new(session_id, block_id, symbol.to_vec()).encode(self.key.as_deref())?;
        self.socket
            .send(&wire)
            .await
            .map_err(|e| AftError::Other(format!("FEC UDP send: {}", e)))
    }

    /// Send one symbol to an explicit address (before `connect`).
    pub async fn send_to(
        &self,
        peer: SocketAddr,
        block_id: u32,
        session_id: u64,
        symbol: &[u8],
    ) -> AftResult<usize> {
        let wire =
            Envelope::new(session_id, block_id, symbol.to_vec()).encode(self.key.as_deref())?;
        self.socket
            .send_to(&wire, peer)
            .await
            .map_err(|e| AftError::Other(format!("FEC UDP send_to {}: {}", peer, e)))
    }

    /// Receive and verify one symbol.
    ///
    /// Returns `Ok(None)` for a datagram that fails verification or belongs to
    /// another session. That is deliberately *not* an error: on a hostile or
    /// noisy network, junk arriving on the socket is expected, and a receiver
    /// that aborted on the first bad datagram would be trivially deniable.
    /// Genuine socket failures still surface as `Err`.
    pub async fn recv(&self, expect_session: u64) -> AftResult<Option<(u32, Vec<u8>, SocketAddr)>> {
        let mut buf = vec![0u8; RECV_BUF];
        let (n, from) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| AftError::Other(format!("FEC UDP recv: {}", e)))?;
        buf.truncate(n);

        match Envelope::decode(&buf, self.key.as_deref()) {
            Ok(env) if env.session_id == expect_session => {
                Ok(Some((env.block_id, env.payload, from)))
            }
            // Wrong session or unverifiable: drop it and keep listening.
            _ => Ok(None),
        }
    }
}

/// Enlarge the data-plane socket buffers. Best effort — a failure here costs
/// throughput, not correctness, so we do not surface it.
fn tune_udp_socket(socket: &UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let buf = DATA_PLANE_SOCK_BUF as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let sock = socket.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
        let buf = DATA_PLANE_SOCK_BUF as i32;
        unsafe {
            windows_sys::Win32::Networking::WinSock::setsockopt(
                sock,
                windows_sys::Win32::Networking::WinSock::SOL_SOCKET,
                windows_sys::Win32::Networking::WinSock::SO_RCVBUF,
                &buf as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
            windows_sys::Win32::Networking::WinSock::setsockopt(
                sock,
                windows_sys::Win32::Networking::WinSock::SOL_SOCKET,
                windows_sys::Win32::Networking::WinSock::SO_SNDBUF,
                &buf as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = socket;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const SESSION: u64 = 0x1234_5678_9abc_def0;

    async fn pair(key: Option<Vec<u8>>) -> (DataPlane, DataPlane) {
        let a = DataPlane::bind("127.0.0.1:0", key.clone()).await.unwrap();
        let b = DataPlane::bind("127.0.0.1:0", key).await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn symbol_round_trips_authenticated() {
        let (tx, rx) = pair(Some(KEY.to_vec())).await;
        tx.send(42, SESSION, b"the-symbol").await.unwrap();
        let (block_id, payload, _) = rx.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 42);
        assert_eq!(payload, b"the-symbol");
    }

    #[tokio::test]
    async fn symbol_round_trips_unauthenticated() {
        let (tx, rx) = pair(None).await;
        tx.send(7, SESSION, b"plain").await.unwrap();
        let (block_id, payload, _) = rx.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 7);
        assert_eq!(payload, b"plain");
    }

    /// A datagram for another session must be dropped, not mixed into this
    /// transfer's decoder.
    #[tokio::test]
    async fn foreign_session_is_dropped() {
        let (tx, rx) = pair(Some(KEY.to_vec())).await;
        tx.send(1, SESSION, b"wrong-session").await.unwrap();
        assert!(rx.recv(SESSION ^ 0xFF).await.unwrap().is_none());
    }

    /// Junk on the socket must be discarded quietly rather than aborting the
    /// transfer — otherwise anyone who can reach the port can deny service.
    #[tokio::test]
    async fn unverifiable_datagram_is_dropped_not_fatal() {
        let (tx, rx) = pair(Some(KEY.to_vec())).await;
        // Raw garbage straight onto the wire, bypassing the envelope encoder.
        tx.socket
            .send(b"not a valid envelope at all")
            .await
            .unwrap();
        assert!(rx.recv(SESSION).await.unwrap().is_none());

        // The receiver still works afterwards.
        tx.send(3, SESSION, b"after-junk").await.unwrap();
        let (block_id, payload, _) = rx.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 3);
        assert_eq!(payload, b"after-junk");
    }

    /// A sender using the wrong key must not be able to inject symbols.
    #[tokio::test]
    async fn forged_symbol_is_rejected() {
        let rx = DataPlane::bind("127.0.0.1:0", Some(KEY.to_vec()))
            .await
            .unwrap();
        let attacker = DataPlane::bind(
            "127.0.0.1:0",
            Some(b"ffffffffffffffffffffffffffffffff".to_vec()),
        )
        .await
        .unwrap();
        attacker.connect(rx.local_addr().unwrap()).await.unwrap();
        attacker.send(1, SESSION, b"forged").await.unwrap();
        assert!(rx.recv(SESSION).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn full_size_symbol_fits_one_datagram() {
        let (tx, rx) = pair(Some(KEY.to_vec())).await;
        let max = super::super::envelope::max_symbol_size(DEFAULT_MTU, true) as usize;
        let symbol = vec![0xAB; max + 4]; // + raptorq PayloadId
        let sent = tx.send(0, SESSION, &symbol).await.unwrap();
        assert_eq!(sent, DEFAULT_MTU as usize);
        let (_, payload, _) = rx.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(payload, symbol);
    }

    #[tokio::test]
    async fn send_to_works_before_connect() {
        let rx = DataPlane::bind("127.0.0.1:0", None).await.unwrap();
        let tx = DataPlane::bind("127.0.0.1:0", None).await.unwrap();
        tx.send_to(rx.local_addr().unwrap(), 9, SESSION, b"addressed")
            .await
            .unwrap();
        let (block_id, payload, _) = rx.recv(SESSION).await.unwrap().unwrap();
        assert_eq!(block_id, 9);
        assert_eq!(payload, b"addressed");
    }
}
