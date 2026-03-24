#![allow(dead_code)]
//! AFTP multiplexed streams: concurrent transfers over a single connection.
//!
//! A MuxSession wraps a single TCP/TLS connection and allows multiple
//! concurrent streams (each with their own GET/PUT/HEAD/LIST exchange).
//! Stream IDs are assigned by the client (odd) or server (even).
//!
//! Wire format for mux frames:
//! - STREAM_OPEN:  `[stream_id:2]`
//! - STREAM_CLOSE: `[stream_id:2]`
//! - STREAM_DATA:  `[stream_id:2][inner_frame_type:1][data_len:4][data:N]`

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{mpsc, Mutex};

use crate::error::{AftError, AftResult};

use super::frame::*;

/// A demuxed frame delivered to a stream handler.
pub struct MuxFrame {
    pub frame_type: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

/// Client-side multiplexer over a single connection.
///
/// Spawns a reader task that demultiplexes incoming frames by stream ID
/// and routes them to per-stream channels.
pub struct MuxSession {
    writer: Arc<Mutex<BufWriter<Box<dyn AsyncWrite + Unpin + Send>>>>,
    streams: Arc<Mutex<HashMap<u16, mpsc::Sender<MuxFrame>>>>,
    next_stream_id: Arc<Mutex<u16>>,
    max_frame_size: u32,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl MuxSession {
    /// Create a new multiplexed session.
    /// `reader` and `writer` should be from a connected and handshaken AFTP connection.
    pub fn new(
        reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
        writer: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>,
        max_frame_size: u32,
    ) -> Self {
        let streams: Arc<Mutex<HashMap<u16, mpsc::Sender<MuxFrame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let writer = Arc::new(Mutex::new(writer));

        let streams_clone = Arc::clone(&streams);
        let _reader_handle = tokio::spawn(async move {
            Self::reader_loop(reader, streams_clone, max_frame_size).await;
        });

        Self {
            writer,
            streams,
            next_stream_id: Arc::new(Mutex::new(1)), // client uses odd IDs
            max_frame_size,
            _reader_handle,
        }
    }

    /// Open a new multiplexed stream. Returns (stream_id, receiver).
    pub async fn open_stream(&self) -> AftResult<(u16, MuxStream)> {
        let mut id = self.next_stream_id.lock().await;
        let stream_id = *id;
        *id = id.wrapping_add(2); // client uses odd IDs
        drop(id);

        let (tx, rx) = mpsc::channel(64);
        self.streams.lock().await.insert(stream_id, tx);

        // Send STREAM_OPEN
        let payload = build_stream_open(stream_id);
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, &Frame::new(FRAME_STREAM_OPEN, payload)).await?;
        w.flush().await?;
        drop(w);

        Ok((
            stream_id,
            MuxStream {
                stream_id,
                writer: Arc::clone(&self.writer),
                receiver: rx,
                max_frame_size: self.max_frame_size,
            },
        ))
    }

    /// Close a stream.
    pub async fn close_stream(&self, stream_id: u16) -> AftResult<()> {
        self.streams.lock().await.remove(&stream_id);

        let payload = build_stream_close(stream_id);
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, &Frame::new(FRAME_STREAM_CLOSE, payload)).await?;
        w.flush().await?;
        Ok(())
    }

    async fn reader_loop(
        mut reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
        streams: Arc<Mutex<HashMap<u16, mpsc::Sender<MuxFrame>>>>,
        max_frame_size: u32,
    ) {
        loop {
            let frame = match read_frame(&mut reader, max_frame_size + 1024).await {
                Ok(f) => f,
                Err(_) => break, // connection closed
            };

            match frame.frame_type {
                FRAME_STREAM_DATA => {
                    if let Ok(sd) = parse_stream_data(&frame.payload) {
                        let streams = streams.lock().await;
                        if let Some(tx) = streams.get(&sd.stream_id) {
                            let _ = tx
                                .send(MuxFrame {
                                    frame_type: sd.inner_frame_type,
                                    flags: frame.flags,
                                    payload: sd.data,
                                })
                                .await;
                        }
                    }
                }
                FRAME_STREAM_CLOSE => {
                    if let Ok(sc) = parse_stream_close(&frame.payload) {
                        streams.lock().await.remove(&sc.stream_id);
                    }
                }
                _ => {
                    // Non-mux frame on stream 0 (control channel) — route to stream 0
                    let streams = streams.lock().await;
                    if let Some(tx) = streams.get(&0) {
                        let _ = tx
                            .send(MuxFrame {
                                frame_type: frame.frame_type,
                                flags: frame.flags,
                                payload: frame.payload,
                            })
                            .await;
                    }
                }
            }
        }
    }
}

/// A single multiplexed stream within a MuxSession.
pub struct MuxStream {
    pub stream_id: u16,
    writer: Arc<Mutex<BufWriter<Box<dyn AsyncWrite + Unpin + Send>>>>,
    receiver: mpsc::Receiver<MuxFrame>,
    #[allow(dead_code)]
    max_frame_size: u32,
}

impl MuxStream {
    /// Send a frame on this stream.
    pub async fn send_frame(&self, frame_type: u8, payload: &[u8]) -> AftResult<()> {
        let sd_payload = build_stream_data(self.stream_id, frame_type, payload);
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, &Frame::new(FRAME_STREAM_DATA, sd_payload)).await?;
        w.flush().await?;
        Ok(())
    }

    /// Receive the next frame on this stream.
    pub async fn recv_frame(&mut self) -> AftResult<MuxFrame> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| AftError::ConnectionFailed("Stream closed".into()))
    }
}

/// Server-side multiplexed connection handler.
///
/// Spawns separate tasks for each incoming stream, routing frames
/// between the shared connection and per-stream handlers.
pub struct MuxServer {
    streams: Arc<Mutex<HashMap<u16, mpsc::Sender<MuxFrame>>>>,
    writer: Arc<Mutex<BufWriter<Box<dyn AsyncWrite + Unpin + Send>>>>,
}

impl MuxServer {
    /// Run the mux server on a connected reader/writer pair.
    /// `stream_handler` is called for each opened stream with (stream_id, MuxStream).
    pub async fn run<R, W, F, Fut>(
        rd: R,
        wr: W,
        max_frame_size: u32,
        stream_handler: F,
    ) -> AftResult<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        F: Fn(u16, MuxServerStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = AftResult<()>> + Send + 'static,
    {
        let writer: Arc<Mutex<BufWriter<Box<dyn AsyncWrite + Unpin + Send>>>> =
            Arc::new(Mutex::new(BufWriter::new(Box::new(wr))));
        let streams: Arc<Mutex<HashMap<u16, mpsc::Sender<MuxFrame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let handler = Arc::new(stream_handler);

        let mut reader = BufReader::new(rd);

        loop {
            let frame = match read_frame(&mut reader, max_frame_size + 1024).await {
                Ok(f) => f,
                Err(_) => break,
            };

            match frame.frame_type {
                FRAME_STREAM_OPEN => {
                    if let Ok(so) = parse_stream_open(&frame.payload) {
                        let (tx, rx) = mpsc::channel(64);
                        streams.lock().await.insert(so.stream_id, tx);

                        let mux_stream = MuxServerStream {
                            stream_id: so.stream_id,
                            writer: Arc::clone(&writer),
                            receiver: rx,
                        };

                        let h = Arc::clone(&handler);
                        let sid = so.stream_id;
                        let streams_clone = Arc::clone(&streams);
                        tokio::spawn(async move {
                            let _ = h(sid, mux_stream).await;
                            streams_clone.lock().await.remove(&sid);
                        });
                    }
                }
                FRAME_STREAM_DATA => {
                    if let Ok(sd) = parse_stream_data(&frame.payload) {
                        let streams = streams.lock().await;
                        if let Some(tx) = streams.get(&sd.stream_id) {
                            let _ = tx
                                .send(MuxFrame {
                                    frame_type: sd.inner_frame_type,
                                    flags: frame.flags,
                                    payload: sd.data,
                                })
                                .await;
                        }
                    }
                }
                FRAME_STREAM_CLOSE => {
                    if let Ok(sc) = parse_stream_close(&frame.payload) {
                        streams.lock().await.remove(&sc.stream_id);
                    }
                }
                _ => {
                    // Non-mux frames — handle as legacy single-stream
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Server-side stream within a multiplexed connection.
pub struct MuxServerStream {
    pub stream_id: u16,
    writer: Arc<Mutex<BufWriter<Box<dyn AsyncWrite + Unpin + Send>>>>,
    receiver: mpsc::Receiver<MuxFrame>,
}

impl MuxServerStream {
    /// Send a frame on this stream.
    pub async fn send_frame(&self, frame_type: u8, payload: &[u8]) -> AftResult<()> {
        let sd_payload = build_stream_data(self.stream_id, frame_type, payload);
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, &Frame::new(FRAME_STREAM_DATA, sd_payload)).await?;
        w.flush().await?;
        Ok(())
    }

    /// Receive the next frame on this stream.
    pub async fn recv_frame(&mut self) -> AftResult<MuxFrame> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| AftError::ConnectionFailed("Stream closed".into()))
    }
}
