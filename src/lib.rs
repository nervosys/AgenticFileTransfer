//! # AFT — Agentic File Transfer
//!
//! A high-performance, protocol-agnostic file transfer library designed
//! for both human operators and AI agents. Supports HTTP/HTTPS, FTP, SFTP,
//! S3, WebDAV, Azure Blob, GCS, SMB, and custom protocols via plugins.
//!
//! Provides quantum-resistant encryption (Kyber1024 + AES-256-GCM),
//! DoD classification handling, neural network cipher research, and
//! structured JSON output for agentic workflows.
//!
//! # Quick Start
//!
//! ```no_run
//! use aft::engine::{TransferConfig, download};
//! use aft::protocols::{resolve_protocol, ProtocolOptions};
//! ```

pub mod aftp;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod protocols;
pub mod sync;

// Internal modules — exposed for integration testing only
#[doc(hidden)]
pub mod audit;
#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod history;
#[doc(hidden)]
pub mod ontology;
#[doc(hidden)]
pub mod output;
#[doc(hidden)]
pub mod plugins;
#[doc(hidden)]
pub mod telemetry;

// Convenience re-exports
pub use engine::{TransferConfig, TransferResult};
pub use error::{AftError, AftResult};
pub use protocols::{ProtocolHandler, ProtocolOptions};
