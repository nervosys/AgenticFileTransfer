//! # AFT — Agentic File Transfer
//!
//! A high-performance, protocol-agnostic file transfer library designed
//! for both human operators and AI agents. Supports HTTP/HTTPS, FTP, SFTP,
//! S3, WebDAV, Azure Blob, GCS, SMB, and custom protocols via plugins.
//!
//! Provides quantum-resistant encryption (Kyber1024 + AES-256-GCM),
//! DoD classification handling, neural network cipher research, and
//! structured JSON output for agentic workflows.

pub mod aftp;
pub mod audit;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod history;
pub mod ontology;
pub mod output;
pub mod plugins;
pub mod protocols;
pub mod telemetry;
