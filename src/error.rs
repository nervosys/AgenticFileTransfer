// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Error types for the AFT library.
//!
//! Provides a unified error enum covering all protocol, I/O, and
//! application-level failures, with automatic conversion from
//! `std::io::Error` and `reqwest::Error`.

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AftError {
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Timeout after {0}s")]
    Timeout(u64),

    #[error("Resume not supported by remote server")]
    ResumeNotSupported,

    #[error("Server returned HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Other(String),
}

pub type AftResult<T> = Result<T, AftError>;
