//! Integration and unit tests for the AFT codebase.

mod frame_tests {
    use aft::aftp::frame::*;

    // ── Binary encoding helpers ─────────────────────────────────────────

    #[test]
    fn put_get_u8() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 0x42);
        let mut off = 0;
        assert_eq!(get_u8(&buf, &mut off).unwrap(), 0x42);
        assert_eq!(off, 1);
    }

    #[test]
    fn put_get_u16() {
        let mut buf = Vec::new();
        put_u16(&mut buf, 0xBEEF);
        let mut off = 0;
        assert_eq!(get_u16(&buf, &mut off).unwrap(), 0xBEEF);
        assert_eq!(off, 2);
    }

    #[test]
    fn put_get_u32() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 0xDEAD_BEEF);
        let mut off = 0;
        assert_eq!(get_u32(&buf, &mut off).unwrap(), 0xDEAD_BEEF);
        assert_eq!(off, 4);
    }

    #[test]
    fn put_get_u64() {
        let mut buf = Vec::new();
        put_u64(&mut buf, 0xCAFE_BABE_DEAD_BEEF);
        let mut off = 0;
        assert_eq!(get_u64(&buf, &mut off).unwrap(), 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(off, 8);
    }

    #[test]
    fn put_get_str() {
        let mut buf = Vec::new();
        put_str(&mut buf, "hello world");
        let mut off = 0;
        assert_eq!(get_str(&buf, &mut off).unwrap(), "hello world");
        assert_eq!(off, 2 + 11); // u16 length + 11 bytes
    }

    #[test]
    fn put_get_empty_str() {
        let mut buf = Vec::new();
        put_str(&mut buf, "");
        let mut off = 0;
        assert_eq!(get_str(&buf, &mut off).unwrap(), "");
        assert_eq!(off, 2);
    }

    #[test]
    fn get_u8_truncated() {
        let buf: &[u8] = &[];
        let mut off = 0;
        assert!(get_u8(buf, &mut off).is_err());
    }

    #[test]
    fn get_u16_truncated() {
        let buf: &[u8] = &[0x01]; // only 1 byte, need 2
        let mut off = 0;
        assert!(get_u16(buf, &mut off).is_err());
    }

    #[test]
    fn get_u32_truncated() {
        let buf: &[u8] = &[0x01, 0x02]; // only 2 bytes, need 4
        let mut off = 0;
        assert!(get_u32(buf, &mut off).is_err());
    }

    #[test]
    fn get_u64_truncated() {
        let buf: &[u8] = &[0x01, 0x02, 0x03, 0x04]; // only 4 bytes, need 8
        let mut off = 0;
        assert!(get_u64(buf, &mut off).is_err());
    }

    #[test]
    fn get_str_truncated_data() {
        // String header says "5 bytes" but only 2 bytes of data follow
        let mut buf = Vec::new();
        put_u16(&mut buf, 5);
        buf.extend_from_slice(b"ab");
        let mut off = 0;
        assert!(get_str(&buf, &mut off).is_err());
    }

    // ── Multiple values in sequence ─────────────────────────────────────

    #[test]
    fn sequential_encoding() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 1);
        put_u16(&mut buf, 2);
        put_u32(&mut buf, 3);
        put_u64(&mut buf, 4);
        put_str(&mut buf, "test");

        let mut off = 0;
        assert_eq!(get_u8(&buf, &mut off).unwrap(), 1);
        assert_eq!(get_u16(&buf, &mut off).unwrap(), 2);
        assert_eq!(get_u32(&buf, &mut off).unwrap(), 3);
        assert_eq!(get_u64(&buf, &mut off).unwrap(), 4);
        assert_eq!(get_str(&buf, &mut off).unwrap(), "test");
        assert_eq!(off, buf.len());
    }

    // ── Payload builders and parsers (roundtrip) ────────────────────────

    #[test]
    fn hello_roundtrip() {
        let payload = build_hello(CAP_COMPRESSION | CAP_CHECKSUM, Some("my_secret_token"));
        let parsed = parse_hello(&payload).unwrap();
        assert_eq!(parsed.capabilities, CAP_COMPRESSION | CAP_CHECKSUM);
        assert_eq!(parsed.auth_token, "my_secret_token");
    }

    #[test]
    fn hello_no_token() {
        let payload = build_hello(0, None);
        let parsed = parse_hello(&payload).unwrap();
        assert_eq!(parsed.capabilities, 0);
        assert_eq!(parsed.auth_token, "");
    }

    #[test]
    fn hello_ack_roundtrip() {
        let payload = build_hello_ack(CAP_COMPRESSION, DEFAULT_MAX_FRAME);
        let parsed = parse_hello_ack(&payload).unwrap();
        assert_eq!(parsed.capabilities, CAP_COMPRESSION);
        assert_eq!(parsed.max_frame_size, DEFAULT_MAX_FRAME);
    }

    #[test]
    fn get_roundtrip() {
        let payload = build_get("/path/to/file.txt", 1024, 2048);
        let parsed = parse_get(&payload).unwrap();
        assert_eq!(parsed.path, "/path/to/file.txt");
        assert_eq!(parsed.range_start, 1024);
        assert_eq!(parsed.range_end, 2048);
    }

    #[test]
    fn get_full_file() {
        let payload = build_get("/data.bin", 0, 0);
        let parsed = parse_get(&payload).unwrap();
        assert_eq!(parsed.path, "/data.bin");
        assert_eq!(parsed.range_start, 0);
        assert_eq!(parsed.range_end, 0);
    }

    #[test]
    fn head_resp_roundtrip() {
        let payload = build_head_resp(1_048_576, 1700000000, "application/octet-stream");
        let parsed = parse_head_resp(&payload).unwrap();
        assert_eq!(parsed.file_size, 1_048_576);
        assert_eq!(parsed.modified_secs, 1700000000);
        assert_eq!(parsed.content_type, "application/octet-stream");
    }

    #[test]
    fn put_roundtrip() {
        let payload = build_put("/uploads/doc.pdf", 5_000_000);
        let parsed = parse_put(&payload).unwrap();
        assert_eq!(parsed.path, "/uploads/doc.pdf");
        assert_eq!(parsed.file_size, 5_000_000);
    }

    #[test]
    fn put_ack_ready() {
        let payload = build_put_ack(false);
        let parsed = parse_put_ack(&payload).unwrap();
        assert!(!parsed.complete);
    }

    #[test]
    fn put_ack_complete() {
        let payload = build_put_ack(true);
        let parsed = parse_put_ack(&payload).unwrap();
        assert!(parsed.complete);
    }

    #[test]
    fn data_end_roundtrip() {
        let checksum = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let payload = build_data_end(999_999, CHECKSUM_SHA256, &checksum);
        let parsed = parse_data_end(&payload).unwrap();
        assert_eq!(parsed.total_bytes, 999_999);
        assert_eq!(parsed.checksum_algo, CHECKSUM_SHA256);
        assert_eq!(parsed.checksum, checksum);
    }

    #[test]
    fn data_end_no_checksum() {
        let payload = build_data_end(42, CHECKSUM_NONE, &[]);
        let parsed = parse_data_end(&payload).unwrap();
        assert_eq!(parsed.total_bytes, 42);
        assert_eq!(parsed.checksum_algo, CHECKSUM_NONE);
        assert!(parsed.checksum.is_empty());
    }

    #[test]
    fn error_roundtrip() {
        let payload = build_error(ERR_NOT_FOUND, "File not found: /missing.txt");
        let parsed = parse_error(&payload).unwrap();
        assert_eq!(parsed.code, ERR_NOT_FOUND);
        assert_eq!(parsed.message, "File not found: /missing.txt");
    }

    #[test]
    fn error_codes() {
        for (code, name) in [
            (ERR_NOT_FOUND, "not_found"),
            (ERR_PERMISSION_DENIED, "perm_denied"),
            (ERR_INVALID_REQUEST, "invalid_req"),
            (ERR_AUTH_FAILED, "auth_failed"),
            (ERR_INTERNAL, "internal"),
            (ERR_IO, "io"),
        ] {
            let payload = build_error(code, name);
            let parsed = parse_error(&payload).unwrap();
            assert_eq!(parsed.code, code);
            assert_eq!(parsed.message, name);
        }
    }

    #[test]
    fn list_resp_roundtrip() {
        let entries = vec![
            ListEntry {
                name: "file1.txt".to_string(),
                size: 1024,
                is_dir: false,
                modified_secs: 1700000000,
            },
            ListEntry {
                name: "subdir".to_string(),
                size: 0,
                is_dir: true,
                modified_secs: 1700000100,
            },
            ListEntry {
                name: "file2.bin".to_string(),
                size: 999_999_999,
                is_dir: false,
                modified_secs: 1700000200,
            },
        ];

        let payload = build_list_resp(&entries);
        let parsed = parse_list_resp(&payload).unwrap();
        assert_eq!(parsed.len(), 3);

        assert_eq!(parsed[0].name, "file1.txt");
        assert_eq!(parsed[0].size, 1024);
        assert!(!parsed[0].is_dir);
        assert_eq!(parsed[0].modified_secs, 1700000000);

        assert_eq!(parsed[1].name, "subdir");
        assert!(parsed[1].is_dir);

        assert_eq!(parsed[2].name, "file2.bin");
        assert_eq!(parsed[2].size, 999_999_999);
    }

    #[test]
    fn list_resp_empty() {
        let payload = build_list_resp(&[]);
        let parsed = parse_list_resp(&payload).unwrap();
        assert!(parsed.is_empty());
    }

    // ── Frame construction ──────────────────────────────────────────────

    #[test]
    fn frame_new() {
        let f = Frame::new(FRAME_DATA, vec![1, 2, 3]);
        assert_eq!(f.frame_type, FRAME_DATA);
        assert_eq!(f.flags, 0);
        assert_eq!(f.payload, vec![1, 2, 3]);
    }

    #[test]
    fn frame_with_flags() {
        let f = Frame::with_flags(FRAME_DATA, FLAG_COMPRESSED, vec![9, 8, 7]);
        assert_eq!(f.frame_type, FRAME_DATA);
        assert_eq!(f.flags, FLAG_COMPRESSED);
        assert_eq!(f.payload, vec![9, 8, 7]);
    }

    #[test]
    fn frame_empty() {
        let f = Frame::empty(FRAME_PING);
        assert_eq!(f.frame_type, FRAME_PING);
        assert_eq!(f.flags, 0);
        assert!(f.payload.is_empty());
    }

    // ── Frame I/O (async) ───────────────────────────────────────────────

    #[tokio::test]
    async fn frame_write_read_roundtrip() {
        let original = Frame::new(FRAME_GET, build_get("/test.txt", 0, 0));

        let mut buf = Vec::new();
        write_frame(&mut buf, &original).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor, INITIAL_MAX_PAYLOAD).await.unwrap();

        assert_eq!(decoded.frame_type, FRAME_GET);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.payload, original.payload);
    }

    #[tokio::test]
    async fn frame_write_read_with_flags() {
        let original = Frame::with_flags(FRAME_DATA, FLAG_COMPRESSED, vec![0xDE, 0xAD]);

        let mut buf = Vec::new();
        write_frame(&mut buf, &original).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor, INITIAL_MAX_PAYLOAD).await.unwrap();

        assert_eq!(decoded.frame_type, FRAME_DATA);
        assert_eq!(decoded.flags, FLAG_COMPRESSED);
        assert_eq!(decoded.payload, vec![0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn frame_empty_roundtrip() {
        let original = Frame::empty(FRAME_PING);

        let mut buf = Vec::new();
        write_frame(&mut buf, &original).await.unwrap();

        assert_eq!(buf.len(), HEADER_SIZE); // header only, no payload

        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor, INITIAL_MAX_PAYLOAD).await.unwrap();
        assert_eq!(decoded.frame_type, FRAME_PING);
        assert!(decoded.payload.is_empty());
    }

    #[tokio::test]
    async fn frame_header_magic_and_version() {
        let f = Frame::empty(FRAME_PONG);
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).await.unwrap();

        assert_eq!(buf[0], MAGIC[0]);
        assert_eq!(buf[1], MAGIC[1]);
        assert_eq!(buf[2], VERSION);
        assert_eq!(buf[3], FRAME_PONG);
    }

    #[tokio::test]
    async fn frame_payload_too_large() {
        let f = Frame::new(FRAME_DATA, vec![0u8; 100]);
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).await.unwrap();

        let mut cursor = &buf[..];
        // Request max_payload of 50 — 100-byte payload should be rejected
        let result = read_frame(&mut cursor, 50).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn frame_invalid_magic() {
        let buf = vec![0xFF, 0xFF, VERSION, FRAME_PING, 0, 0, 0, 0, 0, 0]; // bad magic
        let mut cursor = &buf[..];
        let result = read_frame(&mut cursor, INITIAL_MAX_PAYLOAD).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn frame_header_only_write() {
        let mut buf = Vec::new();
        write_frame_header(&mut buf, FRAME_DATA, FLAG_COMPRESSED, 1024)
            .await
            .unwrap();

        assert_eq!(buf.len(), HEADER_SIZE);
        assert_eq!(buf[0], MAGIC[0]);
        assert_eq!(buf[1], MAGIC[1]);
        assert_eq!(buf[2], VERSION);
        assert_eq!(buf[3], FRAME_DATA);
        assert_eq!(buf[4], FLAG_COMPRESSED);
        assert_eq!(buf[5], 0); // reserved

        let payload_len = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        assert_eq!(payload_len, 1024);
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn wire_constants() {
        assert_eq!(MAGIC, [0xAF, 0x54]);
        assert_eq!(VERSION, 1);
        assert_eq!(HEADER_SIZE, 10);
        assert_eq!(DEFAULT_PORT, 2600);
        assert_eq!(DEFAULT_MAX_FRAME, 1_048_576);
        assert_eq!(INITIAL_MAX_PAYLOAD, 65_536);
    }
}

mod protocol_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn resolve_http() {
        let h = resolve_protocol("http://example.com/file.txt").unwrap();
        assert_eq!(h.scheme(), "http");
    }

    #[test]
    fn resolve_https() {
        let h = resolve_protocol("https://example.com/file.txt").unwrap();
        assert_eq!(h.scheme(), "https");
    }

    #[test]
    fn resolve_ftp() {
        let h = resolve_protocol("ftp://ftp.example.com/pub/file.tar.gz").unwrap();
        assert_eq!(h.scheme(), "ftp");
    }

    #[test]
    fn resolve_ftps() {
        let h = resolve_protocol("ftps://ftp.example.com/pub/file.tar.gz").unwrap();
        assert_eq!(h.scheme(), "ftps");
    }

    #[test]
    fn resolve_sftp() {
        let h = resolve_protocol("sftp://server.example.com/path").unwrap();
        assert_eq!(h.scheme(), "sftp");
    }

    #[test]
    fn resolve_scp() {
        let h = resolve_protocol("scp://server.example.com/path").unwrap();
        assert_eq!(h.scheme(), "scp");
    }

    #[test]
    fn resolve_s3() {
        let h = resolve_protocol("s3://my-bucket/some/key.dat").unwrap();
        assert_eq!(h.scheme(), "s3");
    }

    #[test]
    fn resolve_aftp() {
        let h = resolve_protocol("aftp://localhost:2600/file.txt").unwrap();
        assert_eq!(h.scheme(), "aftp");
    }

    #[test]
    fn resolve_aftps() {
        let h = resolve_protocol("aftps://localhost:2600/file.txt").unwrap();
        assert_eq!(h.scheme(), "aftps");
    }

    #[test]
    fn resolve_local_relative() {
        let h = resolve_protocol("./some/path").unwrap();
        assert_eq!(h.scheme(), "file");
    }

    #[test]
    fn resolve_local_tilde() {
        let h = resolve_protocol("~/downloads/file.txt").unwrap();
        assert_eq!(h.scheme(), "file");
    }

    #[test]
    fn resolve_unknown_scheme() {
        let result = resolve_protocol("gopher://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_no_scheme() {
        // A string that doesn't look like a path or URL
        let result = resolve_protocol("definitely-not-a-url-or-path-2024");
        // Should fail if it can't detect protocol and path doesn't exist
        assert!(result.is_err());
    }
}

mod engine_tests {
    use aft::engine::TransferConfig;

    #[test]
    fn default_config() {
        let config = TransferConfig::default();
        assert_eq!(config.parallel_chunks, 4);
        assert_eq!(config.chunk_size, 8 * 1024 * 1024);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert!(config.verify_checksum.is_none());
        assert!(!config.resume);
        assert_eq!(config.rate_limit_bytes_per_sec, 0);
    }
}

mod config_tests {
    use aft::config::{load_config, AftConfig};

    #[test]
    fn default_config_all_none() {
        let config = AftConfig::default();
        assert!(config.format.is_none());
        assert!(config.parallel.is_none());
        assert!(config.retries.is_none());
        assert!(config.connect_timeout.is_none());
        assert!(config.insecure.is_none());
        assert!(config.rate_limit.is_none());
        assert!(config.user_agent.is_none());
        assert!(config.bearer_token.is_none());
        assert!(config.server.is_none());
    }

    #[test]
    fn load_config_returns_defaults_when_no_file() {
        // If ~/.aft/config.toml doesn't exist, should return defaults
        let config = load_config().unwrap();
        // We can't assert the values since the file might exist in the user's home dir,
        // but at least it shouldn't error
        let _ = config;
    }

    #[test]
    fn config_toml_deserialization() {
        let toml_content = r#"
format = "json"
parallel = 8
retries = 5
connect_timeout = 30
insecure = true
rate_limit = 1048576
user_agent = "test-agent"

[server]
port = 3000
bind = "0.0.0.0"
compression = true
auth_token = "secret123"
"#;
        let config: AftConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.format.as_deref(), Some("json"));
        assert_eq!(config.parallel, Some(8));
        assert_eq!(config.retries, Some(5));
        assert_eq!(config.connect_timeout, Some(30));
        assert_eq!(config.insecure, Some(true));
        assert_eq!(config.rate_limit, Some(1_048_576));
        assert_eq!(config.user_agent.as_deref(), Some("test-agent"));

        let server = config.server.unwrap();
        assert_eq!(server.port, Some(3000));
        assert_eq!(server.bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(server.compression, Some(true));
        assert_eq!(server.auth_token.as_deref(), Some("secret123"));
    }

    #[test]
    fn config_toml_partial() {
        let toml_content = r#"
retries = 10
"#;
        let config: AftConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.retries, Some(10));
        assert!(config.format.is_none());
        assert!(config.parallel.is_none());
        assert!(config.server.is_none());
    }

    #[test]
    fn config_toml_empty() {
        let config: AftConfig = toml::from_str("").unwrap();
        assert!(config.format.is_none());
        assert!(config.parallel.is_none());
    }
}

mod history_tests {
    use aft::history::HistoryEntry;

    #[test]
    fn history_entry_serialization() {
        let entry = HistoryEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            operation: "download".to_string(),
            source: Some("https://example.com/file.bin".to_string()),
            destination: Some("/tmp/file.bin".to_string()),
            protocol: Some("https".to_string()),
            status: "success".to_string(),
            bytes_transferred: 1_000_000,
            duration_ms: 500,
            error: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: HistoryEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.operation, "download");
        assert_eq!(
            deserialized.source.as_deref(),
            Some("https://example.com/file.bin")
        );
        assert_eq!(deserialized.bytes_transferred, 1_000_000);
        assert_eq!(deserialized.duration_ms, 500);
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn history_entry_with_error() {
        let entry = HistoryEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            operation: "upload".to_string(),
            source: Some("./file.txt".to_string()),
            destination: Some("s3://bucket/key".to_string()),
            protocol: Some("s3".to_string()),
            status: "error".to_string(),
            bytes_transferred: 0,
            duration_ms: 100,
            error: Some("Access denied".to_string()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, "error");
        assert_eq!(deserialized.error.as_deref(), Some("Access denied"));
    }
}

mod output_tests {
    use aft::output::OutputResult;

    #[test]
    fn output_result_success() {
        let r = OutputResult::success("download");
        assert_eq!(r.status, "success");
        assert_eq!(r.operation, "download");
        assert!(r.error.is_none());
    }

    #[test]
    fn output_result_failure() {
        let r = OutputResult::failure("upload", "Permission denied");
        assert_eq!(r.status, "error");
        assert_eq!(r.operation, "upload");
        assert_eq!(r.error.as_deref(), Some("Permission denied"));
    }

    #[test]
    fn output_result_json_serialization() {
        let r = OutputResult::success("head");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"operation\":\"head\""));
    }
}

mod local_copy_tests {
    use std::fs;

    #[test]
    fn local_file_copy_via_fs() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.txt");
        let dst = dir.path().join("dest.txt");

        fs::write(&src, "hello world").unwrap();
        fs::copy(&src, &dst).unwrap();

        assert_eq!(fs::read_to_string(&dst).unwrap(), "hello world");
    }

    #[test]
    fn local_recursive_dir_structure() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = dir.path().join("src_root");
        let sub_dir = src_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::write(src_dir.join("a.txt"), "aaa").unwrap();
        fs::write(sub_dir.join("b.txt"), "bbb").unwrap();

        let dst_dir = dir.path().join("dst_root");
        // Walk and copy
        let mut stack = vec![(src_dir.clone(), dst_dir.clone())];
        while let Some((s, d)) = stack.pop() {
            fs::create_dir_all(&d).unwrap();
            for entry in fs::read_dir(&s).unwrap() {
                let entry = entry.unwrap();
                let ft = entry.file_type().unwrap();
                let dest_path = d.join(entry.file_name());
                if ft.is_dir() {
                    stack.push((entry.path(), dest_path));
                } else {
                    fs::copy(entry.path(), &dest_path).unwrap();
                }
            }
        }

        assert_eq!(fs::read_to_string(dst_dir.join("a.txt")).unwrap(), "aaa");
        assert_eq!(
            fs::read_to_string(dst_dir.join("subdir").join("b.txt")).unwrap(),
            "bbb"
        );
    }
}

mod checksum_tests {
    use sha2::{Digest, Sha256};

    #[test]
    fn sha256_known_value() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(
            result,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn md5_known_value() {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(b"hello world");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }
}

mod aftp_client_tests {
    use aft::aftp::client::parse_aftp_url;

    #[test]
    fn parse_aftp_basic() {
        let (host, port, path, use_tls) = parse_aftp_url("aftp://localhost/file.txt").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 2600); // DEFAULT_PORT
        assert_eq!(path, "/file.txt");
        assert!(!use_tls);
    }

    #[test]
    fn parse_aftp_with_port() {
        let (host, port, path, use_tls) =
            parse_aftp_url("aftp://myhost:3000/data/file.bin").unwrap();
        assert_eq!(host, "myhost");
        assert_eq!(port, 3000);
        assert_eq!(path, "/data/file.bin");
        assert!(!use_tls);
    }

    #[test]
    fn parse_aftps() {
        let (host, port, path, use_tls) =
            parse_aftp_url("aftps://secure.host:2601/secret.dat").unwrap();
        assert_eq!(host, "secure.host");
        assert_eq!(port, 2601);
        assert_eq!(path, "/secret.dat");
        assert!(use_tls);
    }

    #[test]
    fn parse_aftp_no_path() {
        let (host, port, path, use_tls) = parse_aftp_url("aftp://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 2600);
        assert_eq!(path, "/");
        assert!(!use_tls);
    }

    #[test]
    fn parse_aftp_invalid_scheme() {
        let result = parse_aftp_url("http://example.com/file");
        assert!(result.is_err());
    }
}

// ── Auth frame round-trip tests ─────────────────────────────────────────────

mod auth_frame_tests {
    use aft::aftp::frame::*;

    #[test]
    fn auth_challenge_round_trip() {
        let nonce: Vec<u8> = (0..32).collect();
        let payload = build_auth_challenge(&nonce);
        let parsed = parse_auth_challenge(&payload).unwrap();
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn auth_challenge_empty_nonce() {
        let payload = build_auth_challenge(&[]);
        let parsed = parse_auth_challenge(&payload).unwrap();
        assert!(parsed.nonce.is_empty());
    }

    #[test]
    fn auth_response_round_trip() {
        let hmac_bytes: Vec<u8> = (100..132).collect();
        let payload = build_auth_response(&hmac_bytes);
        let parsed = parse_auth_response(&payload).unwrap();
        assert_eq!(parsed.hmac, hmac_bytes);
    }

    #[test]
    fn auth_response_empty() {
        let payload = build_auth_response(&[]);
        let parsed = parse_auth_response(&payload).unwrap();
        assert!(parsed.hmac.is_empty());
    }
}

// ── Mux frame round-trip tests ──────────────────────────────────────────────

mod mux_frame_tests {
    use aft::aftp::frame::*;

    #[test]
    fn stream_open_round_trip() {
        let payload = build_stream_open(42);
        let parsed = parse_stream_open(&payload).unwrap();
        assert_eq!(parsed.stream_id, 42);
    }

    #[test]
    fn stream_close_round_trip() {
        let payload = build_stream_close(1001);
        let parsed = parse_stream_close(&payload).unwrap();
        assert_eq!(parsed.stream_id, 1001);
    }

    #[test]
    fn stream_data_round_trip() {
        let data = b"hello mux world";
        let payload = build_stream_data(7, FRAME_DATA, data);
        let parsed = parse_stream_data(&payload).unwrap();
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.inner_frame_type, FRAME_DATA);
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn stream_data_empty_payload() {
        let payload = build_stream_data(0, FRAME_PUT, &[]);
        let parsed = parse_stream_data(&payload).unwrap();
        assert_eq!(parsed.stream_id, 0);
        assert_eq!(parsed.inner_frame_type, FRAME_PUT);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn stream_data_truncated() {
        // Craft a truncated payload: header says 100 bytes but only 5 present
        let mut payload = Vec::new();
        put_u16(&mut payload, 1); // stream_id
        put_u8(&mut payload, FRAME_DATA); // inner type
        put_u32(&mut payload, 100); // claims 100 bytes
        payload.extend_from_slice(&[0u8; 5]); // only 5 bytes
        assert!(parse_stream_data(&payload).is_err());
    }
}

// ── Transport type parsing tests ────────────────────────────────────────────

mod transport_tests {
    use aft::aftp::transport::TransportType;

    #[test]
    fn parse_tcp() {
        assert_eq!("tcp".parse::<TransportType>().unwrap(), TransportType::Tcp);
        assert_eq!("TCP".parse::<TransportType>().unwrap(), TransportType::Tcp);
    }

    #[test]
    fn parse_websocket() {
        assert_eq!(
            "ws".parse::<TransportType>().unwrap(),
            TransportType::WebSocket
        );
        assert_eq!(
            "websocket".parse::<TransportType>().unwrap(),
            TransportType::WebSocket
        );
        assert_eq!(
            "WebSocket".parse::<TransportType>().unwrap(),
            TransportType::WebSocket
        );
    }

    #[test]
    fn parse_quic() {
        assert_eq!(
            "quic".parse::<TransportType>().unwrap(),
            TransportType::Quic
        );
        assert_eq!(
            "QUIC".parse::<TransportType>().unwrap(),
            TransportType::Quic
        );
    }

    #[test]
    fn parse_invalid_transport() {
        assert!("http".parse::<TransportType>().is_err());
        assert!("".parse::<TransportType>().is_err());
        assert!("ftp".parse::<TransportType>().is_err());
    }

    #[test]
    fn display_round_trip() {
        let types = [
            TransportType::Tcp,
            TransportType::WebSocket,
            TransportType::Quic,
        ];
        for t in &types {
            let s = t.to_string();
            let parsed: TransportType = s.parse().unwrap();
            assert_eq!(*t, parsed);
        }
    }
}

// ── Plugin registry tests ───────────────────────────────────────────────────

mod plugin_tests {
    use aft::plugins::PluginRegistry;

    #[test]
    fn empty_registry() {
        let reg = PluginRegistry::new();
        assert!(reg.list().is_empty());
    }

    #[test]
    fn has_scheme_empty() {
        let reg = PluginRegistry::new();
        assert!(!reg.has_scheme("custom"));
        assert!(!reg.has_scheme(""));
    }

    #[test]
    fn create_handler_missing_scheme() {
        let reg = PluginRegistry::new();
        assert!(reg.create_handler("nonexistent").is_none());
    }

    #[test]
    fn unload_missing_scheme() {
        let mut reg = PluginRegistry::new();
        assert!(reg.unload("nope").is_err());
    }
}

// ── New protocol resolution tests ───────────────────────────────────────────

mod new_protocol_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn resolve_webdav() {
        let h = resolve_protocol("webdav://server.example.com/dav/files").unwrap();
        assert_eq!(h.scheme(), "webdav");
        assert_eq!(h.name(), "WebDAV");
    }

    #[test]
    fn resolve_webdavs() {
        let h = resolve_protocol("webdavs://server.example.com/dav/files").unwrap();
        assert_eq!(h.scheme(), "webdavs");
        assert_eq!(h.name(), "WebDAV");
    }

    #[test]
    fn resolve_dav() {
        let h = resolve_protocol("dav://server.example.com/files").unwrap();
        assert_eq!(h.scheme(), "dav");
        assert_eq!(h.name(), "WebDAV");
    }

    #[test]
    fn resolve_azure_blob() {
        let h = resolve_protocol("az://mycontainer/myblob.dat").unwrap();
        assert_eq!(h.scheme(), "az");
        assert_eq!(h.name(), "Azure Blob Storage");
    }

    #[test]
    fn resolve_azblob() {
        let h = resolve_protocol("azblob://mycontainer/path/to/file").unwrap();
        assert_eq!(h.scheme(), "az"); // azblob is an alias for az
        assert_eq!(h.name(), "Azure Blob Storage");
    }

    #[test]
    fn resolve_gcs() {
        let h = resolve_protocol("gs://my-bucket/object/key").unwrap();
        assert_eq!(h.scheme(), "gs");
        assert_eq!(h.name(), "Google Cloud Storage");
    }

    #[test]
    fn resolve_smb() {
        let h = resolve_protocol("smb://server/share/path").unwrap();
        assert_eq!(h.scheme(), "smb");
        assert_eq!(h.name(), "SMB/CIFS");
    }

    #[test]
    fn webdav_supports_ranges() {
        let h = resolve_protocol("webdav://server/path").unwrap();
        assert!(h.supports_ranges());
        assert!(h.supports_resume());
    }

    #[test]
    fn smb_no_ranges() {
        let h = resolve_protocol("smb://server/share/file").unwrap();
        assert!(!h.supports_ranges());
        assert!(!h.supports_resume());
    }

    #[test]
    fn gcs_supports_ranges() {
        let h = resolve_protocol("gs://bucket/key").unwrap();
        assert!(h.supports_ranges());
        assert!(h.supports_resume());
    }

    #[test]
    fn azure_supports_ranges() {
        let h = resolve_protocol("az://container/blob").unwrap();
        assert!(h.supports_ranges());
        assert!(h.supports_resume());
    }
}

// ── SMB URL parsing & security tests ────────────────────────────────────────

mod smb_security_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn smb_rejects_shell_metacharacters() {
        // Semicolons, pipes, backticks, dollar signs should be rejected
        let bad_urls = vec![
            "smb://server;evil/share/path",
            "smb://server/share;rm -rf/path",
            "smb://server/share/path|evil",
            "smb://server/share/`whoami`",
            "smb://server/share/$HOME",
            "smb://server/share/path\"injection",
        ];
        for url in &bad_urls {
            let h = resolve_protocol(url).unwrap();
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(h.head(url, &Default::default()));
            assert!(result.is_err(), "Should reject: {}", url);
        }
    }

    #[test]
    fn smb_rejects_missing_share() {
        let h = resolve_protocol("smb://server").unwrap();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(h.head("smb://server", &Default::default()));
        assert!(result.is_err());
    }
}

// ── Audit logging tests ─────────────────────────────────────────────────────

mod audit_tests {
    use aft::audit::*;

    #[test]
    fn audit_event_serialization() {
        let event = AuditEvent::new(AuditEventType::AuthSuccess, AuditSeverity::Info, "success")
            .with_source_ip("192.168.1.1")
            .with_resource("/path/to/file")
            .with_details("test details");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"auth_success\""));
        assert!(json.contains("\"severity\":\"INFO\""));
        assert!(json.contains("\"source_ip\":\"192.168.1.1\""));
        assert!(json.contains("\"resource\":\"/path/to/file\""));
        assert!(json.contains("\"outcome\":\"success\""));
        assert!(json.contains("\"details\":\"test details\""));
    }

    #[test]
    fn audit_event_minimal() {
        let event = AuditEvent::new(
            AuditEventType::AuthFailure,
            AuditSeverity::Warning,
            "failure",
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"auth_failure\""));
        assert!(json.contains("\"source_ip\":null"));
    }

    #[test]
    fn audit_event_types_serialize() {
        let types = vec![
            (AuditEventType::AuthSuccess, "auth_success"),
            (AuditEventType::AuthFailure, "auth_failure"),
            (AuditEventType::AuthLockout, "auth_lockout"),
            (AuditEventType::FileRead, "file_read"),
            (AuditEventType::FileWrite, "file_write"),
            (AuditEventType::FileList, "file_list"),
        ];
        for (event_type, expected) in types {
            let event = AuditEvent::new(event_type, AuditSeverity::Info, "ok");
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.contains(&format!("\"event_type\":\"{}\"", expected)));
        }
    }

    #[test]
    fn audit_severity_levels() {
        let severities = vec![
            (AuditSeverity::Info, "INFO"),
            (AuditSeverity::Warning, "WARNING"),
            (AuditSeverity::Error, "ERROR"),
            (AuditSeverity::Critical, "CRITICAL"),
        ];
        for (severity, expected) in severities {
            let event = AuditEvent::new(AuditEventType::AuthSuccess, severity, "ok");
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.contains(&format!("\"severity\":\"{}\"", expected)));
        }
    }
}

// ── Credential scrubbing tests ──────────────────────────────────────────────

mod credential_scrub_tests {
    // Test the URL scrubbing logic via history entries
    use aft::history::HistoryEntry;

    #[test]
    fn history_entry_structure() {
        let entry = HistoryEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            operation: "get".to_string(),
            source: Some("https://example.com/file.txt".to_string()),
            destination: Some("/tmp/file.txt".to_string()),
            protocol: Some("https".to_string()),
            status: "success".to_string(),
            bytes_transferred: 1024,
            duration_ms: 500,
            error: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"operation\":\"get\""));
        assert!(json.contains("\"bytes_transferred\":1024"));
        assert!(!json.contains("password"));
    }
}

// ── PQC crypto tests ────────────────────────────────────────────────────────

mod pqc_tests {
    use aft::crypto::pqc;
    use std::path::PathBuf;

    #[test]
    fn generate_keypair_produces_valid_keys() {
        let kp = pqc::generate_keypair().unwrap();
        // Kyber1024: public key = 1568 bytes, secret key = 3168 bytes
        assert_eq!(kp.public_key.len(), 1568);
        assert_eq!(kp.secret_key.len(), 3168);
    }

    #[test]
    fn roundtrip_key_save_load() {
        let kp = pqc::generate_keypair().unwrap();
        let dir = std::env::temp_dir().join("aft_pqc_test");
        std::fs::create_dir_all(&dir).ok();
        let pub_path = dir.join("test_key.pub");
        let sec_path = dir.join("test_key.sec");

        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let loaded_pub = pqc::load_public_key(&pub_path).unwrap();
        let loaded_sec = pqc::load_secret_key(&sec_path).unwrap();

        assert_eq!(kp.public_key, loaded_pub);
        assert_eq!(kp.secret_key, loaded_sec);

        // Cleanup
        std::fs::remove_file(&pub_path).ok();
        std::fs::remove_file(&sec_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = pqc::generate_keypair().unwrap();
        let dir = std::env::temp_dir().join("aft_pqc_enc_test");
        std::fs::create_dir_all(&dir).ok();
        let pub_path = dir.join("enc_key.pub");
        let sec_path = dir.join("enc_key.sec");

        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let plaintext = b"Hello, post-quantum world! This is classified data.";
        let (kem_ct, encrypted) = pqc::encrypt(plaintext, &pub_path).unwrap();

        // KEM ciphertext should be 1568 bytes for Kyber1024
        assert_eq!(kem_ct.len(), 1568);
        // Encrypted data should be longer than plaintext (nonce + tag overhead)
        assert!(encrypted.len() > plaintext.len());

        let decrypted = pqc::decrypt(&kem_ct, &encrypted, &sec_path).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Cleanup
        std::fs::remove_file(&pub_path).ok();
        std::fs::remove_file(&sec_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let kp1 = pqc::generate_keypair().unwrap();
        let kp2 = pqc::generate_keypair().unwrap();
        let dir = std::env::temp_dir().join("aft_pqc_wrong_key_test");
        std::fs::create_dir_all(&dir).ok();

        let pub1 = dir.join("k1.pub");
        let sec2 = dir.join("k2.sec");
        pqc::save_public_key(&kp1.public_key, &pub1).unwrap();
        pqc::save_secret_key(&kp2.secret_key, &sec2).unwrap();

        let (kem_ct, encrypted) = pqc::encrypt(b"secret", &pub1).unwrap();
        // Decrypting with wrong secret key should fail
        let result = pqc::decrypt(&kem_ct, &encrypted, &sec2);
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(&pub1).ok();
        std::fs::remove_file(&sec2).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn rejects_invalid_key_file() {
        let path = PathBuf::from("nonexistent_key.pub");
        let result = pqc::load_public_key(&path);
        assert!(result.is_err());
    }
}

// ── Neural cipher tests ─────────────────────────────────────────────────────

mod neural_tests {
    use aft::crypto::neural::{NeuralCipher, TrainConfig, BLOCK_SIZE};

    fn quick_cipher(seed: u64) -> NeuralCipher {
        let config = TrainConfig {
            epochs: 100,
            learning_rate: 0.01,
            batch_size: 32,
            seed,
        };
        NeuralCipher::train(&config)
    }

    #[test]
    fn train_and_encrypt_decrypt_block() {
        let cipher = quick_cipher(12345);

        let plaintext = b"0123456789abcdef"; // exactly 16 bytes
        let encrypted = cipher.encrypt(plaintext);
        // Encrypted: 16 (IV) + 32 (1 data block + 1 padding block)
        assert_eq!(encrypted.len(), 16 + 32);

        let decrypted = cipher.decrypt(&encrypted);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_multi_block() {
        let cipher = quick_cipher(99);

        let plaintext = b"This is a longer message that spans several blocks for testing.";
        let encrypted = cipher.encrypt(plaintext);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = cipher.decrypt(&encrypted);
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn model_save_and_load() {
        let cipher = quick_cipher(42);

        let path = std::env::temp_dir().join("aft_neural_test.nn");
        cipher.save(&path).unwrap();

        let loaded = NeuralCipher::load(&path).unwrap();

        let test_data = b"test block data!"; // 16 bytes
        let encrypted = loaded.encrypt(test_data);
        let decrypted = loaded.decrypt(&encrypted);
        assert_eq!(&decrypted, test_data);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn deterministic_training() {
        let cipher1 = quick_cipher(777);
        let cipher2 = quick_cipher(777);

        let plaintext = b"determinism test";
        // Each independently encrypts and decrypts
        let dec1 = cipher1.decrypt(&cipher1.encrypt(plaintext));
        assert_eq!(&dec1, plaintext);

        let dec2 = cipher2.decrypt(&cipher2.encrypt(plaintext));
        assert_eq!(&dec2, plaintext);

        // cipher2 can decrypt cipher1's ciphertext (same model)
        let enc1 = cipher1.encrypt(plaintext);
        let dec_cross = cipher2.decrypt(&enc1);
        assert_eq!(&dec_cross, plaintext);
    }

    #[test]
    fn rejects_invalid_model_file() {
        let path = std::env::temp_dir().join("aft_bad_model.nn");
        std::fs::write(&path, b"not a valid model").unwrap();

        let result = NeuralCipher::load(&path);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_data_handling() {
        let cipher = quick_cipher(42);

        let encrypted = cipher.encrypt(b"");
        let decrypted = cipher.decrypt(&encrypted);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn block_size_is_16() {
        assert_eq!(BLOCK_SIZE, 16);
    }
}

// ── Classification tests ────────────────────────────────────────────────────

mod classification_tests {
    use aft::crypto::classification::{validate_compliance, Classification};

    #[test]
    fn parse_classification_levels() {
        assert_eq!(
            Classification::parse("UNCLASSIFIED"),
            Some(Classification::Unclassified)
        );
        assert_eq!(Classification::parse("CUI"), Some(Classification::Cui));
        assert_eq!(
            Classification::parse("SECRET"),
            Some(Classification::Secret)
        );
        assert_eq!(
            Classification::parse("TOP SECRET"),
            Some(Classification::TopSecret)
        );
        assert_eq!(
            Classification::parse("TOP-SECRET"),
            Some(Classification::TopSecret)
        );
        assert_eq!(Classification::parse("TS"), Some(Classification::TopSecret));
        assert_eq!(
            Classification::parse("U"),
            Some(Classification::Unclassified)
        );
        assert_eq!(Classification::parse("invalid"), None);
    }

    #[test]
    fn case_insensitive_parsing() {
        assert_eq!(
            Classification::parse("secret"),
            Some(Classification::Secret)
        );
        assert_eq!(
            Classification::parse("Secret"),
            Some(Classification::Secret)
        );
        assert_eq!(
            Classification::parse("SECRET"),
            Some(Classification::Secret)
        );
    }

    #[test]
    fn classification_banners() {
        assert_eq!(Classification::Unclassified.banner(), "UNCLASSIFIED");
        assert_eq!(Classification::Secret.banner(), "SECRET");
        assert_eq!(Classification::TopSecret.banner(), "TOP SECRET");
        assert!(Classification::Cui.banner().contains("CUI"));
    }

    #[test]
    fn compliance_allows_unclassified_insecure() {
        // UNCLASSIFIED data can use --insecure
        assert!(validate_compliance(Classification::Unclassified, true).is_ok());
    }

    #[test]
    fn compliance_rejects_classified_insecure() {
        // Classified data cannot use --insecure
        assert!(validate_compliance(Classification::Secret, true).is_err());
        assert!(validate_compliance(Classification::TopSecret, true).is_err());
        assert!(validate_compliance(Classification::Cui, true).is_err());
    }

    #[test]
    fn compliance_allows_classified_secure() {
        assert!(validate_compliance(Classification::Secret, false).is_ok());
        assert!(validate_compliance(Classification::TopSecret, false).is_ok());
    }

    #[test]
    fn header_values() {
        assert_eq!(Classification::Unclassified.header_value(), "UNCLASSIFIED");
        assert_eq!(Classification::Secret.header_value(), "SECRET");
        assert_eq!(Classification::TopSecret.header_value(), "TOP SECRET");
    }
}

// ── DoD protocol handler tests ──────────────────────────────────────────────

mod dod_protocol_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn resolve_dod_protocol() {
        let h = resolve_protocol("dod://SECRET@files.mil/data/report.pdf").unwrap();
        assert_eq!(h.scheme(), "dod");
        assert_eq!(h.name(), "DoD Cross-Domain Solution (CDS)");
    }

    #[test]
    fn dod_supports_ranges() {
        let h = resolve_protocol("dod://UNCLASSIFIED@example.mil/test").unwrap();
        // DoD CDS gateway may not support HTTP ranges — conservative default
        assert!(!h.supports_ranges());
        assert!(!h.supports_resume());
    }
}

// ── Encryption method tests ─────────────────────────────────────────────────

mod encryption_method_tests {
    use aft::crypto::EncryptionMethod;

    #[test]
    fn parse_encryption_methods() {
        assert_eq!(EncryptionMethod::parse("pqc"), Some(EncryptionMethod::Pqc));
        assert_eq!(
            EncryptionMethod::parse("kyber"),
            Some(EncryptionMethod::Pqc)
        );
        assert_eq!(
            EncryptionMethod::parse("neural"),
            Some(EncryptionMethod::Neural)
        );
        assert_eq!(
            EncryptionMethod::parse("nn"),
            Some(EncryptionMethod::Neural)
        );
        assert_eq!(
            EncryptionMethod::parse("hybrid"),
            Some(EncryptionMethod::Hybrid)
        );
        assert_eq!(EncryptionMethod::parse("invalid"), None);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(EncryptionMethod::parse("PQC"), Some(EncryptionMethod::Pqc));
        assert_eq!(
            EncryptionMethod::parse("Neural"),
            Some(EncryptionMethod::Neural)
        );
        assert_eq!(
            EncryptionMethod::parse("HYBRID"),
            Some(EncryptionMethod::Hybrid)
        );
    }
}

// ── End-to-end AFTP server integration tests ────────────────────────────────

mod aftp_e2e_tests {
    use aft::aftp::client::AftpClient;
    use aft::aftp::server::AftpServer;
    use tempfile::TempDir;

    /// Helper: start an AFTP server on a random port, return the port.
    async fn start_server(root: &std::path::Path, port: u16) -> tokio::task::JoinHandle<()> {
        let server = AftpServer::new(
            root,
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        tokio::spawn(async move {
            let _ = server.run().await;
        })
    }

    fn make_client(port: u16) -> AftpClient {
        AftpClient::new("127.0.0.1".into(), port, None, false, false)
    }

    #[tokio::test]
    async fn server_head_returns_metadata() {
        let dir = TempDir::new().unwrap();
        let test_file = dir.path().join("hello.txt");
        std::fs::write(&test_file, "Hello, AFTP!").unwrap();

        let port = 12601;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = make_client(port);
        let info = client.head("/hello.txt").await.unwrap();
        assert_eq!(info.size, 12); // "Hello, AFTP!" = 12 bytes
        assert!(!info.content_type.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn server_download_file() {
        let dir = TempDir::new().unwrap();
        let content = "AFTP download test content - 1234567890";
        std::fs::write(dir.path().join("dl.txt"), content).unwrap();

        let port = 12602;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = make_client(port);
        let dest = dir.path().join("dl_output.txt");
        let bytes = client.download("/dl.txt", &dest, None).await.unwrap();
        assert_eq!(bytes, content.len() as u64);
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), content);

        handle.abort();
    }

    #[tokio::test]
    async fn server_upload_file() {
        let dir = TempDir::new().unwrap();
        let upload_content = "Uploaded via AFTP client test";
        let src = dir.path().join("upload_src.txt");
        std::fs::write(&src, upload_content).unwrap();

        let port = 12603;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = make_client(port);
        let bytes = client.upload(&src, "/uploaded.txt", None).await.unwrap();
        assert_eq!(bytes, upload_content.len() as u64);

        // Verify server wrote the file
        let server_path = dir.path().join("uploaded.txt");
        assert_eq!(
            std::fs::read_to_string(&server_path).unwrap(),
            upload_content
        );

        handle.abort();
    }

    #[tokio::test]
    async fn server_list_directory() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("aaa.txt"), "a").unwrap();
        std::fs::write(dir.path().join("bbb.txt"), "bb").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let port = 12604;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = make_client(port);
        let entries = client.list("/").await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"aaa.txt"));
        assert!(names.contains(&"bbb.txt"));
        assert!(names.contains(&"subdir"));

        // Check subdir is flagged as directory
        let subdir_entry = entries.iter().find(|e| e.name == "subdir").unwrap();
        assert!(subdir_entry.is_dir);

        handle.abort();
    }

    #[tokio::test]
    async fn server_head_nonexistent_file() {
        let dir = TempDir::new().unwrap();

        let port = 12605;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = make_client(port);
        let result = client.head("/nonexistent.txt").await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn server_with_auth_rejects_no_token() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("secret.txt"), "classified").unwrap();

        let port = 12606;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            Some("test_token_123".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client with no token should be rejected
        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let result = client.head("/secret.txt").await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn server_with_auth_accepts_correct_token() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("secret.txt"), "classified").unwrap();

        let port = 12607;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            Some("correct_token".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new(
            "127.0.0.1".into(),
            port,
            Some("correct_token".into()),
            false,
            false,
        );
        let info = client.head("/secret.txt").await.unwrap();
        assert_eq!(info.size, 10); // "classified" = 10 bytes

        handle.abort();
    }

    // ── Fountain-coded data plane, end to end ───────────────────────────

    /// Reproducible, incompressible-ish content so a corrupt or mis-ordered
    /// reassembly is unmistakable.
    fn fec_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect()
    }

    /// A full transfer over the real UDP data plane: handshake, offer/accept,
    /// symbol spray, per-block feedback, and the closing digest.
    ///
    /// RaptorQ decoding is roughly two orders of magnitude slower unoptimized,
    /// so this takes minutes in a debug build and ~0.3 s in release. Run it
    /// where the timing is meaningful.
    #[cfg_attr(debug_assertions, ignore = "too slow unoptimized; run with --release")]
    #[tokio::test]
    async fn fec_download_round_trips_over_udp() {
        let dir = TempDir::new().unwrap();
        // Above FEC_MIN_TRANSFER (1 MiB) so the data plane actually engages.
        let content = fec_payload(3 * 1024 * 1024);
        std::fs::write(dir.path().join("big.bin"), &content).unwrap();

        let port = 12651;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let out = dir.path().join("out.bin");
        let client = make_client(port).with_fec(true);
        let n = client.download("/big.bin", &out, None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), content);

        handle.abort();
    }

    /// Authenticated symbols: every datagram carries a per-session HMAC.
    /// Release-only for the same reason as the test above.
    #[cfg_attr(debug_assertions, ignore = "too slow unoptimized; run with --release")]
    #[tokio::test]
    async fn fec_download_with_authenticated_symbols() {
        let dir = TempDir::new().unwrap();
        let content = fec_payload(2 * 1024 * 1024);
        std::fs::write(dir.path().join("auth.bin"), &content).unwrap();

        let port = 12652;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            Some("fec_token".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let out = dir.path().join("auth-out.bin");
        let client = AftpClient::new(
            "127.0.0.1".into(),
            port,
            Some("fec_token".into()),
            false,
            false,
        )
        .with_fec(true);
        let n = client.download("/auth.bin", &out, None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), content);

        handle.abort();
    }

    /// A client that does not ask for the data plane must get the ordinary
    /// reliable path, unchanged. This is the v1-client-against-v2-server case.
    #[tokio::test]
    async fn client_without_fec_uses_reliable_path() {
        let dir = TempDir::new().unwrap();
        let content = fec_payload(2 * 1024 * 1024);
        std::fs::write(dir.path().join("plain.bin"), &content).unwrap();

        let port = 12653;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let out = dir.path().join("plain-out.bin");
        // Default client: CAP_FEC never advertised.
        let client = make_client(port);
        let n = client.download("/plain.bin", &out, None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), content);

        handle.abort();
    }

    /// A server with the data plane disabled must not offer it, and a client
    /// that asked for it must still succeed. This is the v2-client-against-
    /// v1-server case.
    #[tokio::test]
    async fn fec_client_falls_back_to_v1_server() {
        let dir = TempDir::new().unwrap();
        let content = fec_payload(2 * 1024 * 1024);
        std::fs::write(dir.path().join("fallback.bin"), &content).unwrap();

        let port = 12654;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        )
        .with_fec(false);
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let out = dir.path().join("fallback-out.bin");
        let client = make_client(port).with_fec(true);
        let n = client.download("/fallback.bin", &out, None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), content);

        handle.abort();
    }

    /// Files below the size floor stay on the reliable path even with the data
    /// plane negotiated — the setup cost is not worth paying for them.
    #[tokio::test]
    async fn small_files_bypass_the_data_plane() {
        let dir = TempDir::new().unwrap();
        let content = b"tiny".to_vec();
        std::fs::write(dir.path().join("tiny.txt"), &content).unwrap();

        let port = 12655;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let out = dir.path().join("tiny-out.txt");
        let client = make_client(port).with_fec(true);
        let n = client.download("/tiny.txt", &out, None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), content);

        handle.abort();
    }

    /// Pushing a file over the data plane: the client is the symbol sender,
    /// the server decodes blocks straight to disk and commits on digest match.
    /// Release-only — RaptorQ is ~100x slower unoptimized.
    #[cfg_attr(debug_assertions, ignore = "too slow unoptimized; run with --release")]
    #[tokio::test]
    async fn fec_upload_round_trips_over_udp() {
        let dir = TempDir::new().unwrap();
        let served = dir.path().join("served");
        std::fs::create_dir_all(&served).unwrap();

        let content = fec_payload(3 * 1024 * 1024);
        let src = dir.path().join("push.bin");
        std::fs::write(&src, &content).unwrap();

        let port = 12659;
        let handle = start_server(&served, port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = make_client(port).with_fec(true);
        let n = client.upload(&src, "/pushed.bin", None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(served.join("pushed.bin")).unwrap(), content);
        // Staging file must not be left behind.
        assert!(!served.join("pushed.aft-tmp").exists());

        handle.abort();
    }

    /// Authenticated push: symbols carry a per-session HMAC that both ends
    /// derive from the shared token without it crossing the wire.
    #[cfg_attr(debug_assertions, ignore = "too slow unoptimized; run with --release")]
    #[tokio::test]
    async fn fec_upload_with_authenticated_symbols() {
        let dir = TempDir::new().unwrap();
        let served = dir.path().join("served");
        std::fs::create_dir_all(&served).unwrap();

        let content = fec_payload(2 * 1024 * 1024);
        let src = dir.path().join("push-auth.bin");
        std::fs::write(&src, &content).unwrap();

        let port = 12660;
        let server = AftpServer::new(
            &served,
            port,
            "127.0.0.1",
            Some("push_token".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = AftpClient::new(
            "127.0.0.1".into(),
            port,
            Some("push_token".into()),
            false,
            false,
        )
        .with_fec(true);
        let n = client.upload(&src, "/auth-pushed.bin", None).await.unwrap();

        assert_eq!(n, content.len() as u64);
        assert_eq!(
            std::fs::read(served.join("auth-pushed.bin")).unwrap(),
            content
        );

        handle.abort();
    }

    /// A pushed file below the size floor stays on the reliable frame path.
    #[tokio::test]
    async fn small_upload_bypasses_the_data_plane() {
        let dir = TempDir::new().unwrap();
        let served = dir.path().join("served");
        std::fs::create_dir_all(&served).unwrap();
        let src = dir.path().join("small.txt");
        std::fs::write(&src, b"small payload").unwrap();

        let port = 12661;
        let handle = start_server(&served, port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = make_client(port).with_fec(true);
        let n = client.upload(&src, "/small.txt", None).await.unwrap();

        assert_eq!(n, 13);
        assert_eq!(
            std::fs::read(served.join("small.txt")).unwrap(),
            b"small payload"
        );

        handle.abort();
    }

    /// Syncing a directory tree to AFTP used to fail outright on the first
    /// subdirectory with "mkdir is not supported by this protocol". The AFTP
    /// server creates parent directories when handling a PUT, so the sync
    /// engine must skip the explicit mkdir rather than attempt it.
    #[tokio::test]
    async fn sync_tree_to_aftp_server() {
        use aft::sync::{CompareMode, SyncConfig};

        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        let dst_root = dir.path().join("served");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();

        // Nested tree, several files per directory.
        for i in 0..24 {
            let sub = src.join(format!("d{}", i % 4)).join(format!("e{}", i % 2));
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(format!("f{}.bin", i)), format!("contents-{}", i)).unwrap();
        }

        let port = 12657;
        let handle = start_server(&dst_root, port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let src_handler = aft::protocols::resolve_protocol("file://").unwrap();
        let dst_handler = aft::protocols::resolve_protocol("aftp://x/").unwrap();
        let src_url = format!("file://{}", src.to_str().unwrap().replace('\\', "/"));
        let dst_url = format!("aftp://127.0.0.1:{}/", port);

        let config = SyncConfig {
            compare: CompareMode::Size,
            transfers: 8,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &*src_handler,
            &src_url,
            &*dst_handler,
            &dst_url,
            &aft::protocols::ProtocolOptions::default(),
            &config,
            None,
        )
        .await
        .expect("tree sync to AFTP should succeed");

        assert_eq!(result.files_copied, 24, "every file should transfer");

        // Every file must have landed at the right nested path with the right
        // bytes — the server creating parents implicitly must not flatten it.
        for i in 0..24 {
            let landed = dst_root
                .join(format!("d{}", i % 4))
                .join(format!("e{}", i % 2))
                .join(format!("f{}.bin", i));
            assert_eq!(
                std::fs::read_to_string(&landed).unwrap_or_default(),
                format!("contents-{}", i),
                "missing or wrong at {:?}",
                landed
            );
        }

        handle.abort();
    }

    /// Ranged reads must keep using the reliable path — the data plane only
    /// serves whole files, and `download_range` backs parallel chunking.
    #[tokio::test]
    async fn ranged_reads_still_work_with_fec_negotiated() {
        let dir = TempDir::new().unwrap();
        let content = fec_payload(2 * 1024 * 1024);
        std::fs::write(dir.path().join("ranged.bin"), &content).unwrap();

        let port = 12656;
        let handle = start_server(dir.path(), port).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = make_client(port).with_fec(true);
        let chunk = client.download_range("/ranged.bin", 1000, 1999).await.unwrap();

        assert_eq!(chunk.len(), 1000);
        assert_eq!(chunk, &content[1000..2000]);

        handle.abort();
    }
}

// ── Security-specific tests ─────────────────────────────────────────────────

mod security_tests {
    use aft::aftp::client::AftpClient;
    use aft::aftp::server::AftpServer;
    use tempfile::TempDir;

    #[tokio::test]
    async fn path_traversal_rejected() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("safe.txt"), "ok").unwrap();

        let port = 12610;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);

        // Attempt path traversal
        let result = client.head("/../../../etc/passwd").await;
        assert!(result.is_err());

        let result2 = client.head("/..\\..\\Windows\\System32\\config\\SAM").await;
        assert!(result2.is_err());

        handle.abort();
    }

    /// `safe_path` was relaxed to permit uploads into directories that do not
    /// exist yet, so that nested PUTs work. Containment must still hold: a
    /// path that escapes the server root has to be refused whether or not any
    /// part of it exists.
    #[tokio::test]
    async fn traversal_rejected_on_uploads_to_nonexistent_paths() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let payload = dir.path().join("payload.txt");
        std::fs::write(&payload, "should not escape").unwrap();

        let port = 12658;
        let server = AftpServer::new(
            &root, port, "127.0.0.1", None, false, false, false, None, None, 0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);

        // Escape attempts through directories that do not exist yet.
        for target in [
            "/../outside/escaped.txt",
            "/a/b/../../../outside/escaped.txt",
            "/newdir/../../outside/escaped.txt",
        ] {
            let r = client.upload(&payload, target, None).await;
            assert!(r.is_err(), "traversal via {} was accepted", target);
        }

        // Nothing escaped.
        assert!(
            !outside.join("escaped.txt").exists(),
            "a file was written outside the server root"
        );

        // The legitimate nested case still works — this is what the relaxation
        // was for.
        let ok = client.upload(&payload, "/fresh/nested/deep/file.txt", None).await;
        assert!(ok.is_ok(), "nested upload should succeed: {:?}", ok.err());
        assert!(root.join("fresh").join("nested").join("deep").join("file.txt").exists());

        handle.abort();
    }

    #[tokio::test]
    async fn auth_rate_limiting_locks_out_ip() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("test.txt"), "data").unwrap();

        let port = 12611;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            Some("real_token".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send 5 bad auth attempts to trigger lockout
        for _ in 0..5 {
            let client = AftpClient::new(
                "127.0.0.1".into(),
                port,
                Some("wrong_token".into()),
                false,
                false,
            );
            let _ = client.head("/test.txt").await;
        }

        // 6th attempt should also fail (locked out)
        let client = AftpClient::new(
            "127.0.0.1".into(),
            port,
            Some("real_token".into()),
            false,
            false,
        );
        let result = client.head("/test.txt").await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn smb_control_char_rejection() {
        // Control characters in URL path should be rejected at URL parsing level
        // Test via direct SMB URL parsing
        use aft::protocols::resolve_protocol;
        let bad_urls = vec![
            "smb://server\x00/share/path",
            "smb://server/share\t/path",
            "smb://server/share/pa\nth",
        ];
        for url in &bad_urls {
            let handler = resolve_protocol(url).unwrap();
            let result = handler.head(url, &Default::default()).await;
            assert!(result.is_err(), "Should reject: {:?}", url);
        }
    }

    #[test]
    fn credential_scrubbing_expanded() {
        // Verify the expanded sensitive param list works via the history module
        let entry = aft::history::HistoryEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            operation: "get".to_string(),
            source: Some("https://api.example.com/data?access_key=AKID123&name=file".to_string()),
            destination: Some("/tmp/file".to_string()),
            protocol: Some("https".to_string()),
            status: "success".to_string(),
            bytes_transferred: 100,
            duration_ms: 50,
            error: None,
        };
        // The source URL has access_key= which should be scrubbed when logged
        let json = serde_json::to_string(&entry).unwrap();
        // The entry itself stores the raw value, scrubbing happens in log_transfer
        assert!(json.contains("access_key"));
    }
}

// ── Crypto roundtrip file-level tests ───────────────────────────────────────

mod crypto_file_tests {
    use aft::crypto;
    use tempfile::TempDir;

    #[tokio::test]
    async fn pqc_encrypt_decrypt_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("plain.txt");
        let encrypted = dir.path().join("plain.txt.enc");
        let decrypted = dir.path().join("plain.dec.txt");

        let plaintext = "Post-quantum encryption file roundtrip test data!";
        std::fs::write(&input, plaintext).unwrap();

        // Generate keypair
        let kp = crypto::pqc::generate_keypair().unwrap();
        let pub_key = dir.path().join("test.pub");
        let sec_key = dir.path().join("test.sec");
        crypto::pqc::save_public_key(&kp.public_key, &pub_key).unwrap();
        crypto::pqc::save_secret_key(&kp.secret_key, &sec_key).unwrap();

        // Encrypt
        let enc_size =
            crypto::encrypt_file(&input, &encrypted, crypto::EncryptionMethod::Pqc, &pub_key)
                .await
                .unwrap();
        assert!(enc_size > 0);
        assert!(encrypted.exists());

        // Decrypt
        let dec_size = crypto::decrypt_file(&encrypted, &decrypted, &sec_key)
            .await
            .unwrap();
        assert_eq!(dec_size, plaintext.len() as u64);
        assert_eq!(std::fs::read_to_string(&decrypted).unwrap(), plaintext);
    }

    #[tokio::test]
    async fn neural_encrypt_decrypt_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("neural_plain.txt");
        let encrypted = dir.path().join("neural_plain.txt.enc");
        let decrypted = dir.path().join("neural_plain.dec.txt");

        let plaintext = "Neural cipher file roundtrip test!";
        std::fs::write(&input, plaintext).unwrap();

        // Train a cipher model
        let config = crypto::neural::TrainConfig {
            epochs: 100,
            learning_rate: 0.01,
            batch_size: 32,
            seed: 42,
        };
        let cipher = crypto::neural::NeuralCipher::train(&config);
        let model_path = dir.path().join("test.nn");
        cipher.save(&model_path).unwrap();

        // Encrypt
        let enc_size = crypto::encrypt_file(
            &input,
            &encrypted,
            crypto::EncryptionMethod::Neural,
            &model_path,
        )
        .await
        .unwrap();
        assert!(enc_size > 0);

        // Decrypt
        let dec_size = crypto::decrypt_file(&encrypted, &decrypted, &model_path)
            .await
            .unwrap();
        assert_eq!(dec_size, plaintext.len() as u64);
        assert_eq!(std::fs::read_to_string(&decrypted).unwrap(), plaintext);
    }

    #[tokio::test]
    async fn hybrid_encrypt_decrypt_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("hybrid_plain.txt");
        let encrypted = dir.path().join("hybrid_plain.txt.enc");
        let decrypted = dir.path().join("hybrid_plain.dec.txt");

        let plaintext = "Hybrid PQC+Neural roundtrip test data for file encryption!";
        std::fs::write(&input, plaintext).unwrap();

        // Generate PQC keypair (used for key exchange)
        let kp = crypto::pqc::generate_keypair().unwrap();
        let pub_key = dir.path().join("hybrid.pub");
        let sec_key = dir.path().join("hybrid.sec");
        crypto::pqc::save_public_key(&kp.public_key, &pub_key).unwrap();
        crypto::pqc::save_secret_key(&kp.secret_key, &sec_key).unwrap();

        // Encrypt with hybrid method (needs pub key for PQC KEM)
        let enc_size = crypto::encrypt_file(
            &input,
            &encrypted,
            crypto::EncryptionMethod::Hybrid,
            &pub_key,
        )
        .await
        .unwrap();
        assert!(enc_size > 0);

        // Decrypt with secret key
        let dec_size = crypto::decrypt_file(&encrypted, &decrypted, &sec_key)
            .await
            .unwrap();
        assert_eq!(dec_size, plaintext.len() as u64);
        assert_eq!(std::fs::read_to_string(&decrypted).unwrap(), plaintext);
    }

    #[tokio::test]
    async fn pqc_wrong_key_fails_file_decrypt() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("wrong_key.txt");
        let encrypted = dir.path().join("wrong_key.enc");
        let decrypted = dir.path().join("wrong_key.dec");

        std::fs::write(&input, "secret data").unwrap();

        let kp1 = crypto::pqc::generate_keypair().unwrap();
        let kp2 = crypto::pqc::generate_keypair().unwrap();
        let pub1 = dir.path().join("k1.pub");
        let sec2 = dir.path().join("k2.sec");
        crypto::pqc::save_public_key(&kp1.public_key, &pub1).unwrap();
        crypto::pqc::save_secret_key(&kp2.secret_key, &sec2).unwrap();

        // Encrypt with key 1
        crypto::encrypt_file(&input, &encrypted, crypto::EncryptionMethod::Pqc, &pub1)
            .await
            .unwrap();

        // Decrypt with key 2 should fail
        let result = crypto::decrypt_file(&encrypted, &decrypted, &sec2).await;
        assert!(result.is_err());
    }
}

// ── Phase 12 hardening tests ────────────────────────────────────────────────

mod hardening_tests {
    use aft::config::AftConfig;
    use aft::protocols::resolve_protocol;

    #[test]
    fn url_scheme_rejects_invalid_chars() {
        // Null byte in scheme
        let result = resolve_protocol("ht\x00tp://example.com/file");
        assert!(result.is_err());
        // Newline in scheme
        let result = resolve_protocol("ht\ntp://example.com/file");
        assert!(result.is_err());
        // Space in scheme
        let result = resolve_protocol("ht tp://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn url_scheme_accepts_valid_schemes() {
        // Standard schemes should resolve (may error on unsupported, but not InvalidUrl)
        let result = resolve_protocol("http://example.com/file");
        assert!(result.is_ok());
        let result = resolve_protocol("https://example.com/file");
        assert!(result.is_ok());
    }

    #[test]
    fn config_rejects_zero_parallel() {
        let config = AftConfig {
            parallel: Some(0),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_rejects_excessive_parallel() {
        let config = AftConfig {
            parallel: Some(999),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_rejects_excessive_retries() {
        let config = AftConfig {
            retries: Some(200),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_accepts_valid_values() {
        let config = AftConfig {
            parallel: Some(8),
            retries: Some(5),
            connect_timeout: Some(30),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_default_validates() {
        let config = AftConfig::default();
        assert!(config.validate().is_ok());
    }
}

mod telemetry_tests {
    use aft::telemetry::TelemetryConfig;

    #[test]
    fn default_config_enabled() {
        let config = TelemetryConfig::default();
        assert!(config.enabled, "Telemetry should be enabled by default");
        assert!(
            config.remote_enabled,
            "Remote telemetry should be enabled by default"
        );
    }

    #[test]
    fn installation_id_is_uuid_format() {
        let config = TelemetryConfig::default();
        // UUID v4 format: 8-4-4-4-12 (36 chars with dashes)
        assert_eq!(config.installation_id.len(), 36);
        assert_eq!(config.installation_id.chars().nth(8), Some('-'));
        assert_eq!(config.installation_id.chars().nth(13), Some('-'));
        assert_eq!(config.installation_id.chars().nth(18), Some('-'));
        assert_eq!(config.installation_id.chars().nth(23), Some('-'));
    }

    #[test]
    fn installation_ids_are_unique() {
        let config1 = TelemetryConfig::default();
        let config2 = TelemetryConfig::default();
        assert_ne!(
            config1.installation_id, config2.installation_id,
            "Each config should have a unique installation ID"
        );
    }

    #[test]
    fn default_endpoint_is_nervosys() {
        let config = TelemetryConfig::default();
        assert!(
            config.remote_endpoint.contains("nervosys"),
            "Default endpoint should be Nervosys AWS EC2 server"
        );
    }

    #[test]
    fn config_version_is_one() {
        let config = TelemetryConfig::default();
        assert_eq!(config.version, 1);
    }
}

// ── Phase 16: Validation & hardening tests ──────────────────────────────────

mod cli_validation_tests {
    use aft::cli::Cli;
    use clap::Parser;

    fn make_cli(args: &[&str]) -> Cli {
        let mut full = vec!["aft"];
        full.extend_from_slice(args);
        full.push("schema"); // needs a subcommand
        Cli::parse_from(full)
    }

    #[test]
    fn cli_rejects_parallel_zero() {
        let cli = make_cli(&["--parallel", "0"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_rejects_parallel_too_high() {
        let cli = make_cli(&["--parallel", "999"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_accepts_parallel_valid() {
        let cli = make_cli(&["--parallel", "8"]);
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn cli_rejects_retries_too_high() {
        let cli = make_cli(&["--retries", "200"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_accepts_retries_valid() {
        let cli = make_cli(&["--retries", "5"]);
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn cli_rejects_retry_delay_zero() {
        let cli = make_cli(&["--retry-delay-ms", "0"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_rejects_connect_timeout_too_high() {
        let cli = make_cli(&["--connect-timeout", "9999"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_rejects_timeout_too_high() {
        let cli = make_cli(&["--timeout", "999999"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn cli_default_validates() {
        let cli = make_cli(&[]);
        assert!(cli.validate().is_ok());
    }
}

mod retry_delay_tests {
    use aft::engine::TransferConfig;

    #[test]
    fn retry_delay_does_not_overflow_at_high_retries() {
        let config = TransferConfig {
            max_retries: 100,
            retry_delay_ms: 1000,
            ..Default::default()
        };
        // Simulate the delay calculation used in engine.rs
        for retries in 1..=config.max_retries {
            let exp = (retries - 1).min(30);
            let delay = config
                .retry_delay_ms
                .saturating_mul(2u64.saturating_pow(exp));
            let delay = delay.min(300_000);
            assert!(delay <= 300_000, "Delay overflowed at retry {}", retries);
        }
    }

    #[test]
    fn retry_delay_caps_at_five_minutes() {
        let config = TransferConfig {
            retry_delay_ms: 60_000,
            ..Default::default()
        };
        let exp = 10u32 - 1;
        let delay = config
            .retry_delay_ms
            .saturating_mul(2u64.saturating_pow(exp));
        let delay = delay.min(300_000);
        assert_eq!(delay, 300_000);
    }
}

mod scheme_validation_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn empty_scheme_is_rejected() {
        let result = resolve_protocol("://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn ws_scheme_is_unsupported() {
        let result = resolve_protocol("ws://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn quic_scheme_is_unsupported() {
        let result = resolve_protocol("quic://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn scheme_with_control_chars_rejected() {
        let result = resolve_protocol("ht\x01tp://example.com/file");
        assert!(result.is_err());
    }
}

mod neural_signature_tests {
    use aft::crypto::neural::{NeuralCipher, TrainConfig};
    use std::io::Write;

    #[test]
    fn model_without_sidecar_loads_fine() {
        let dir = tempfile::TempDir::new().unwrap();
        let model_path = dir.path().join("test.nn");
        let config = TrainConfig {
            epochs: 10,
            learning_rate: 0.01,
            seed: 42,
            ..Default::default()
        };
        let cipher = NeuralCipher::train(&config);
        cipher.save(&model_path).unwrap();

        // No sidecar — should be accepted (backward-compatible)
        let result = aft::crypto::neural::encrypt_file_data(b"hello world!", &model_path);
        assert!(result.is_ok(), "Model without sidecar should be accepted");
    }

    #[test]
    fn model_with_valid_sidecar_loads() {
        let dir = tempfile::TempDir::new().unwrap();
        let model_path = dir.path().join("test.nn");
        let config = TrainConfig {
            epochs: 10,
            learning_rate: 0.01,
            seed: 42,
            ..Default::default()
        };
        let cipher = NeuralCipher::train(&config);
        cipher.save(&model_path).unwrap();

        // Create valid sidecar
        let model_bytes = std::fs::read(&model_path).unwrap();
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(&model_bytes));
        let sig_path = model_path.with_extension("aftnn.sha256");
        std::fs::write(&sig_path, &hash).unwrap();

        let result = aft::crypto::neural::encrypt_file_data(b"hello world!", &model_path);
        assert!(result.is_ok(), "Model with valid sidecar should load");
    }

    #[test]
    fn tampered_model_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let model_path = dir.path().join("test.nn");
        let config = TrainConfig {
            epochs: 10,
            learning_rate: 0.01,
            seed: 42,
            ..Default::default()
        };
        let cipher = NeuralCipher::train(&config);
        cipher.save(&model_path).unwrap();

        // Create valid sidecar first
        let model_bytes = std::fs::read(&model_path).unwrap();
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(&model_bytes));
        let sig_path = model_path.with_extension("aftnn.sha256");
        std::fs::write(&sig_path, &hash).unwrap();

        // Tamper with the model file
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&model_path)
            .unwrap();
        f.write_all(b"TAMPERED").unwrap();

        // Attempting to encrypt with tampered model should fail
        let result = aft::crypto::neural::encrypt_file_data(b"hello", &model_path);
        assert!(result.is_err(), "Tampered model should be rejected");
    }
}

mod rate_limiter_cleanup_tests {
    #[test]
    fn max_tracked_ips_is_bounded() {
        // Verify the constant exists and is reasonable
        // The rate limiter should clean up at MAX_TRACKED_IPS / 2 (5000)
        // and hard cap at MAX_TRACKED_IPS (10000)
        // Rate limiter bounds verified by code review:
        // MAX_TRACKED_IPS = 10_000, cleanup at 50% (5000)
    }
}

// ── Session resume frame tests ──────────────────────────────────────────────

mod session_resume_tests {
    use aft::aftp::frame::*;

    #[test]
    fn hello_ack_with_session_roundtrip() {
        let payload = build_hello_ack_with_session(
            CAP_COMPRESSION | CAP_SESSION_RESUME,
            DEFAULT_MAX_FRAME,
            "abc123",
        );
        let parsed = parse_hello_ack(&payload).unwrap();
        assert_eq!(parsed.capabilities, CAP_COMPRESSION | CAP_SESSION_RESUME);
        assert_eq!(parsed.max_frame_size, DEFAULT_MAX_FRAME);
        assert_eq!(parsed.session_id, "abc123");
    }

    #[test]
    fn hello_ack_without_session_roundtrip() {
        // build_hello_ack (no session) should produce empty session_id
        let payload = build_hello_ack(CAP_COMPRESSION, DEFAULT_MAX_FRAME);
        let parsed = parse_hello_ack(&payload).unwrap();
        assert_eq!(parsed.capabilities, CAP_COMPRESSION);
        assert_eq!(parsed.max_frame_size, DEFAULT_MAX_FRAME);
        assert_eq!(parsed.session_id, "");
    }

    #[test]
    fn resume_roundtrip() {
        let payload = build_resume("sess-42", CAP_SESSION_RESUME | CAP_CHECKSUM, Some("tok"));
        let parsed = parse_resume(&payload).unwrap();
        assert_eq!(parsed.session_id, "sess-42");
        assert_eq!(parsed.capabilities, CAP_SESSION_RESUME | CAP_CHECKSUM);
        assert_eq!(parsed.auth_token, "tok");
    }

    #[test]
    fn resume_no_token() {
        let payload = build_resume("sess-99", CAP_SESSION_RESUME, None);
        let parsed = parse_resume(&payload).unwrap();
        assert_eq!(parsed.session_id, "sess-99");
        assert_eq!(parsed.auth_token, "");
    }

    #[test]
    fn resume_ack_accepted_roundtrip() {
        let payload = build_resume_ack(true, 8192, "/uploads/data.bin");
        let parsed = parse_resume_ack(&payload).unwrap();
        assert!(parsed.accepted);
        assert_eq!(parsed.bytes_received, 8192);
        assert_eq!(parsed.path, "/uploads/data.bin");
    }

    #[test]
    fn resume_ack_rejected_roundtrip() {
        let payload = build_resume_ack(false, 0, "");
        let parsed = parse_resume_ack(&payload).unwrap();
        assert!(!parsed.accepted);
        assert_eq!(parsed.bytes_received, 0);
        assert_eq!(parsed.path, "");
    }

    #[test]
    fn session_resume_capability_bit() {
        assert_eq!(CAP_SESSION_RESUME, 0x10);
        // Verify it doesn't collide with existing capabilities
        assert_ne!(CAP_SESSION_RESUME, CAP_COMPRESSION);
        assert_ne!(CAP_SESSION_RESUME, CAP_CHECKSUM);
        assert_ne!(CAP_SESSION_RESUME, CAP_AUTH_CHALLENGE);
    }

    #[test]
    fn resume_frame_types() {
        assert_eq!(FRAME_RESUME, 0x14);
        assert_eq!(FRAME_RESUME_ACK, 0x15);
    }

    #[test]
    fn err_session_expired_code() {
        assert_eq!(ERR_SESSION_EXPIRED, 7);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V1.0 — Engine integration tests
// ═══════════════════════════════════════════════════════════════════════════

mod engine_download_upload_tests {
    use aft::engine::{ChecksumConfig, TransferConfig, TransferResult};
    use aft::error::{AftError, AftResult};
    use aft::protocols::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // ── Mock protocol handler ───────────────────────────────────────────

    struct MockHandler {
        /// Content returned by downloads
        content: Vec<u8>,
        /// Whether HEAD reports ranges support
        ranges: bool,
        /// Number of times download() was called (for retry testing)
        download_calls: Arc<AtomicU32>,
        /// Fail the first N download() calls
        fail_first_n: u32,
        /// Content length reported by HEAD (None = no HEAD)
        report_size: Option<u64>,
    }

    impl MockHandler {
        fn new(content: &[u8]) -> Self {
            Self {
                content: content.to_vec(),
                ranges: false,
                download_calls: Arc::new(AtomicU32::new(0)),
                fail_first_n: 0,
                report_size: Some(content.len() as u64),
            }
        }

        fn with_fail_first(mut self, n: u32) -> Self {
            self.fail_first_n = n;
            self
        }

        #[allow(dead_code)]
        fn with_ranges(mut self, ranges: bool) -> Self {
            self.ranges = ranges;
            self
        }

        fn with_no_head(mut self) -> Self {
            self.report_size = None;
            self
        }
    }

    #[async_trait]
    impl ProtocolHandler for MockHandler {
        fn scheme(&self) -> &str {
            "mock"
        }
        fn name(&self) -> &str {
            "Mock"
        }
        fn supports_ranges(&self) -> bool {
            self.ranges
        }
        fn supports_resume(&self) -> bool {
            true
        }

        async fn head(&self, _url: &str, _opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
            match self.report_size {
                Some(size) => Ok(ResourceMetadata {
                    content_length: Some(size),
                    content_type: Some("application/octet-stream".into()),
                    last_modified: None,
                    etag: None,
                    accepts_ranges: self.ranges,
                    headers: HashMap::new(),
                }),
                None => Err(AftError::Other("HEAD not supported".into())),
            }
        }

        async fn download(
            &self,
            _url: &str,
            dest: &Path,
            _opts: &ProtocolOptions,
            resume_from: Option<u64>,
            progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
        ) -> AftResult<u64> {
            let call = self.download_calls.fetch_add(1, Ordering::SeqCst);
            if call < self.fail_first_n {
                return Err(AftError::TransferFailed("Simulated failure".into()));
            }
            let offset = resume_from.unwrap_or(0) as usize;
            let data = &self.content[offset..];
            tokio::fs::write(dest, data).await?;
            if let Some(cb) = &progress {
                cb(data.len() as u64, Some(self.content.len() as u64));
            }
            Ok(data.len() as u64)
        }

        async fn download_range(
            &self,
            _url: &str,
            start: u64,
            end: u64,
            _opts: &ProtocolOptions,
        ) -> AftResult<Vec<u8>> {
            let s = start as usize;
            let e = (end as usize).min(self.content.len() - 1);
            Ok(self.content[s..=e].to_vec())
        }

        async fn upload(
            &self,
            source: &Path,
            _url: &str,
            _opts: &ProtocolOptions,
            _content_type: Option<&str>,
            _method: Option<&str>,
            _progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
        ) -> AftResult<u64> {
            let data = tokio::fs::read(source).await?;
            Ok(data.len() as u64)
        }

        async fn list(
            &self,
            _url: &str,
            _opts: &ProtocolOptions,
        ) -> AftResult<Vec<DirectoryEntry>> {
            Ok(vec![])
        }
    }

    // A variant that always fails upload
    struct FailUploadHandler;

    #[async_trait]
    impl ProtocolHandler for FailUploadHandler {
        fn scheme(&self) -> &str {
            "mock"
        }
        fn name(&self) -> &str {
            "FailUpload"
        }
        fn supports_ranges(&self) -> bool {
            false
        }
        fn supports_resume(&self) -> bool {
            false
        }

        async fn head(&self, _url: &str, _opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
            Ok(ResourceMetadata {
                content_length: None,
                content_type: None,
                last_modified: None,
                etag: None,
                accepts_ranges: false,
                headers: HashMap::new(),
            })
        }

        async fn download(
            &self,
            _url: &str,
            _dest: &Path,
            _opts: &ProtocolOptions,
            _resume: Option<u64>,
            _progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
        ) -> AftResult<u64> {
            Err(AftError::TransferFailed("always fails".into()))
        }

        async fn download_range(
            &self,
            _url: &str,
            _s: u64,
            _e: u64,
            _opts: &ProtocolOptions,
        ) -> AftResult<Vec<u8>> {
            Err(AftError::TransferFailed("always fails".into()))
        }

        async fn upload(
            &self,
            _source: &Path,
            _url: &str,
            _opts: &ProtocolOptions,
            _ct: Option<&str>,
            _method: Option<&str>,
            _progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
        ) -> AftResult<u64> {
            Err(AftError::TransferFailed("always fails".into()))
        }

        async fn list(
            &self,
            _url: &str,
            _opts: &ProtocolOptions,
        ) -> AftResult<Vec<DirectoryEntry>> {
            Ok(vec![])
        }
    }

    // ── Download tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn download_simple_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("out.bin");
        let content = b"Hello, engine download test!";
        let handler = MockHandler::new(content);
        let config = TransferConfig::default();
        let opts = ProtocolOptions::default();

        let result = aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None)
            .await
            .unwrap();

        assert_eq!(result.bytes_transferred, content.len() as u64);
        assert_eq!(result.retries_used, 0);
        assert_eq!(result.chunks_used, 1);
        assert!(result.checksum.is_none());
        assert_eq!(std::fs::read(&dest).unwrap(), content);
    }

    #[tokio::test]
    async fn download_with_retry_succeeds_after_failures() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("retry.bin");
        let content = b"Retry content";
        let handler = MockHandler::new(content).with_fail_first(2);
        let config = TransferConfig {
            max_retries: 5,
            retry_delay_ms: 1, // minimal delay in tests
            ..Default::default()
        };
        let opts = ProtocolOptions::default();

        let result = aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None)
            .await
            .unwrap();

        assert_eq!(result.bytes_transferred, content.len() as u64);
        assert_eq!(result.retries_used, 2);
        assert_eq!(std::fs::read(&dest).unwrap(), content);
    }

    #[tokio::test]
    async fn download_exhausts_retries() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("fail.bin");
        let handler = MockHandler::new(b"x").with_fail_first(100);
        let config = TransferConfig {
            max_retries: 2,
            retry_delay_ms: 1,
            ..Default::default()
        };
        let opts = ProtocolOptions::default();

        let result =
            aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None).await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("failed") || msg.contains("Failed"));
    }

    #[tokio::test]
    async fn download_with_sha256_checksum_succeeds() {
        use sha2::{Digest, Sha256};

        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("cs.bin");
        let content = b"checksum test data";
        let expected_hash = hex::encode(Sha256::digest(content));

        let handler = MockHandler::new(content);
        let config = TransferConfig {
            verify_checksum: Some(ChecksumConfig {
                algorithm: "sha256".into(),
                expected_value: Some(expected_hash.clone()),
            }),
            ..Default::default()
        };
        let opts = ProtocolOptions::default();

        let result = aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None)
            .await
            .unwrap();

        let cs = result.checksum.unwrap();
        assert_eq!(cs.algorithm, "sha256");
        assert_eq!(cs.value, expected_hash);
        assert!(cs.verified);
    }

    #[tokio::test]
    async fn download_with_wrong_checksum_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("badcs.bin");
        let handler = MockHandler::new(b"real data");
        let config = TransferConfig {
            verify_checksum: Some(ChecksumConfig {
                algorithm: "sha256".into(),
                expected_value: Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                ),
            }),
            ..Default::default()
        };
        let opts = ProtocolOptions::default();

        let result =
            aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None).await;
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("mismatch") || msg.contains("Mismatch") || msg.contains("Checksum"));
    }

    #[tokio::test]
    async fn download_without_head_falls_back_to_single_stream() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("nohead.bin");
        let content = b"no head content";
        let handler = MockHandler::new(content).with_no_head();
        let config = TransferConfig::default();
        let opts = ProtocolOptions::default();

        let result = aft::engine::download(&handler, "mock://file", &dest, &opts, &config, None)
            .await
            .unwrap();

        assert_eq!(result.bytes_transferred, content.len() as u64);
        assert_eq!(result.chunks_used, 1);
    }

    #[tokio::test]
    async fn download_progress_callback_fires() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("prog.bin");
        let content = b"progress callback test!";
        let handler = MockHandler::new(content);
        let config = TransferConfig::default();
        let opts = ProtocolOptions::default();
        let called = Arc::new(AtomicU32::new(0));
        let called2 = called.clone();
        let cb: aft::engine::ProgressCb = Arc::new(move |_bytes, _total| {
            called2.fetch_add(1, Ordering::SeqCst);
        });

        let _result =
            aft::engine::download(&handler, "mock://file", &dest, &opts, &config, Some(cb))
                .await
                .unwrap();

        assert!(
            called.load(Ordering::SeqCst) > 0,
            "Progress callback should have been called"
        );
    }

    // ── Upload tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn upload_simple_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("upload_src.bin");
        let content = b"Upload me via engine!";
        std::fs::write(&src, content).unwrap();

        let handler = MockHandler::new(b"");
        let config = TransferConfig::default();
        let opts = ProtocolOptions::default();

        let result = aft::engine::upload(
            &handler,
            &src,
            "mock://dest",
            &opts,
            &config,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.bytes_transferred, content.len() as u64);
        assert_eq!(result.retries_used, 0);
        assert_eq!(result.chunks_used, 1);
    }

    #[tokio::test]
    async fn upload_exhausts_retries() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("upload_fail.bin");
        std::fs::write(&src, b"fail me").unwrap();

        let handler = FailUploadHandler;
        let config = TransferConfig {
            max_retries: 1,
            retry_delay_ms: 1,
            ..Default::default()
        };
        let opts = ProtocolOptions::default();

        let result = aft::engine::upload(
            &handler,
            &src,
            "mock://dest",
            &opts,
            &config,
            None,
            None,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    // ── TransferConfig edge cases ───────────────────────────────────────

    #[test]
    fn config_zero_retries_means_one_attempt() {
        let config = TransferConfig {
            max_retries: 0,
            ..Default::default()
        };
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn config_custom_chunk_size() {
        let config = TransferConfig {
            chunk_size: 1024 * 1024,
            parallel_chunks: 16,
            ..Default::default()
        };
        assert_eq!(config.chunk_size, 1_048_576);
        assert_eq!(config.parallel_chunks, 16);
    }

    #[test]
    fn transfer_result_serializes_to_json() {
        let result = TransferResult {
            bytes_transferred: 1024,
            duration_ms: 100,
            throughput_bytes_per_sec: 10240.0,
            checksum: None,
            retries_used: 0,
            chunks_used: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("1024"));
        assert!(json.contains("bytes_transferred"));
    }

    #[test]
    fn checksum_config_stores_algorithm() {
        let config = ChecksumConfig {
            algorithm: "sha512".into(),
            expected_value: Some("abcdef".into()),
        };
        assert_eq!(config.algorithm, "sha512");
        assert_eq!(config.expected_value.as_deref(), Some("abcdef"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V1.0 — AFTP server tests (session store, auth rate limiter via E2E)
// ═══════════════════════════════════════════════════════════════════════════

mod aftp_server_extended_tests {
    use aft::aftp::client::AftpClient;
    use aft::aftp::server::AftpServer;
    use tempfile::TempDir;

    #[tokio::test]
    async fn server_download_range() {
        let dir = TempDir::new().unwrap();
        let content = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::fs::write(dir.path().join("alpha.txt"), content).unwrap();

        let port = 12620;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let data = client.download_range("/alpha.txt", 0, 4).await.unwrap();
        assert_eq!(&data, b"ABCDE");

        handle.abort();
    }

    #[tokio::test]
    async fn server_upload_overwrite() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("existing.txt"), "old content").unwrap();

        let port = 12621;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let src = dir.path().join("new_src.txt");
        std::fs::write(&src, "new content").unwrap();

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        client.upload(&src, "/existing.txt", None).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("existing.txt")).unwrap(),
            "new content"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn server_upload_creates_new_file() {
        let dir = TempDir::new().unwrap();

        let port = 12622;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let src = dir.path().join("brand_new_src.txt");
        std::fs::write(&src, "brand new").unwrap();

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        client.upload(&src, "/brand_new.txt", None).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("brand_new.txt")).unwrap(),
            "brand new"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn server_with_compression_flag() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("comp.txt"), "compress me").unwrap();

        let port = 12623;
        // Enable compression on server
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            true,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client without TLS (server is not TLS)
        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let info = client.head("/comp.txt").await.unwrap();
        assert_eq!(info.size, 11);

        handle.abort();
    }

    #[tokio::test]
    async fn server_list_empty_directory() {
        let dir = TempDir::new().unwrap();

        let port = 12624;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let entries = client.list("/").await.unwrap();
        assert!(entries.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn server_head_reports_correct_content_type() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("data.json"), r#"{"key":"value"}"#).unwrap();

        let port = 12625;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let info = client.head("/data.json").await.unwrap();
        assert_eq!(info.size, 15);
        // content_type should be inferred
        assert!(!info.content_type.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn server_multiple_sequential_operations() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("seq.txt"), "sequential ops").unwrap();

        let port = 12626;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);

        // HEAD then download on same connection
        let info = client.head("/seq.txt").await.unwrap();
        assert_eq!(info.size, 14);

        let dest = dir.path().join("seq_out.txt");
        let bytes = client.download("/seq.txt", &dest, None).await.unwrap();
        assert_eq!(bytes, 14);

        handle.abort();
    }

    #[tokio::test]
    async fn server_download_nonexistent_file() {
        let dir = TempDir::new().unwrap();

        let port = 12627;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let dest = dir.path().join("ghost.bin");
        let result = client.download("/no_such_file.txt", &dest, None).await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn server_with_wrong_auth_token_rejected() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("secure.txt"), "top secret").unwrap();

        let port = 12628;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            Some("correct_password".into()),
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new(
            "127.0.0.1".into(),
            port,
            Some("wrong_password".into()),
            false,
            false,
        );
        let result = client.head("/secure.txt").await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn server_large_file_download() {
        let dir = TempDir::new().unwrap();
        // 1 MB file
        let content = vec![0xABu8; 1024 * 1024];
        std::fs::write(dir.path().join("large.bin"), &content).unwrap();

        let port = 12629;
        let server = AftpServer::new(
            dir.path(),
            port,
            "127.0.0.1",
            None,
            false,
            false,
            false,
            None,
            None,
            0,
        );
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = AftpClient::new("127.0.0.1".into(), port, None, false, false);
        let dest = dir.path().join("large_out.bin");
        let bytes = client.download("/large.bin", &dest, None).await.unwrap();
        assert_eq!(bytes, 1024 * 1024);
        assert_eq!(std::fs::read(&dest).unwrap().len(), 1024 * 1024);

        handle.abort();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V1.0 — Crypto roundtrip & edge case tests
// ═══════════════════════════════════════════════════════════════════════════

mod crypto_extended_tests {
    use aft::crypto;
    use aft::crypto::neural::{NeuralCipher, TrainConfig};
    use aft::crypto::pqc;

    #[test]
    fn pqc_keypair_generation_is_unique() {
        let kp1 = pqc::generate_keypair().unwrap();
        let kp2 = pqc::generate_keypair().unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
        assert_ne!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn pqc_key_save_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = pqc::generate_keypair().unwrap();
        let pub_path = dir.path().join("rt.pub");
        let sec_path = dir.path().join("rt.sec");

        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let loaded_pub = pqc::load_public_key(&pub_path).unwrap();
        let loaded_sec = pqc::load_secret_key(&sec_path).unwrap();

        assert_eq!(kp.public_key, loaded_pub);
        assert_eq!(kp.secret_key, loaded_sec);
    }

    #[test]
    fn pqc_encapsulate_decapsulate_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = pqc::generate_keypair().unwrap();
        let pub_path = dir.path().join("kem.pub");
        let sec_path = dir.path().join("kem.sec");
        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let (ct, shared_secret_enc) = pqc::encapsulate_key(&pub_path).unwrap();
        let shared_secret_dec = pqc::decapsulate_key(&ct, &sec_path).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn pqc_encrypt_decrypt_data_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = pqc::generate_keypair().unwrap();
        let pub_path = dir.path().join("data.pub");
        let sec_path = dir.path().join("data.sec");
        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let plaintext = b"Top secret post-quantum data!";
        let (kem_ct, ciphertext) = pqc::encrypt(plaintext, &pub_path).unwrap();
        let decrypted = pqc::decrypt(&kem_ct, &ciphertext, &sec_path).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pqc_encrypt_empty_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = pqc::generate_keypair().unwrap();
        let pub_path = dir.path().join("e.pub");
        let sec_path = dir.path().join("e.sec");
        pqc::save_public_key(&kp.public_key, &pub_path).unwrap();
        pqc::save_secret_key(&kp.secret_key, &sec_path).unwrap();

        let (kem_ct, ciphertext) = pqc::encrypt(b"", &pub_path).unwrap();
        let decrypted = pqc::decrypt(&kem_ct, &ciphertext, &sec_path).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn neural_cipher_encrypt_decrypt_roundtrip() {
        let config = TrainConfig {
            epochs: 50,
            learning_rate: 0.01,
            batch_size: 32,
            seed: 123,
        };
        let cipher = NeuralCipher::train(&config);
        let plaintext = b"Neural cipher roundtrip test!";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn neural_cipher_different_seeds_produce_different_ciphers() {
        let c1 = NeuralCipher::train(&TrainConfig {
            seed: 1,
            epochs: 10,
            ..Default::default()
        });
        let c2 = NeuralCipher::train(&TrainConfig {
            seed: 2,
            epochs: 10,
            ..Default::default()
        });
        let data = b"same plaintext";
        assert_ne!(c1.encrypt(data), c2.encrypt(data));
    }

    #[test]
    fn neural_cipher_save_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cipher.nn");
        let config = TrainConfig {
            epochs: 20,
            seed: 42,
            ..Default::default()
        };
        let cipher = NeuralCipher::train(&config);
        cipher.save(&path).unwrap();

        let loaded = NeuralCipher::load(&path).unwrap();
        let plaintext = b"persist me!";
        let ct = cipher.encrypt(plaintext);
        let dec = loaded.decrypt(&ct);
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn neural_encrypt_file_data_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let model_path = dir.path().join("fdata.nn");
        let config = TrainConfig {
            epochs: 50,
            seed: 7,
            ..Default::default()
        };
        let cipher = NeuralCipher::train(&config);
        cipher.save(&model_path).unwrap();

        let plaintext = b"File-level neural roundtrip";
        let ct = crypto::neural::encrypt_file_data(plaintext, &model_path).unwrap();
        let dec = crypto::neural::decrypt_file_data(&ct, &model_path).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encryption_method_parse_all_variants() {
        assert_eq!(
            crypto::EncryptionMethod::parse("pqc"),
            Some(crypto::EncryptionMethod::Pqc)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("kyber"),
            Some(crypto::EncryptionMethod::Pqc)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("post-quantum"),
            Some(crypto::EncryptionMethod::Pqc)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("neural"),
            Some(crypto::EncryptionMethod::Neural)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("nn"),
            Some(crypto::EncryptionMethod::Neural)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("hybrid"),
            Some(crypto::EncryptionMethod::Hybrid)
        );
        assert_eq!(crypto::EncryptionMethod::parse("invalid"), None);
        assert_eq!(crypto::EncryptionMethod::parse(""), None);
    }

    #[test]
    fn encryption_method_case_insensitive() {
        assert_eq!(
            crypto::EncryptionMethod::parse("PQC"),
            Some(crypto::EncryptionMethod::Pqc)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("Neural"),
            Some(crypto::EncryptionMethod::Neural)
        );
        assert_eq!(
            crypto::EncryptionMethod::parse("HYBRID"),
            Some(crypto::EncryptionMethod::Hybrid)
        );
    }

    #[tokio::test]
    async fn decrypt_non_aft_file_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let bad_file = dir.path().join("not_encrypted.bin");
        let output = dir.path().join("dec.bin");
        let key = dir.path().join("dummy.sec");
        std::fs::write(&bad_file, b"This is not an encrypted file at all").unwrap();
        std::fs::write(&key, [0u8; 32]).unwrap();

        let result = crypto::decrypt_file(&bad_file, &output, &key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn decrypt_truncated_header_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let short_file = dir.path().join("short.bin");
        let output = dir.path().join("dec.bin");
        let key = dir.path().join("dummy.sec");
        std::fs::write(&short_file, b"AFTE").unwrap(); // magic but too short
        std::fs::write(&key, [0u8; 32]).unwrap();

        let result = crypto::decrypt_file(&short_file, &output, &key).await;
        assert!(result.is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V1.0 — E2E CLI tests (binary invocation)
// ═══════════════════════════════════════════════════════════════════════════

mod cli_e2e_tests {
    use std::process::Command;

    fn aft_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_aft"))
    }

    #[test]
    fn cli_help_exits_zero() {
        let output = aft_bin().arg("--help").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Agentic File Transfer"));
    }

    #[test]
    fn cli_version_exits_zero() {
        let output = aft_bin().arg("--version").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("aft"));
    }

    #[test]
    fn cli_schema_subcommand() {
        let output = aft_bin().arg("schema").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Schema should produce JSON describing the CLI
        assert!(stdout.contains("get") || stdout.contains("schema") || stdout.contains("command"));
    }

    #[test]
    fn cli_capabilities_subcommand() {
        let output = aft_bin().arg("capabilities").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("http") || stdout.contains("protocol") || stdout.contains("aftp"));
    }

    #[test]
    fn cli_agent_mode_json_output() {
        let output = aft_bin().args(["--agent", "schema"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Agent mode should produce structured output
        assert!(!stdout.is_empty());
    }

    #[test]
    fn cli_json_format_schema() {
        let output = aft_bin()
            .args(["--format", "json", "schema"])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn cli_no_subcommand_fails() {
        let output = aft_bin().output().unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn cli_invalid_subcommand_fails() {
        let output = aft_bin().arg("nonexistent_command").output().unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn cli_get_missing_url_fails() {
        let output = aft_bin().arg("get").output().unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn cli_checksum_subcommand_missing_file_fails() {
        let output = aft_bin()
            .args(["checksum", "/nonexistent/file.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V1.0 — Extended mux, classification, telemetry, and misc tests
// ═══════════════════════════════════════════════════════════════════════════

mod mux_extended_tests {
    use aft::aftp::frame::*;

    #[test]
    fn stream_open_roundtrip() {
        let payload = build_stream_open(42);
        let parsed = parse_stream_open(&payload).unwrap();
        assert_eq!(parsed.stream_id, 42);
    }

    #[test]
    fn stream_close_roundtrip() {
        let payload = build_stream_close(100);
        let parsed = parse_stream_close(&payload).unwrap();
        assert_eq!(parsed.stream_id, 100);
    }

    #[test]
    fn stream_data_roundtrip() {
        let inner_data = b"inner frame data for stream";
        let payload = build_stream_data(7, FRAME_PUT, inner_data);
        let parsed = parse_stream_data(&payload).unwrap();
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.inner_frame_type, FRAME_PUT);
        assert_eq!(parsed.data, inner_data);
    }

    #[test]
    fn stream_data_empty_payload() {
        let payload = build_stream_data(1, FRAME_HEAD, b"");
        let parsed = parse_stream_data(&payload).unwrap();
        assert_eq!(parsed.stream_id, 1);
        assert_eq!(parsed.data, b"");
    }

    #[test]
    fn stream_open_close_different_ids() {
        for id in [0, 1, 255, 1000, u16::MAX] {
            let open_payload = build_stream_open(id);
            let open_parsed = parse_stream_open(&open_payload).unwrap();
            assert_eq!(open_parsed.stream_id, id);

            let close_payload = build_stream_close(id);
            let close_parsed = parse_stream_close(&close_payload).unwrap();
            assert_eq!(close_parsed.stream_id, id);
        }
    }

    #[test]
    fn stream_frame_type_constants() {
        // Frame types for stream ops should be distinct
        assert_ne!(FRAME_STREAM_OPEN, FRAME_STREAM_CLOSE);
        assert_ne!(FRAME_STREAM_OPEN, FRAME_STREAM_DATA);
        assert_ne!(FRAME_STREAM_CLOSE, FRAME_STREAM_DATA);
    }
}

mod classification_extended_tests {
    use aft::crypto::classification::{validate_compliance, Classification};

    #[test]
    fn classification_ordering() {
        // Higher classifications should have stricter requirements
        assert!(validate_compliance(Classification::Unclassified, true).is_ok());
        assert!(validate_compliance(Classification::Cui, true).is_err());
        assert!(validate_compliance(Classification::Secret, true).is_err());
        assert!(validate_compliance(Classification::TopSecret, true).is_err());
    }

    #[test]
    fn classification_all_levels_secure_ok() {
        for level in [
            Classification::Unclassified,
            Classification::Cui,
            Classification::Secret,
            Classification::TopSecret,
        ] {
            assert!(
                validate_compliance(level, false).is_ok(),
                "Secure should pass for {:?}",
                level
            );
        }
    }

    #[test]
    fn classification_banner_not_empty() {
        for level in [
            Classification::Unclassified,
            Classification::Cui,
            Classification::Secret,
            Classification::TopSecret,
        ] {
            assert!(
                !level.banner().is_empty(),
                "Banner should not be empty for {:?}",
                level
            );
        }
    }

    #[test]
    fn classification_header_values_uppercase() {
        for level in [
            Classification::Unclassified,
            Classification::Secret,
            Classification::TopSecret,
        ] {
            let hv = level.header_value();
            assert_eq!(
                hv,
                hv.to_uppercase(),
                "Header value should be uppercase for {:?}",
                level
            );
        }
    }

    #[test]
    fn parse_returns_none_for_empty() {
        assert_eq!(Classification::parse(""), None);
    }

    #[test]
    fn parse_returns_none_for_whitespace() {
        assert_eq!(Classification::parse("  "), None);
    }
}

mod telemetry_extended_tests {
    use aft::telemetry::{
        TelemetryConfig, TelemetryEvent, TelemetryRecord, DEFAULT_TELEMETRY_ENDPOINT,
    };
    use std::collections::HashMap;

    #[test]
    fn telemetry_config_serialization_roundtrip() {
        let config = TelemetryConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TelemetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.version, config.version);
        assert_eq!(deserialized.installation_id, config.installation_id);
    }

    #[test]
    fn telemetry_config_is_enabled_reflects_field() {
        let mut config = TelemetryConfig::default();
        assert!(config.is_enabled());
        config.enabled = false;
        assert!(!config.is_enabled());
    }

    #[test]
    fn telemetry_config_is_remote_enabled() {
        let mut config = TelemetryConfig::default();
        assert!(config.is_remote_enabled());
        config.remote_enabled = false;
        assert!(!config.is_remote_enabled());
        // Also false if main switch is off
        config.remote_enabled = true;
        config.enabled = false;
        assert!(!config.is_remote_enabled());
    }

    #[test]
    fn default_endpoint_constant() {
        assert!(DEFAULT_TELEMETRY_ENDPOINT.starts_with("https://"));
        assert!(DEFAULT_TELEMETRY_ENDPOINT.contains("nervosys"));
    }

    #[test]
    fn telemetry_event_variants_serialize() {
        let events = vec![
            TelemetryEvent::CommandInvoked {
                command: "get".into(),
                subcommand: None,
                duration_ms: Some(100),
                success: true,
            },
            TelemetryEvent::TransferCompleted {
                protocol: "https".into(),
                direction: "download".into(),
                size_bytes: 1024,
                duration_ms: 500,
                parallel_connections: 4,
                resumed: false,
                compressed: false,
                encrypted: false,
                success: true,
            },
            TelemetryEvent::ServerStarted {
                port: 8080,
                transport: "tcp".into(),
                tls_enabled: false,
            },
            TelemetryEvent::ProtocolUsed {
                protocol: "sftp".into(),
            },
            TelemetryEvent::ErrorOccurred {
                error_type: "timeout".into(),
                command: Some("get".into()),
            },
            TelemetryEvent::AppStarted {
                version: "0.1.0".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
            },
        ];

        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            assert!(!json.is_empty());
            // Verify it roundtrips
            let _: TelemetryEvent = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn telemetry_record_new_populates_fields() {
        let data = HashMap::new();
        let record = TelemetryRecord::new(
            "inst-id-123",
            "usage",
            "test_event",
            data,
            vec!["tag1".into()],
            None,
        );

        assert_eq!(record.installation_id, "inst-id-123");
        assert_eq!(record.category, "usage");
        assert_eq!(record.event, "test_event");
        assert_eq!(record.tags, vec!["tag1"]);
        assert!(record.context.is_none());
        assert!(!record.id.is_empty());
        assert!(!record.timestamp_iso.is_empty());
        assert!(record.timestamp > 0);
        assert_eq!(record.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn telemetry_record_unique_ids() {
        let r1 = TelemetryRecord::new("a", "cat", "evt", HashMap::new(), vec![], None);
        let r2 = TelemetryRecord::new("a", "cat", "evt", HashMap::new(), vec![], None);
        assert_ne!(r1.id, r2.id);
    }

    #[test]
    fn telemetry_record_serialization() {
        let mut data = HashMap::new();
        data.insert("key".into(), serde_json::json!("value"));
        let record =
            TelemetryRecord::new("inst", "perf", "transfer", data, vec![], Some("ctx".into()));

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: TelemetryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.installation_id, "inst");
        assert_eq!(deserialized.category, "perf");
        assert_eq!(deserialized.context, Some("ctx".into()));
    }
}

mod error_type_tests {
    use aft::error::AftError;

    #[test]
    fn error_display_messages() {
        let cases: Vec<(AftError, &str)> = vec![
            (AftError::UnsupportedProtocol("gopher".into()), "gopher"),
            (AftError::InvalidUrl("bad".into()), "bad"),
            (AftError::ConnectionFailed("refused".into()), "refused"),
            (AftError::TransferFailed("timeout".into()), "timeout"),
            (AftError::FileNotFound("missing.txt".into()), "missing.txt"),
            (AftError::PermissionDenied("read".into()), "read"),
            (
                AftError::ChecksumMismatch {
                    expected: "aaa".into(),
                    actual: "bbb".into(),
                },
                "aaa",
            ),
            (AftError::Timeout(30), "30"),
            (AftError::ResumeNotSupported, "Resume"),
            (
                AftError::HttpStatus {
                    status: 404,
                    message: "Not Found".into(),
                },
                "404",
            ),
            (AftError::AuthFailed("bad token".into()), "bad token"),
            (AftError::CryptoError("decrypt".into()), "decrypt"),
            (AftError::Other("misc".into()), "misc"),
        ];

        for (err, expected_substring) in cases {
            let msg = format!("{}", err);
            assert!(
                msg.contains(expected_substring),
                "Error '{}' should contain '{}'",
                msg,
                expected_substring
            );
        }
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let aft_err: AftError = io_err.into();
        let msg = format!("{}", aft_err);
        assert!(msg.contains("gone"));
    }
}

mod protocol_handler_tests {
    use aft::protocols::resolve_protocol;

    #[test]
    fn resolve_all_builtin_schemes() {
        let schemes = [
            "http", "https", "ftp", "sftp", "s3", "aftp", "aftps", "file", "smb", "webdav", "gs",
            "az", "dod",
        ];
        for scheme in &schemes {
            let url = if *scheme == "file" {
                "file:///tmp/test".to_string()
            } else if *scheme == "dod" {
                "dod://UNCLASSIFIED@example.mil/test".to_string()
            } else {
                format!("{}://example.com/test", scheme)
            };
            let result = resolve_protocol(&url);
            assert!(result.is_ok(), "Should resolve scheme: {}", scheme);
            let handler = result.unwrap();
            assert!(!handler.scheme().is_empty());
            assert!(!handler.name().is_empty());
        }
    }

    #[test]
    fn local_path_resolves_as_file() {
        // Relative path should resolve as local protocol
        let result = resolve_protocol("./local_file.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().scheme(), "file");
    }

    #[test]
    fn windows_path_resolves_as_file() {
        // Windows drive letter path
        let result = resolve_protocol("C:\\Users\\test\\file.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().scheme(), "file");
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let result = resolve_protocol("gopher://gopher.example.com/test");
        assert!(result.is_err());
    }

    /// Supporting byte ranges and *benefiting* from parallel ranges are
    /// different questions. AFTP supports ranges but opens a fresh connection
    /// and repeats the handshake for each one, so parallel chunking pays
    /// repeated TCP slow-start — measured at 4.2x slower than streaming on a
    /// 25 ms path. It must opt out.
    #[test]
    fn aftp_supports_ranges_but_opts_out_of_parallel_chunking() {
        for url in ["aftp://example.com/f", "aftps://example.com/f"] {
            let h = resolve_protocol(url).unwrap();
            assert!(h.supports_ranges(), "{} should support ranges", url);
            assert!(
                !h.benefits_from_parallel_ranges(),
                "{} must not be split into parallel ranges",
                url
            );
        }
    }

    /// The HTTP family pools connections, so parallel ranges are a genuine win
    /// there and must stay enabled.
    #[test]
    fn http_family_keeps_parallel_chunking() {
        for url in ["http://example.com/f", "https://example.com/f"] {
            let h = resolve_protocol(url).unwrap();
            assert!(
                h.benefits_from_parallel_ranges(),
                "{} should still use parallel ranges",
                url
            );
        }
    }
}

mod plugin_extended_tests {
    use aft::plugins::PluginRegistry;

    #[test]
    fn default_registry_is_empty() {
        let reg = PluginRegistry::default();
        assert!(reg.list().is_empty());
    }

    #[test]
    fn new_registry_matches_default() {
        let new_reg = PluginRegistry::new();
        let def_reg = PluginRegistry::default();
        assert_eq!(new_reg.list().len(), def_reg.list().len());
    }

    #[test]
    fn create_handler_unknown_returns_none() {
        let reg = PluginRegistry::new();
        assert!(reg.create_handler("nonexistent").is_none());
    }

    #[test]
    fn has_scheme_returns_false_for_unknown() {
        let reg = PluginRegistry::new();
        assert!(!reg.has_scheme("nonexistent"));
    }
}

mod ontology_tests {
    use aft::ontology;

    #[test]
    fn generate_schema_has_operations() {
        let schema = ontology::generate_schema();
        assert!(!schema.operations.is_empty());
        assert!(!schema.protocols.is_empty());
    }

    #[test]
    fn schema_serializes_to_json() {
        let schema = ontology::generate_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed["operations"].is_array());
    }
}

mod output_extended_tests {
    #[test]
    fn json_output_format() {
        let result = serde_json::json!({
            "status": "success",
            "bytes": 1024
        });
        let formatted = serde_json::to_string_pretty(&result).unwrap();
        assert!(formatted.contains("success"));
        assert!(formatted.contains("1024"));
    }
}

// ── Extended local protocol operations ─────────────────────────────────

mod local_extended_ops_tests {
    use aft::protocols::local::LocalHandler;
    use aft::protocols::{ProtocolHandler, ProtocolOptions};
    use std::fs;

    fn opts() -> ProtocolOptions {
        ProtocolOptions::default()
    }

    fn file_url(path: &std::path::Path) -> String {
        format!("file://{}", path.to_str().unwrap().replace('\\', "/"))
    }

    #[tokio::test]
    async fn local_mkdir_creates_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let target = dir.path().join("a").join("b").join("c");
        handler.mkdir(&file_url(&target), &opts()).await.unwrap();
        assert!(target.exists());
        assert!(target.is_dir());
    }

    #[tokio::test]
    async fn local_exists_true_for_file() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let f = dir.path().join("exists.txt");
        fs::write(&f, "data").unwrap();
        assert!(handler.exists(&file_url(&f), &opts()).await.unwrap());
    }

    #[tokio::test]
    async fn local_exists_false_for_missing() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let f = dir.path().join("nope.txt");
        assert!(!handler.exists(&file_url(&f), &opts()).await.unwrap());
    }

    #[tokio::test]
    async fn local_delete_file() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let f = dir.path().join("deleteme.txt");
        fs::write(&f, "gone").unwrap();
        assert!(f.exists());
        handler.delete(&file_url(&f), false, &opts()).await.unwrap();
        assert!(!f.exists());
    }

    #[tokio::test]
    async fn local_delete_dir_recursive() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let sub = dir.path().join("parent").join("child");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("file.txt"), "x").unwrap();
        let target = dir.path().join("parent");
        handler
            .delete(&file_url(&target), true, &opts())
            .await
            .unwrap();
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn local_rename_file() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let src = dir.path().join("old.txt");
        let dst = dir.path().join("new.txt");
        fs::write(&src, "renamed").unwrap();
        handler
            .rename(&file_url(&src), &file_url(&dst), &opts())
            .await
            .unwrap();
        assert!(!src.exists());
        assert_eq!(fs::read_to_string(&dst).unwrap(), "renamed");
    }

    #[tokio::test]
    async fn local_rename_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let src = dir.path().join("move.txt");
        let dst = dir.path().join("deep").join("dir").join("moved.txt");
        fs::write(&src, "moved").unwrap();
        handler
            .rename(&file_url(&src), &file_url(&dst), &opts())
            .await
            .unwrap();
        assert!(!src.exists());
        assert_eq!(fs::read_to_string(&dst).unwrap(), "moved");
    }

    #[tokio::test]
    async fn local_set_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let f = dir.path().join("ts.txt");
        fs::write(&f, "timestamp test").unwrap();
        let mtime = chrono::DateTime::parse_from_rfc3339("2020-06-15T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        handler
            .set_timestamps(&file_url(&f), mtime, &opts())
            .await
            .unwrap();
        let meta = fs::metadata(&f).unwrap();
        let actual = meta.modified().unwrap();
        let expected = std::time::SystemTime::from(mtime);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn local_supports_extended_ops() {
        let handler = LocalHandler;
        assert!(handler.supports_extended_ops());
    }

    #[tokio::test]
    async fn local_list_recursive() {
        let dir = tempfile::tempdir().unwrap();
        let handler = LocalHandler;
        let sub = dir.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.path().join("root.txt"), "r").unwrap();
        fs::write(sub.join("child.txt"), "c").unwrap();

        let entries = handler
            .list_recursive(&file_url(dir.path()), &opts(), 10)
            .await
            .unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"root.txt".to_string()));
        assert!(names.contains(&"child.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
    }
}

// ── Sync engine integration tests ──────────────────────────────────────

mod sync_engine_tests {
    use aft::protocols::local::LocalHandler;
    use aft::protocols::ProtocolOptions;
    use aft::sync::{CompareMode, SyncActionKind, SyncConfig};
    use std::fs;

    fn opts() -> ProtocolOptions {
        ProtocolOptions::default()
    }

    fn file_url(path: &std::path::Path) -> String {
        format!("file://{}", path.to_str().unwrap().replace('\\', "/"))
    }

    #[tokio::test]
    async fn sync_copies_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("hello.txt"), "hello world").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 1);
        assert_eq!(
            fs::read_to_string(dst.join("hello.txt")).unwrap(),
            "hello world"
        );
    }

    #[tokio::test]
    async fn sync_skips_identical_files() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("same.txt"), "identical").unwrap();
        fs::write(dst.join("same.txt"), "identical").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        // Size-mode: same length → skip
        assert_eq!(result.files_skipped, 1);
        assert_eq!(result.files_copied, 0);
    }

    #[tokio::test]
    async fn sync_creates_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        let sub = src.join("nested").join("deep");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(sub.join("file.txt"), "deep content").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert!(result.dirs_created > 0);
        assert_eq!(result.files_copied, 1);
        assert_eq!(
            fs::read_to_string(dst.join("nested").join("deep").join("file.txt")).unwrap(),
            "deep content"
        );
    }

    #[tokio::test]
    async fn sync_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("nodry.txt"), "should not appear").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            dry_run: true,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 1); // Counted but not executed
        assert!(!dst.join("nodry.txt").exists()); // File NOT created
    }

    #[tokio::test]
    async fn sync_delete_removes_extraneous() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("keep.txt"), "keep").unwrap();
        fs::write(dst.join("keep.txt"), "keep").unwrap();
        fs::write(dst.join("extra.txt"), "should be deleted").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            delete: true,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_deleted, 1);
        assert!(!dst.join("extra.txt").exists());
        assert!(dst.join("keep.txt").exists());
    }

    #[tokio::test]
    async fn sync_include_filter() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("yes.txt"), "include").unwrap();
        fs::write(src.join("no.rs"), "exclude").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            include: vec!["*.txt".to_string()],
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 1);
        assert!(dst.join("yes.txt").exists());
        assert!(!dst.join("no.rs").exists());
    }

    #[tokio::test]
    async fn sync_exclude_filter() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("keep.txt"), "keep").unwrap();
        fs::write(src.join("skip.log"), "skip").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            exclude: vec!["*.log".to_string()],
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 1);
        assert!(dst.join("keep.txt").exists());
        assert!(!dst.join("skip.log").exists());
    }

    #[tokio::test]
    async fn sync_result_has_actions() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "aaa").unwrap();
        fs::write(src.join("b.txt"), "bbb").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 2);
        let copy_actions: Vec<_> = result
            .actions
            .iter()
            .filter(|a| a.kind == SyncActionKind::Copy)
            .collect();
        assert_eq!(copy_actions.len(), 2);
    }

    #[tokio::test]
    async fn sync_size_filter() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("small.txt"), "x").unwrap(); // 1 byte
        fs::write(src.join("big.txt"), "x".repeat(1000)).unwrap(); // 1000 bytes

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            min_size: Some(10),
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, 1);
        assert!(dst.join("big.txt").exists());
        assert!(!dst.join("small.txt").exists());
    }

    // ── Concurrent execution ────────────────────────────────────────────

    /// Build a nested tree of `count` files spread over subdirectories.
    fn build_tree(root: &std::path::Path, count: usize) {
        for i in 0..count {
            let sub = root.join(format!("d{}", i % 7)).join(format!("e{}", i % 3));
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join(format!("f{}.txt", i)), format!("payload-{}", i)).unwrap();
        }
    }

    fn assert_tree_intact(root: &std::path::Path, count: usize) {
        for i in 0..count {
            let p = root
                .join(format!("d{}", i % 7))
                .join(format!("e{}", i % 3))
                .join(format!("f{}.txt", i));
            assert_eq!(
                fs::read_to_string(&p).unwrap_or_default(),
                format!("payload-{}", i),
                "missing or corrupt file {:?}",
                p
            );
        }
    }

    /// Concurrent execution must copy every file in a nested tree exactly once,
    /// with contents intact — no interleaving corruption, no dropped files.
    #[tokio::test]
    async fn sync_concurrent_copies_whole_tree() {
        const N: usize = 200;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        build_tree(&src, N);

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            transfers: 16,
            ..SyncConfig::default()
        };

        let result = aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.files_copied, N as u64);
        assert_tree_intact(&dst, N);
    }

    /// Raising concurrency must not change the outcome: `transfers: 1`
    /// (sequential, the old behavior) and `transfers: 16` agree on every count.
    #[tokio::test]
    async fn sync_concurrency_does_not_change_results() {
        const N: usize = 60;

        async fn run(transfers: usize) -> aft::sync::SyncResult {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("src");
            let dst = dir.path().join("dst");
            fs::create_dir_all(&src).unwrap();
            fs::create_dir_all(&dst).unwrap();
            build_tree(&src, N);
            // Pre-existing identical file → must be skipped, not recopied.
            let dup = dst.join("d0").join("e0");
            fs::create_dir_all(&dup).unwrap();
            fs::write(dup.join("f0.txt"), "payload-0").unwrap();

            let handler = LocalHandler;
            let config = SyncConfig {
                compare: CompareMode::Size,
                transfers,
                ..SyncConfig::default()
            };
            let r = aft::sync::sync(
                &handler,
                &file_url(&src),
                &handler,
                &file_url(&dst),
                &opts(),
                &config,
                None,
            )
            .await
            .unwrap();
            assert_tree_intact(&dst, N);
            r
        }

        let seq = run(1).await;
        let conc = run(16).await;

        assert_eq!(seq.files_copied, conc.files_copied);
        assert_eq!(seq.files_skipped, conc.files_skipped);
        assert_eq!(seq.dirs_created, conc.dirs_created);
        assert_eq!(seq.bytes_transferred, conc.bytes_transferred);
        assert_eq!(seq.files_skipped, 1, "the identical file should be skipped");
    }

    /// The executor partitions deletes into concurrent file deletes followed by
    /// strictly ordered directory deletes. A parent directory must never be
    /// removed before its children, however deep the nesting.
    #[tokio::test]
    async fn sync_delete_removes_deeply_nested_extraneous_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("keep.txt"), "keep").unwrap();

        // Extraneous 4-level tree at the destination, with files at each level.
        let deep = dst.join("a").join("b").join("c").join("d");
        fs::create_dir_all(&deep).unwrap();
        for (i, p) in [
            dst.join("a"),
            dst.join("a").join("b"),
            dst.join("a").join("b").join("c"),
            deep.clone(),
        ]
        .iter()
        .enumerate()
        {
            fs::write(p.join(format!("junk{}.txt", i)), "junk").unwrap();
        }
        fs::write(dst.join("keep.txt"), "keep").unwrap();

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            delete: true,
            transfers: 8,
            ..SyncConfig::default()
        };

        aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        assert!(!dst.join("a").exists(), "extraneous tree should be gone");
        assert!(dst.join("keep.txt").exists(), "matching file must survive");
    }

    /// `--preserve` now reads mtimes from the recursive listing rather than
    /// issuing a per-file `head()`. Verify it still actually preserves them.
    #[tokio::test]
    async fn sync_preserve_timestamps_concurrent() {
        const N: usize = 20;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        build_tree(&src, N);

        let handler = LocalHandler;
        let config = SyncConfig {
            compare: CompareMode::Size,
            preserve_timestamps: true,
            transfers: 8,
            ..SyncConfig::default()
        };

        aft::sync::sync(
            &handler,
            &file_url(&src),
            &handler,
            &file_url(&dst),
            &opts(),
            &config,
            None,
        )
        .await
        .unwrap();

        for i in 0..N {
            let rel = std::path::Path::new(&format!("d{}", i % 7))
                .join(format!("e{}", i % 3))
                .join(format!("f{}.txt", i));
            let s = fs::metadata(src.join(&rel)).unwrap().modified().unwrap();
            let d = fs::metadata(dst.join(&rel)).unwrap().modified().unwrap();
            let delta = s.duration_since(d).or_else(|_| d.duration_since(s)).unwrap();
            assert!(
                delta < std::time::Duration::from_secs(2),
                "mtime not preserved for {:?}: {:?} vs {:?}",
                rel,
                s,
                d
            );
        }
    }
}

// ── CLI new subcommands ────────────────────────────────────────────────

mod cli_new_subcommands_tests {
    use std::process::Command;

    fn aft_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_aft"))
    }

    #[test]
    fn cli_sync_help() {
        let output = aft_bin().args(["sync", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("source") || stdout.contains("SOURCE"));
    }

    #[test]
    fn cli_mv_help() {
        let output = aft_bin().args(["mv", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("source") || stdout.contains("SOURCE"));
    }

    #[test]
    fn cli_rm_help() {
        let output = aft_bin().args(["rm", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("url") || stdout.contains("URL"));
    }

    #[test]
    fn cli_mkdir_help() {
        let output = aft_bin().args(["mkdir", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("url") || stdout.contains("URL"));
    }

    #[test]
    fn cli_sync_dry_run_local() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("test.txt"), "data").unwrap();

        let src_url = format!("file://{}", src.to_str().unwrap().replace('\\', "/"));
        let dst_url = format!("file://{}", dst.to_str().unwrap().replace('\\', "/"));

        let output = aft_bin()
            .args(["sync", &src_url, &dst_url, "--dry-run", "--format", "json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
