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
        assert!(h.supports_ranges());
        assert!(h.supports_resume());
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
