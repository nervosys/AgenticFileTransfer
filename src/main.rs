mod aftp;
mod audit;
mod cli;
mod config;
mod crypto;
mod engine;
mod error;
mod history;
mod ontology;
mod output;
mod plugins;
mod protocols;
mod sync;
mod telemetry;
mod turbo;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use sha2::Digest;

use cli::{ChecksumAlgorithm, Cli, CliCompareMode, Command, OutputFormat, PluginAction, TelemetryAction};
use colored::Colorize;
use engine::ProgressCb;
use error::AftResult;
use output::{Format, OutputResult};

fn resolve_format(cli: &Cli) -> Format {
    if cli.agent {
        Format::Json
    } else if cli.quiet {
        Format::Quiet
    } else {
        match cli.format {
            OutputFormat::Json => Format::Json,
            OutputFormat::Text => Format::Text,
            OutputFormat::Quiet => Format::Quiet,
        }
    }
}

#[cfg(windows)]
fn enable_utf8_console() {
    // Set console output codepage to UTF-8 so Unicode glyphs render correctly.
    use std::os::raw::c_uint;
    extern "system" {
        fn SetConsoleOutputCP(cp: c_uint) -> i32;
    }
    // SAFETY: SetConsoleOutputCP is a well-defined Win32 API with no UB.
    let ok = unsafe { SetConsoleOutputCP(65001) };
    if ok == 0 {
        eprintln!("Warning: failed to set console codepage to UTF-8");
    }
}

#[tokio::main]
async fn main() {
    #[cfg(windows)]
    enable_utf8_console();

    let mut cli = Cli::parse();
    let _config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}: {} (using defaults)",
                "Config warning".yellow().bold(),
                e
            );
            config::AftConfig::default()
        }
    };

    // Validate loaded config values
    if let Err(e) = _config.validate() {
        eprintln!("{}: {}", "Config error".red().bold(), e);
        std::process::exit(1);
    }

    // Apply config defaults where CLI didn't override
    if cli.parallel == 4 {
        if let Some(p) = _config.parallel {
            cli.parallel = p;
        }
    }
    if cli.retries == 3 {
        if let Some(r) = _config.retries {
            cli.retries = r;
        }
    }
    if cli.connect_timeout == 30 {
        if let Some(t) = _config.connect_timeout {
            cli.connect_timeout = t;
        }
    }
    if cli.rate_limit == 0 {
        if let Some(r) = _config.rate_limit {
            cli.rate_limit = r;
        }
    }
    if _config.insecure == Some(true) {
        cli.insecure = true;
    }

    if cli.insecure {
        eprintln!("WARNING: TLS certificate verification is DISABLED (--insecure).");
        eprintln!("WARNING: Connections are vulnerable to man-in-the-middle attacks.");
        audit::log_audit_event(
            &audit::AuditEvent::new(
                audit::AuditEventType::InsecureMode,
                audit::AuditSeverity::Warning,
                "insecure_mode_enabled",
            )
            .with_details("TLS certificate verification disabled via --insecure flag"),
        );
    }

    // Validate CLI argument ranges (after config merging)
    if let Err(e) = cli.validate() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let format = resolve_format(&cli);

    // Initialize plugin system
    if let Err(e) = plugins::init_registry() {
        if cli.verbose {
            eprintln!("Warning: plugin registry init failed: {}", e);
        }
    }

    // Initialize telemetry (best-effort, never block on failure)
    let mut telemetry = telemetry::TelemetryCollector::new().ok();
    if let Some(ref mut t) = telemetry {
        t.track(telemetry::TelemetryEvent::AppStarted {
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        });
    }

    let cmd_start = std::time::Instant::now();
    let result = run_command(&cli, format).await;
    let cmd_duration_ms = cmd_start.elapsed().as_millis() as u64;

    match result {
        Ok(ref output_result) => {
            history::log_transfer(
                &output_result.operation,
                output_result.source.as_deref(),
                output_result.destination.as_deref(),
                output_result.protocol.as_deref(),
                &output_result.status,
                output_result.transfer.as_ref(),
                output_result.error.as_deref(),
            );

            // Record telemetry for successful command
            if let Some(ref mut t) = telemetry {
                let success = output_result.status == "success";
                t.track_command(
                    &output_result.operation,
                    None,
                    Some(cmd_duration_ms),
                    success,
                );

                // Record transfer metrics if available
                if let (Some(ref transfer), Some(ref protocol)) =
                    (&output_result.transfer, &output_result.protocol)
                {
                    let direction = match output_result.operation.as_str() {
                        "Get" | "Copy" => "download",
                        "Put" => "upload",
                        _ => "unknown",
                    };
                    t.track_transfer(
                        protocol,
                        direction,
                        transfer.bytes_transferred,
                        transfer.duration_ms,
                        transfer.chunks_used as u32,
                        false,
                        false,
                        false,
                        success,
                    );
                }

                if !success {
                    if let Some(ref err) = output_result.error {
                        // Only record error type, never full message (may contain PII)
                        let error_type = if err.contains("timeout") {
                            "timeout"
                        } else if err.contains("not found") {
                            "not_found"
                        } else if err.contains("permission") {
                            "permission_denied"
                        } else if err.contains("checksum") {
                            "checksum_mismatch"
                        } else {
                            "other"
                        };
                        t.track_error(error_type, Some(&output_result.operation));
                    }
                }
            }

            output::print_result(output_result, format);
            if output_result.status == "error" {
                // Flush telemetry before exit
                if let Some(ref mut t) = telemetry {
                    let _ = t.flush();
                }
                std::process::exit(1);
            }
        }
        Err(ref e) => {
            history::log_transfer(
                "unknown",
                None,
                None,
                None,
                "error",
                None,
                Some(&e.to_string()),
            );

            if let Some(ref mut t) = telemetry {
                t.track_command("unknown", None, Some(cmd_duration_ms), false);
                t.track_error("fatal", None);
            }

            let output_result = OutputResult::failure("unknown", &e.to_string());
            output::print_result(&output_result, format);
            // Flush telemetry before exit
            if let Some(ref mut t) = telemetry {
                let _ = t.flush();
            }
            std::process::exit(1);
        }
    }

    // Flush telemetry at normal exit
    if let Some(ref mut t) = telemetry {
        let _ = t.flush();
    }
}

async fn run_command(cli: &Cli, format: Format) -> AftResult<OutputResult> {
    match &cli.command {
        Command::Get {
            url,
            output,
            resume,
            checksum,
            checksum_value,
            headers,
            bearer_token,
            auth,
            user_agent,
            max_redirects,
        } => {
            cmd_get(
                cli,
                format,
                url,
                output.as_deref(),
                *resume,
                checksum,
                checksum_value.as_deref(),
                headers,
                bearer_token.as_deref(),
                auth.as_deref(),
                user_agent.as_deref(),
                *max_redirects,
            )
            .await
        }
        Command::Put {
            source,
            url,
            content_type,
            headers,
            bearer_token,
            auth,
            method,
        } => {
            cmd_put(
                cli,
                format,
                source,
                url,
                content_type.as_deref(),
                headers,
                bearer_token.as_deref(),
                auth.as_deref(),
                method,
            )
            .await
        }
        Command::Copy {
            source,
            destination,
            recursive,
            include,
            exclude,
            preserve,
            dry_run,
        } => cmd_copy(cli, format, source, destination, *recursive, include, exclude, *preserve, *dry_run).await,
        Command::Head {
            url,
            headers,
            bearer_token,
        } => cmd_head(cli, format, url, headers, bearer_token.as_deref()).await,
        Command::List { url, recursive, long } => cmd_list(cli, format, url, *recursive, *long).await,
        Command::Schema => {
            ontology::print_schema(format);
            Ok(OutputResult::success("schema"))
        }
        Command::Capabilities => {
            ontology::print_capabilities(format);
            Ok(OutputResult::success("capabilities"))
        }
        Command::Checksum { path, algorithm } => cmd_checksum(format, path, algorithm).await,
        Command::Serve {
            root,
            port,
            bind,
            auth_token,
            auth_challenge,
            compression,
            tls_cert,
            tls_key,
            rate_limit: _,
            max_connections,
            transport,
        } => {
            let transport_type: aftp::transport::TransportType = transport
                .parse()
                .map_err(|e: String| error::AftError::Other(e))?;

            if transport_type != aftp::transport::TransportType::Tcp {
                return Err(error::AftError::Other(format!(
                    "Transport '{}' is not yet supported. Only TCP is currently implemented.",
                    transport
                )));
            }

            let server = aftp::server::AftpServer::new(
                root,
                *port,
                bind.as_str(),
                auth_token.clone(),
                *auth_challenge,
                *compression,
                cli.verbose,
                tls_cert.clone(),
                tls_key.clone(),
                *max_connections,
            );
            server.run().await?;
            Ok(OutputResult::success("serve"))
        }
        Command::Sync {
            source,
            destination,
            compare,
            dry_run,
            delete,
            update,
            preserve,
            include,
            exclude,
            min_size,
            max_size,
            max_depth,
        } => cmd_sync(cli, format, source, destination, compare, *dry_run, *delete, *update, *preserve, include, exclude, *min_size, *max_size, *max_depth).await,
        Command::Move { source, destination } => cmd_mv(cli, source, destination).await,
        Command::Remove { url, recursive, force: _ } => cmd_rm(cli, url, *recursive).await,
        Command::Mkdir { url } => cmd_mkdir(cli, url).await,
        Command::Plugin { action } => cmd_plugin(action).await,
        Command::Crypto { action } => cmd_crypto(action).await,
        Command::Telemetry { action } => cmd_telemetry(action).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_opts(
    cli: &Cli,
    headers: &[String],
    bearer_token: Option<&str>,
    auth: Option<&str>,
    user_agent: Option<&str>,
    max_redirects: Option<usize>,
) -> protocols::ProtocolOptions {
    let mut opts = protocols::ProtocolOptions {
        connect_timeout_secs: cli.connect_timeout,
        timeout_secs: cli.timeout,
        insecure: cli.insecure,
        max_redirects: max_redirects.unwrap_or(10),
        ..Default::default()
    };

    for header in headers {
        if let Some((k, v)) = header.split_once(':') {
            opts.headers
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    if let Some(token) = bearer_token {
        opts.bearer_token = Some(token.to_string());
    }

    if let Some(auth_str) = auth {
        if let Some((user, pass)) = auth_str.split_once(':') {
            opts.basic_auth = Some((user.to_string(), pass.to_string()));
        }
    }

    if let Some(ua) = user_agent {
        opts.user_agent = Some(ua.to_string());
    }

    if let Some(ref pin) = cli.pin_cert {
        opts.pin_cert = Some(pin.clone());
    }
    if let Some(ref ca) = cli.ca_bundle {
        opts.ca_bundle = Some(ca.clone());
    }

    opts
}

fn build_turbo_config(cli: &Cli) -> turbo::TurboConfig {
    turbo::TurboConfig {
        enabled: cli.turbo,
        streams: cli.streams,
        chunk_size: cli.chunk_size,
        sock_buf: cli.sock_buf,
        mmap: !cli.no_mmap,
        write_pipeline: true,
        rate_limit: cli.rate_limit,
    }
}
fn resolve_output_path(url: &str, output: Option<&str>) -> PathBuf {
    if let Some(out) = output {
        let path = PathBuf::from(out);
        if path.is_dir() || out.ends_with('/') || out.ends_with('\\') {
            path.join(extract_filename(url))
        } else {
            path
        }
    } else {
        PathBuf::from(extract_filename(url))
    }
}

fn extract_filename(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut segs| segs.next_back())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "download".to_string())
}

fn algo_to_string(algo: &ChecksumAlgorithm) -> String {
    match algo {
        ChecksumAlgorithm::Sha256 => "sha256".to_string(),
        ChecksumAlgorithm::Sha512 => "sha512".to_string(),
        ChecksumAlgorithm::Md5 => "md5".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn cmd_get(
    cli: &Cli,
    format: Format,
    url: &str,
    output: Option<&str>,
    resume: bool,
    checksum: &Option<ChecksumAlgorithm>,
    checksum_value: Option<&str>,
    headers: &[String],
    bearer_token: Option<&str>,
    auth: Option<&str>,
    user_agent: Option<&str>,
    max_redirects: usize,
) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(
        cli,
        headers,
        bearer_token,
        auth,
        user_agent,
        Some(max_redirects),
    );
    let dest = resolve_output_path(url, output);

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                eprintln!("Warning: failed to create directory {:?}: {}", parent, e);
            }
        }
    }

    let config = engine::TransferConfig {
        parallel_chunks: cli.parallel,
        max_retries: cli.retries,
        retry_delay_ms: cli.retry_delay_ms,
        resume,
        verify_checksum: checksum.as_ref().map(|algo| engine::ChecksumConfig {
            algorithm: algo_to_string(algo),
            expected_value: checksum_value.map(|s| s.to_string()),
        }),
        rate_limit_bytes_per_sec: cli.rate_limit,
        ..Default::default()
    };

    // For turbo, skip the extra HEAD — turbo_download_auto already probes.
    // For standard, probe for progress bar sizing.
    let result = if cli.turbo {
        let tc = build_turbo_config(cli);
        let pb = output::create_progress_bar(None, format);
        let progress_cb: Option<ProgressCb> = pb.as_ref().map(|pb| {
            let pb = pb.clone();
            Arc::new(move |bytes: u64, total: Option<u64>| {
                if let Some(t) = total { pb.set_length(t); }
                pb.set_position(bytes);
            }) as ProgressCb
        });
        let r = turbo::turbo_download_auto(&*handler, url, &dest, &opts, &tc, progress_cb)
            .await
            .map(|(tr, _profile)| tr);
        if let Some(ref pb) = pb { pb.finish_and_clear(); }
        r
    } else {
        let metadata = handler.head(url, &opts).await.ok();
        let total_size = metadata.as_ref().and_then(|m| m.content_length);
        let pb = output::create_progress_bar(total_size, format);
        let progress_cb: Option<ProgressCb> = pb.as_ref().map(|pb| {
            let pb = pb.clone();
            Arc::new(move |bytes: u64, _total: Option<u64>| {
                pb.set_position(bytes);
            }) as ProgressCb
        });
        let r = engine::download(&*handler, url, &dest, &opts, &config, progress_cb).await;
        if let Some(ref pb) = pb { pb.finish_and_clear(); }
        r
    };

    match result {
        Ok(transfer) => {
            let mut out = OutputResult::success("Download");
            out.source = Some(url.to_string());
            out.destination = Some(dest.display().to_string());
            out.protocol = Some(handler.scheme().to_string());
            out.transfer = Some(transfer);
            Ok(out)
        }
        Err(e) => {
            let mut out = OutputResult::failure("Download", &e.to_string());
            out.source = Some(url.to_string());
            out.destination = Some(dest.display().to_string());
            out.protocol = Some(handler.scheme().to_string());
            Ok(out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_put(
    cli: &Cli,
    format: Format,
    source: &str,
    url: &str,
    content_type: Option<&str>,
    headers: &[String],
    bearer_token: Option<&str>,
    auth: Option<&str>,
    method: &str,
) -> AftResult<OutputResult> {
    let source_path = Path::new(source);
    if !source_path.exists() {
        return Ok(OutputResult::failure(
            "Upload",
            &format!("Source file not found: {}", source),
        ));
    }

    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, headers, bearer_token, auth, None, None);

    let config = engine::TransferConfig {
        max_retries: cli.retries,
        retry_delay_ms: cli.retry_delay_ms,
        rate_limit_bytes_per_sec: cli.rate_limit,
        ..Default::default()
    };

    let file_size = tokio::fs::metadata(source_path).await?.len();
    let pb = output::create_progress_bar(Some(file_size), format);

    let progress_cb: Option<ProgressCb> = pb.as_ref().map(|pb| {
        let pb = pb.clone();
        Arc::new(move |bytes: u64, _total: Option<u64>| {
            pb.set_position(bytes);
        }) as ProgressCb
    });

    let result = if cli.turbo {
        let tc = build_turbo_config(cli);
        turbo::turbo_upload_auto(&*handler, source_path, url, &opts, &tc, content_type, Some(method), progress_cb)
            .await
            .map(|(tr, _profile)| tr)
    } else {
        engine::upload(
            &*handler,
            source_path,
            url,
            &opts,
            &config,
            content_type,
            Some(method),
            progress_cb,
        )
        .await
    };

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    match result {
        Ok(transfer) => {
            let mut out = OutputResult::success("Upload");
            out.source = Some(source.to_string());
            out.destination = Some(url.to_string());
            out.protocol = Some(handler.scheme().to_string());
            out.transfer = Some(transfer);
            Ok(out)
        }
        Err(e) => {
            let mut out = OutputResult::failure("Upload", &e.to_string());
            out.source = Some(source.to_string());
            out.destination = Some(url.to_string());
            Ok(out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_copy(
    cli: &Cli,
    format: Format,
    source: &str,
    destination: &str,
    recursive: bool,
    _include: &[String],
    _exclude: &[String],
    _preserve: bool,
    _dry_run: bool,
) -> AftResult<OutputResult> {
    let src_handler = protocols::resolve_protocol(source)?;
    let dst_handler = protocols::resolve_protocol(destination)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    let config = engine::TransferConfig {
        parallel_chunks: cli.parallel,
        max_retries: cli.retries,
        retry_delay_ms: cli.retry_delay_ms,
        rate_limit_bytes_per_sec: cli.rate_limit,
        ..Default::default()
    };

    // Recursive directory copy
    if recursive && src_handler.scheme() == "file" && dst_handler.scheme() == "file" {
        return recursive_local_copy(source, destination, &config, format).await;
    }

    if src_handler.scheme() == "file" && dst_handler.scheme() == "file" {
        // Direct local-to-local copy
        let dest_path = {
            let dp = PathBuf::from(destination);
            if dp.is_dir() {
                dp.join(Path::new(source).file_name().unwrap_or_default())
            } else {
                dp
            }
        };
        if let Some(parent) = dest_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    eprintln!("Warning: failed to create directory {:?}: {}", parent, e);
                }
            }
        }

        let pb = output::create_progress_bar(None, format);
        let progress_cb: Option<ProgressCb> = pb.as_ref().map(|pb| {
            let pb = pb.clone();
            Arc::new(move |bytes: u64, _total: Option<u64>| {
                pb.set_position(bytes);
            }) as ProgressCb
        });

        let result = if cli.turbo {
            turbo::turbo_local_copy(Path::new(source), &dest_path, progress_cb).await
        } else {
            engine::download(
                &*src_handler,
                source,
                &dest_path,
                &opts,
                &config,
                progress_cb,
            )
            .await
        };

        if let Some(ref pb) = pb {
            pb.finish_and_clear();
        }

        match result {
            Ok(transfer) => {
                let mut out = OutputResult::success("Copy");
                out.source = Some(source.to_string());
                out.destination = Some(destination.to_string());
                out.protocol = Some("file".to_string());
                out.transfer = Some(transfer);
                Ok(out)
            }
            Err(e) => Ok(OutputResult::failure("Copy", &e.to_string())),
        }
    } else {
        // Cross-protocol copy: download to temp, then upload
        let temp_name = format!(
            "aft-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let temp_file = std::env::temp_dir().join(temp_name);

        // Scope guard ensures temp file is cleaned up even on panic
        struct TempFileGuard(std::path::PathBuf);
        impl Drop for TempFileGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _temp_guard = TempFileGuard(temp_file.clone());

        // Restrict temp file permissions (owner-only read/write)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_file)
                .ok();
        }

        let dl_result =
            engine::download(&*src_handler, source, &temp_file, &opts, &config, None).await;
        if let Err(e) = dl_result {
            return Ok(OutputResult::failure(
                "Copy",
                &format!("Download phase failed: {}", e),
            ));
        }

        let ul_result = engine::upload(
            &*dst_handler,
            &temp_file,
            destination,
            &opts,
            &config,
            None,
            None,
            None,
        )
        .await;

        match ul_result {
            Ok(transfer) => {
                let mut out = OutputResult::success("Copy");
                out.source = Some(source.to_string());
                out.destination = Some(destination.to_string());
                out.transfer = Some(transfer);
                Ok(out)
            }
            Err(e) => Ok(OutputResult::failure(
                "Copy",
                &format!("Upload phase failed: {}", e),
            )),
        }
    }
}

async fn cmd_head(
    cli: &Cli,
    _format: Format,
    url: &str,
    headers: &[String],
    bearer_token: Option<&str>,
) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, headers, bearer_token, None, None, None);

    match handler.head(url, &opts).await {
        Ok(metadata) => {
            let mut out = OutputResult::success("Head");
            out.source = Some(url.to_string());
            out.protocol = Some(handler.scheme().to_string());
            out.metadata = Some(metadata);
            Ok(out)
        }
        Err(e) => {
            let mut out = OutputResult::failure("Head", &e.to_string());
            out.source = Some(url.to_string());
            Ok(out)
        }
    }
}

async fn cmd_list(cli: &Cli, _format: Format, url: &str, recursive: bool, _long: bool) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    let list_result = if recursive {
        handler.list_recursive(url, &opts, 200).await
    } else {
        handler.list(url, &opts).await
    };
    match list_result {
        Ok(entries) => {
            let mut out = OutputResult::success("List");
            out.source = Some(url.to_string());
            out.protocol = Some(handler.scheme().to_string());
            out.entries = Some(entries);
            Ok(out)
        }
        Err(e) => {
            let mut out = OutputResult::failure("List", &e.to_string());
            out.source = Some(url.to_string());
            Ok(out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_sync(
    cli: &Cli,
    _format: Format,
    source: &str,
    destination: &str,
    compare: &CliCompareMode,
    dry_run: bool,
    delete: bool,
    update: bool,
    preserve: bool,
    include: &[String],
    exclude: &[String],
    min_size: Option<u64>,
    max_size: Option<u64>,
    max_depth: usize,
) -> AftResult<OutputResult> {
    let src_handler = protocols::resolve_protocol(source)?;
    let dst_handler = protocols::resolve_protocol(destination)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    let compare_mode = match compare {
        CliCompareMode::Size => sync::CompareMode::Size,
        CliCompareMode::Modtime => sync::CompareMode::ModTime,
        CliCompareMode::Checksum => sync::CompareMode::Checksum,
    };

    let config = sync::SyncConfig {
        compare: compare_mode,
        dry_run,
        delete,
        update,
        preserve_timestamps: preserve,
        include: include.to_vec(),
        exclude: exclude.to_vec(),
        min_size,
        max_size,
        max_depth,
        transfer: engine::TransferConfig {
            parallel_chunks: cli.parallel,
            max_retries: cli.retries,
            retry_delay_ms: cli.retry_delay_ms,
            rate_limit_bytes_per_sec: cli.rate_limit,
            ..Default::default()
        },
    };

    let result = sync::sync(&*src_handler, source, &*dst_handler, destination, &opts, &config, None).await?;

    let mut out = OutputResult::success("Sync");
    out.source = Some(source.to_string());
    out.destination = Some(destination.to_string());
    out.extra = Some(serde_json::to_value(&result).unwrap_or_default());
    Ok(out)
}

async fn cmd_mv(cli: &Cli, source: &str, destination: &str) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(source)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    if !handler.supports_extended_ops() {
        return Ok(OutputResult::failure("Move", "Protocol does not support move/rename operations"));
    }

    handler.rename(source, destination, &opts).await?;

    let mut out = OutputResult::success("Move");
    out.source = Some(source.to_string());
    out.destination = Some(destination.to_string());
    out.protocol = Some(handler.scheme().to_string());
    Ok(out)
}

async fn cmd_rm(cli: &Cli, url: &str, recursive: bool) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    if !handler.supports_extended_ops() {
        return Ok(OutputResult::failure("Remove", "Protocol does not support delete operations"));
    }

    handler.delete(url, recursive, &opts).await?;

    let mut out = OutputResult::success("Remove");
    out.source = Some(url.to_string());
    out.protocol = Some(handler.scheme().to_string());
    Ok(out)
}

async fn cmd_mkdir(cli: &Cli, url: &str) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    if !handler.supports_extended_ops() {
        return Ok(OutputResult::failure("Mkdir", "Protocol does not support mkdir operations"));
    }

    handler.mkdir(url, &opts).await?;

    let mut out = OutputResult::success("Mkdir");
    out.source = Some(url.to_string());
    out.protocol = Some(handler.scheme().to_string());
    Ok(out)
}

async fn cmd_checksum(
    _format: Format,
    path: &str,
    algorithm: &ChecksumAlgorithm,
) -> AftResult<OutputResult> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Ok(OutputResult::failure(
            "Checksum",
            &format!("File not found: {}", path),
        ));
    }

    // Stream the file in 64 KB chunks to avoid loading entire file into memory
    let mut file = tokio::fs::File::open(file_path).await?;
    let file_len = file.metadata().await?.len();
    let algo_name = algo_to_string(algorithm);

    let hash = {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65_536];
        match algorithm {
            ChecksumAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
            ChecksumAlgorithm::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
            ChecksumAlgorithm::Md5 => {
                let mut hasher = md5::Md5::new();
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
        }
    };

    let mut out = OutputResult::success("Checksum");
    out.source = Some(path.to_string());
    out.transfer = Some(engine::TransferResult {
        bytes_transferred: file_len,
        duration_ms: 0,
        throughput_bytes_per_sec: 0.0,
        checksum: Some(engine::ChecksumResult {
            algorithm: algo_name,
            value: hash,
            verified: false,
        }),
        retries_used: 0,
        chunks_used: 0,
    });

    Ok(out)
}

// ---------------------------------------------------------------------------
// Plugin management
// ---------------------------------------------------------------------------

async fn cmd_plugin(action: &PluginAction) -> AftResult<OutputResult> {
    match action {
        PluginAction::List => {
            let registry = plugins::global_registry();
            let guard = registry
                .lock()
                .map_err(|e| error::AftError::Other(format!("Plugin registry lock: {}", e)))?;
            let plugins_list = guard.list();

            if plugins_list.is_empty() {
                let mut out = OutputResult::success("Plugin List");
                out.source = Some("No plugins loaded".to_string());
                return Ok(out);
            }

            let mut out = OutputResult::success("Plugin List");
            let entries: Vec<protocols::DirectoryEntry> = plugins_list
                .iter()
                .map(|p| protocols::DirectoryEntry {
                    name: format!("{} v{} ({})", p.name, p.version, p.scheme),
                    size: None,
                    is_directory: false,
                    last_modified: Some(p.description.clone()),
                    relative_path: None,
                    is_symlink: None,
                    permissions: None,
                })
                .collect();
            out.entries = Some(entries);
            Ok(out)
        }
        PluginAction::Load { path } => {
            let registry = plugins::global_registry();
            let mut guard = registry
                .lock()
                .map_err(|e| error::AftError::Other(format!("Plugin registry lock: {}", e)))?;
            let meta = guard.load_plugin(std::path::Path::new(path))?;
            let mut out = OutputResult::success("Plugin Load");
            out.source = Some(format!(
                "Loaded {} v{} for scheme '{}'",
                meta.name, meta.version, meta.scheme
            ));
            Ok(out)
        }
        PluginAction::Unload { scheme } => {
            let registry = plugins::global_registry();
            let mut guard = registry
                .lock()
                .map_err(|e| error::AftError::Other(format!("Plugin registry lock: {}", e)))?;
            guard.unload(scheme)?;
            let mut out = OutputResult::success("Plugin Unload");
            out.source = Some(format!("Unloaded plugin for scheme '{}'", scheme));
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto operations
// ---------------------------------------------------------------------------

async fn cmd_crypto(action: &cli::CryptoAction) -> AftResult<OutputResult> {
    use cli::CryptoAction;

    match action {
        CryptoAction::Keygen { output } => {
            let kp = crypto::pqc::generate_keypair()?;
            let pub_path = std::path::PathBuf::from(format!("{}.pub", output));
            let sec_path = std::path::PathBuf::from(format!("{}.sec", output));
            crypto::pqc::save_public_key(&kp.public_key, &pub_path)?;
            crypto::pqc::save_secret_key(&kp.secret_key, &sec_path)?;

            let mut out = OutputResult::success("Crypto Keygen");
            out.source = Some(format!(
                "Kyber1024 keypair: {} ({} bytes) + {} ({} bytes)",
                pub_path.display(),
                kp.public_key.len(),
                sec_path.display(),
                kp.secret_key.len()
            ));
            Ok(out)
        }
        CryptoAction::Train {
            epochs,
            learning_rate,
            seed,
            output,
        } => {
            let config = crypto::neural::TrainConfig {
                epochs: *epochs,
                learning_rate: *learning_rate,
                seed: *seed,
                ..Default::default()
            };
            let cipher =
                tokio::task::spawn_blocking(move || crypto::neural::NeuralCipher::train(&config))
                    .await
                    .map_err(|e| error::AftError::Other(format!("Training task failed: {}", e)))?;
            let model_path = std::path::PathBuf::from(output);
            cipher
                .save(&model_path)
                .map_err(|e| error::AftError::Other(format!("Failed to save model: {}", e)))?;

            let mut out = OutputResult::success("Crypto Train");
            out.source = Some(format!("Neural cipher model: {}", model_path.display()));
            Ok(out)
        }
        CryptoAction::Encrypt {
            input,
            output,
            method,
            key_file,
        } => {
            let enc_method = crypto::EncryptionMethod::parse(method).ok_or_else(|| {
                error::AftError::Other(format!(
                    "Unknown encryption method '{}'. Use: pqc, neural, hybrid",
                    method
                ))
            })?;

            let input_path = std::path::PathBuf::from(input);
            let output_path = match output {
                Some(o) => std::path::PathBuf::from(o),
                None => std::path::PathBuf::from(format!("{}.enc", input)),
            };
            let key_path = std::path::PathBuf::from(key_file);

            let bytes =
                crypto::encrypt_file(&input_path, &output_path, enc_method, &key_path).await?;

            let mut out = OutputResult::success("Crypto Encrypt");
            out.source = Some(input.clone());
            out.destination = Some(output_path.display().to_string());
            out.transfer = Some(engine::TransferResult {
                bytes_transferred: bytes,
                duration_ms: 0,
                throughput_bytes_per_sec: 0.0,
                checksum: None,
                retries_used: 0,
                chunks_used: 0,
            });
            Ok(out)
        }
        CryptoAction::Decrypt {
            input,
            output,
            key_file,
        } => {
            let input_path = std::path::PathBuf::from(input);
            let output_path = match output {
                Some(o) => std::path::PathBuf::from(o),
                None => {
                    let s = input.strip_suffix(".enc").unwrap_or(input);
                    std::path::PathBuf::from(format!("{}.dec", s))
                }
            };
            let key_path = std::path::PathBuf::from(key_file);

            let bytes = crypto::decrypt_file(&input_path, &output_path, &key_path).await?;

            let mut out = OutputResult::success("Crypto Decrypt");
            out.source = Some(input.clone());
            out.destination = Some(output_path.display().to_string());
            out.transfer = Some(engine::TransferResult {
                bytes_transferred: bytes,
                duration_ms: 0,
                throughput_bytes_per_sec: 0.0,
                checksum: None,
                retries_used: 0,
                chunks_used: 0,
            });
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Recursive directory copy
// ---------------------------------------------------------------------------

/// Maximum directory traversal depth to prevent symlink loops / stack exhaustion.
const MAX_COPY_DEPTH: usize = 100;

async fn recursive_local_copy(
    source: &str,
    destination: &str,
    config: &engine::TransferConfig,
    format: output::Format,
) -> AftResult<OutputResult> {
    let src_path = Path::new(source);
    let dst_path = PathBuf::from(destination);

    if !src_path.is_dir() {
        return Ok(OutputResult::failure(
            "Copy",
            &format!("Source is not a directory: {}", source),
        ));
    }

    let start = std::time::Instant::now();
    let mut total_bytes = 0u64;
    let mut file_count = 0u64;

    let handler = protocols::resolve_protocol(source)?;
    let opts = protocols::ProtocolOptions::default();

    // Walk directory tree with depth tracking
    let mut stack: Vec<(std::path::PathBuf, PathBuf, usize)> =
        vec![(src_path.to_path_buf(), dst_path.clone(), 0)];
    while let Some((src_dir, dst_dir, depth)) = stack.pop() {
        if depth > MAX_COPY_DEPTH {
            return Ok(OutputResult::failure(
                "Copy",
                &format!(
                    "Maximum directory depth ({}) exceeded — possible symlink loop",
                    MAX_COPY_DEPTH
                ),
            ));
        }

        if let Err(e) = tokio::fs::create_dir_all(&dst_dir).await {
            eprintln!("Warning: failed to create directory {:?}: {}", dst_dir, e);
        }

        let mut entries = tokio::fs::read_dir(&src_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let entry_name = entry.file_name();
            let dest_entry = dst_dir.join(&entry_name);

            if file_type.is_dir() {
                stack.push((entry.path(), dest_entry, depth + 1));
            } else if file_type.is_file() {
                let src_str = entry.path().display().to_string();
                let pb = output::create_progress_bar(None, format);
                let progress_cb: Option<ProgressCb> = pb.as_ref().map(|pb| {
                    let pb = pb.clone();
                    Arc::new(move |bytes: u64, _total: Option<u64>| {
                        pb.set_position(bytes);
                    }) as ProgressCb
                });
                let result =
                    engine::download(&*handler, &src_str, &dest_entry, &opts, config, progress_cb)
                        .await;
                if let Some(ref pb) = pb {
                    pb.finish_and_clear();
                }
                match result {
                    Ok(transfer) => {
                        total_bytes += transfer.bytes_transferred;
                        file_count += 1;
                    }
                    Err(e) => {
                        return Ok(OutputResult::failure(
                            "Copy",
                            &format!("Failed to copy {:?}: {}", entry.path(), e),
                        ));
                    }
                }
            }
        }
    }

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as u64;
    let throughput = if duration_ms > 0 {
        total_bytes as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    let mut out = OutputResult::success("Copy");
    out.source = Some(source.to_string());
    out.destination = Some(destination.to_string());
    out.protocol = Some("file".to_string());
    out.transfer = Some(engine::TransferResult {
        bytes_transferred: total_bytes,
        duration_ms,
        throughput_bytes_per_sec: throughput,
        checksum: None,
        retries_used: 0,
        chunks_used: file_count as usize,
    });
    Ok(out)
}

// ---------------------------------------------------------------------------
// Telemetry command
// ---------------------------------------------------------------------------

async fn cmd_telemetry(action: &TelemetryAction) -> AftResult<OutputResult> {
    use telemetry::{format_telemetry_info, TelemetryConfig, TelemetryStore};

    match action {
        TelemetryAction::Status => {
            let config = TelemetryConfig::load()?;
            let store = TelemetryStore::new()?;
            let count = store.count_records().unwrap_or(0);

            let info = format_telemetry_info(&config);
            println!("{}", info);
            println!("Local records: {}", count);

            let mut out = OutputResult::success("Telemetry Status");
            out.source = Some(format!(
                "enabled={}, remote={}, records={}",
                config.enabled, config.remote_enabled, count
            ));
            Ok(out)
        }

        TelemetryAction::OptIn => {
            let mut config = TelemetryConfig::load()?;
            config.opt_in()?;

            println!("{}", "Telemetry enabled.".green());
            println!("Thank you for helping improve AFT!");

            let mut out = OutputResult::success("Telemetry Opt-In");
            out.source = Some("Telemetry is now enabled".to_string());
            Ok(out)
        }

        TelemetryAction::OptOut => {
            let mut config = TelemetryConfig::load()?;
            config.opt_out()?;

            println!("{}", "Telemetry disabled.".yellow());
            println!("No data will be collected or sent.");

            let mut out = OutputResult::success("Telemetry Opt-Out");
            out.source = Some("Telemetry is now disabled".to_string());
            Ok(out)
        }

        TelemetryAction::Reset => {
            let mut config = TelemetryConfig::load()?;
            let old_id = config.installation_id.clone();
            config.reset_id()?;

            println!("{}", "Installation ID reset.".green());
            println!("Old ID: {}", old_id);
            println!("New ID: {}", config.installation_id);

            let mut out = OutputResult::success("Telemetry Reset");
            out.source = Some(format!("New installation ID: {}", config.installation_id));
            Ok(out)
        }

        TelemetryAction::Sync { limit } => {
            let store = TelemetryStore::new()?;

            if !store.config().is_remote_enabled() {
                println!(
                    "{}",
                    "Remote telemetry is disabled. Use 'aft telemetry opt-in' to enable.".yellow()
                );
                return Ok(OutputResult::failure(
                    "Telemetry Sync",
                    "Remote telemetry disabled",
                ));
            }

            println!(
                "Syncing telemetry data to {}...",
                store.config().remote_endpoint
            );

            let result = store.sync_to_remote(*limit).await?;

            if result.success {
                println!(
                    "{}",
                    format!("Synced {} records successfully.", result.records_sent).green()
                );
                let mut out = OutputResult::success("Telemetry Sync");
                out.source = Some(format!("{} records synced", result.records_sent));
                Ok(out)
            } else {
                let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                println!("{}", format!("Sync failed: {}", err_msg).red());
                Ok(OutputResult::failure("Telemetry Sync", &err_msg))
            }
        }

        TelemetryAction::Clear => {
            let store = TelemetryStore::new()?;
            let count = store.clear_records()?;

            println!(
                "{}",
                format!("Cleared {} telemetry records.", count).green()
            );

            let mut out = OutputResult::success("Telemetry Clear");
            out.source = Some(format!("{} records cleared", count));
            Ok(out)
        }

        TelemetryAction::Export {
            output,
            format,
            limit,
        } => {
            let store = TelemetryStore::new()?;
            let records = store.read_records(None, None, None, None, *limit)?;

            if records.is_empty() {
                println!("No telemetry records to export.");
                return Ok(OutputResult::success("Telemetry Export"));
            }

            let content = match format.as_str() {
                "jsonl" => {
                    let lines: Vec<String> = records
                        .iter()
                        .map(|r| serde_json::to_string(r).unwrap_or_default())
                        .collect();
                    lines.join("\n")
                }
                _ => serde_json::to_string_pretty(&records)
                    .map_err(|e| error::AftError::Other(format!("JSON error: {}", e)))?,
            };

            if let Some(path) = output {
                std::fs::write(path, &content)?;
                println!(
                    "{}",
                    format!("Exported {} records to {}", records.len(), path).green()
                );
            } else {
                println!("{}", content);
            }

            let mut out = OutputResult::success("Telemetry Export");
            out.source = Some(format!("{} records exported", records.len()));
            Ok(out)
        }

        TelemetryAction::Config { endpoint, api_key } => {
            let mut config = TelemetryConfig::load()?;
            let mut changed = false;

            if let Some(ep) = endpoint {
                config.set_endpoint(ep)?;
                println!("Endpoint set to: {}", ep);
                changed = true;
            }

            if let Some(key) = api_key {
                config.set_api_key(Some(key.clone()))?;
                println!("API key set.");
                changed = true;
            }

            if !changed {
                println!("Current endpoint: {}", config.remote_endpoint);
                if config.remote_api_key.is_some() {
                    println!("API key: (configured)");
                } else {
                    println!("API key: (not set)");
                }
            }

            let mut out = OutputResult::success("Telemetry Config");
            out.source = Some(format!("endpoint={}", config.remote_endpoint));
            Ok(out)
        }
    }
}
