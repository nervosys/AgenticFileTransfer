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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use sha2::Digest;

use cli::{ChecksumAlgorithm, Cli, Command, OutputFormat, PluginAction};
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
    unsafe {
        SetConsoleOutputCP(65001);
    }
}

#[tokio::main]
async fn main() {
    #[cfg(windows)]
    enable_utf8_console();

    let mut cli = Cli::parse();
    let _config = config::load_config().unwrap_or_default();

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

    let format = resolve_format(&cli);

    // Initialize plugin system
    let _ = plugins::init_registry();

    let result = run_command(&cli, format).await;

    match result {
        Ok(output_result) => {
            history::log_transfer(
                &output_result.operation,
                output_result.source.as_deref(),
                output_result.destination.as_deref(),
                output_result.protocol.as_deref(),
                &output_result.status,
                output_result.transfer.as_ref(),
                output_result.error.as_deref(),
            );
            output::print_result(&output_result, format);
            if output_result.status == "error" {
                std::process::exit(1);
            }
        }
        Err(e) => {
            history::log_transfer(
                "unknown",
                None,
                None,
                None,
                "error",
                None,
                Some(&e.to_string()),
            );
            let output_result = OutputResult::failure("unknown", &e.to_string());
            output::print_result(&output_result, format);
            std::process::exit(1);
        }
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
        } => cmd_copy(cli, format, source, destination, *recursive).await,
        Command::Head {
            url,
            headers,
            bearer_token,
        } => cmd_head(cli, format, url, headers, bearer_token.as_deref()).await,
        Command::List { url } => cmd_list(cli, format, url).await,
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
            transport,
        } => {
            let _transport_type: aftp::transport::TransportType = transport
                .parse()
                .map_err(|e: String| error::AftError::Other(e))?;

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
            );
            server.run().await?;
            Ok(OutputResult::success("serve"))
        }
        Command::Plugin { action } => cmd_plugin(action).await,
        Command::Crypto { action } => cmd_crypto(action).await,
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

    opts
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
                .and_then(|segs| segs.last())
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
            tokio::fs::create_dir_all(parent).await.ok();
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

    // Probe for progress bar sizing
    let metadata = handler.head(url, &opts).await.ok();
    let total_size = metadata.as_ref().and_then(|m| m.content_length);
    let pb = output::create_progress_bar(total_size, format);

    let progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>> = pb.as_ref().map(|pb| {
        let pb = pb.clone();
        Arc::new(move |bytes: u64, _total: Option<u64>| {
            pb.set_position(bytes);
        }) as Arc<dyn Fn(u64, Option<u64>) + Send + Sync>
    });

    let result = engine::download(&*handler, url, &dest, &opts, &config, progress_cb).await;

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

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

    let progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>> = pb.as_ref().map(|pb| {
        let pb = pb.clone();
        Arc::new(move |bytes: u64, _total: Option<u64>| {
            pb.set_position(bytes);
        }) as Arc<dyn Fn(u64, Option<u64>) + Send + Sync>
    });

    let result = engine::upload(
        &*handler,
        source_path,
        url,
        &opts,
        &config,
        content_type,
        Some(method),
        progress_cb,
    )
    .await;

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

async fn cmd_copy(
    cli: &Cli,
    format: Format,
    source: &str,
    destination: &str,
    recursive: bool,
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
                tokio::fs::create_dir_all(parent).await.ok();
            }
        }

        let pb = output::create_progress_bar(None, format);
        let progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>> =
            pb.as_ref().map(|pb| {
                let pb = pb.clone();
                Arc::new(move |bytes: u64, _total: Option<u64>| {
                    pb.set_position(bytes);
                }) as Arc<dyn Fn(u64, Option<u64>) + Send + Sync>
            });

        let result = engine::download(
            &*src_handler,
            source,
            &dest_path,
            &opts,
            &config,
            progress_cb,
        )
        .await;

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

        let dl_result =
            engine::download(&*src_handler, source, &temp_file, &opts, &config, None).await;
        if let Err(e) = dl_result {
            let _ = tokio::fs::remove_file(&temp_file).await;
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
        let _ = tokio::fs::remove_file(&temp_file).await;

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

async fn cmd_list(cli: &Cli, _format: Format, url: &str) -> AftResult<OutputResult> {
    let handler = protocols::resolve_protocol(url)?;
    let opts = build_opts(cli, &[], None, None, None, None);

    match handler.list(url, &opts).await {
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

    let data = tokio::fs::read(file_path).await?;
    let algo_name = algo_to_string(algorithm);

    let hash = match algorithm {
        ChecksumAlgorithm::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        ChecksumAlgorithm::Sha512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        ChecksumAlgorithm::Md5 => {
            let mut hasher = md5::Md5::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
    };

    let mut out = OutputResult::success("Checksum");
    out.source = Some(path.to_string());
    out.transfer = Some(engine::TransferResult {
        bytes_transferred: data.len() as u64,
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
            let cipher = crypto::neural::NeuralCipher::train(&config);
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

    // Walk directory tree
    let mut stack = vec![(src_path.to_path_buf(), dst_path.clone())];
    while let Some((src_dir, dst_dir)) = stack.pop() {
        tokio::fs::create_dir_all(&dst_dir).await.ok();

        let mut entries = tokio::fs::read_dir(&src_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let entry_name = entry.file_name();
            let dest_entry = dst_dir.join(&entry_name);

            if file_type.is_dir() {
                stack.push((entry.path(), dest_entry));
            } else if file_type.is_file() {
                let src_str = entry.path().display().to_string();
                let pb = output::create_progress_bar(None, format);
                let progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>> =
                    pb.as_ref().map(|pb| {
                        let pb = pb.clone();
                        Arc::new(move |bytes: u64, _total: Option<u64>| {
                            pb.set_position(bytes);
                        }) as Arc<dyn Fn(u64, Option<u64>) + Send + Sync>
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
