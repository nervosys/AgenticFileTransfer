use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Colorized human-readable text output
    Text,
    /// Structured JSON output for programmatic consumption
    Json,
    /// Suppress all non-error output
    Quiet,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ChecksumAlgorithm {
    Sha256,
    Sha512,
    Md5,
}

#[derive(Parser, Debug)]
#[command(
    name = "aft",
    version,
    about = "Agentic File Transfer — High-performance file transfer for humans and AI agents",
    long_about = "\
AFT (Agentic File Transfer) is a high-performance, protocol-agnostic file transfer CLI \
designed for both human operators and AI agents. It provides structured output, \
self-describing schemas, and optimized transfer engines across HTTP/HTTPS, FTP, \
SFTP, S3, and local file protocols.\n\n\
AGENTIC USAGE:\n  \
  Use --agent or --format json for structured machine-readable output.\n  \
  Use 'aft schema' to discover all capabilities programmatically.\n  \
  Use 'aft capabilities' to list available protocols and features.\n  \
  All operations return a consistent JSON schema with status, transfer metrics, and errors.",
    after_help = "\
EXAMPLES:\n  \
  aft get https://example.com/file.tar.gz\n  \
  aft get https://example.com/file.tar.gz -o ./downloads/\n  \
  aft put ./report.pdf https://upload.example.com/files/\n  \
  aft copy ./src/ ./backup/src/\n  \
  aft head https://example.com/file.tar.gz\n  \
  aft schema\n  \
  aft capabilities\n  \
  aft checksum ./file.tar.gz --algorithm sha256\n\n\
AGENT MODE:\n  \
  aft --agent get https://example.com/data.json\n  \
  aft --format json head https://example.com/file.tar.gz"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format: text (colorized), json (structured), quiet (errors only)
    #[arg(long, short = 'f', default_value = "text", global = true)]
    pub format: OutputFormat,

    /// Enable verbose logging
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Suppress all non-error output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Agent mode: structured JSON output, no interactive elements, deterministic
    #[arg(long, global = true)]
    pub agent: bool,

    /// Number of parallel connections for chunked transfers
    #[arg(long, default_value = "4", global = true)]
    pub parallel: usize,

    /// Maximum number of retry attempts
    #[arg(long, default_value = "3", global = true)]
    pub retries: u32,

    /// Initial retry delay in milliseconds (exponential backoff: doubles each retry)
    #[arg(long, default_value = "1000", global = true)]
    pub retry_delay_ms: u64,

    /// Connection timeout in seconds
    #[arg(long, default_value = "30", global = true)]
    pub connect_timeout: u64,

    /// Transfer timeout in seconds (0 = no timeout)
    #[arg(long, default_value = "0", global = true)]
    pub timeout: u64,

    /// Skip TLS certificate verification (WARNING: insecure, use only for testing)
    #[arg(long, global = true)]
    pub insecure: bool,

    /// Maximum bandwidth in bytes per second (0 = unlimited)
    #[arg(long, default_value = "0", global = true)]
    pub rate_limit: u64,

    /// Pin a TLS certificate by SHA-256 fingerprint (hex-encoded, for AFTPS connections)
    #[arg(long, global = true)]
    pub pin_cert: Option<String>,

    /// Path to a custom CA certificate bundle (PEM file)
    #[arg(long, global = true)]
    pub ca_bundle: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Download a file from a URL
    Get {
        /// Source URL to download from (http, https, ftp, sftp, s3, file)
        url: String,

        /// Output file or directory path
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Resume a partially downloaded file
        #[arg(long)]
        resume: bool,

        /// Verify download with checksum algorithm
        #[arg(long)]
        checksum: Option<ChecksumAlgorithm>,

        /// Expected checksum hex value for verification
        #[arg(long)]
        checksum_value: Option<String>,

        /// Custom HTTP headers (format: key:value, repeatable)
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Bearer token for authentication
        #[arg(long)]
        bearer_token: Option<String>,

        /// Basic auth credentials (format: user:password)
        #[arg(long)]
        auth: Option<String>,

        /// Custom User-Agent string
        #[arg(long)]
        user_agent: Option<String>,

        /// Maximum number of HTTP redirects to follow
        #[arg(long, default_value = "10")]
        max_redirects: usize,
    },

    /// Upload a file to a URL
    Put {
        /// Local file path to upload
        source: String,

        /// Destination URL to upload to
        url: String,

        /// Content-Type header for the upload
        #[arg(long)]
        content_type: Option<String>,

        /// Custom HTTP headers (format: key:value, repeatable)
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Bearer token for authentication
        #[arg(long)]
        bearer_token: Option<String>,

        /// Basic auth credentials (format: user:password)
        #[arg(long)]
        auth: Option<String>,

        /// HTTP method to use for upload
        #[arg(long, default_value = "PUT")]
        method: String,
    },

    /// Copy files between any two locations (local or remote)
    Copy {
        /// Source path or URL
        source: String,

        /// Destination path or URL
        destination: String,

        /// Recurse into directories
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Inspect remote resource metadata without downloading
    Head {
        /// URL to inspect
        url: String,

        /// Custom HTTP headers (format: key:value, repeatable)
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Bearer token for authentication
        #[arg(long)]
        bearer_token: Option<String>,
    },

    /// List contents of a remote or local directory
    #[command(name = "ls")]
    List {
        /// Directory URL or path to list
        url: String,
    },

    /// Output the agentic ontology schema describing all capabilities
    Schema,

    /// List available protocols, operations, and features
    Capabilities,

    /// Compute checksum of a local file
    Checksum {
        /// File path to compute checksum for
        path: String,

        /// Checksum algorithm to use
        #[arg(long, short = 'a', default_value = "sha256")]
        algorithm: ChecksumAlgorithm,
    },

    /// Start an AFTP file server
    Serve {
        /// Root directory to serve files from
        root: String,

        /// TCP port to listen on
        #[arg(long, default_value = "2600")]
        port: u16,

        /// Address to bind to
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,

        /// Pre-shared authentication token (clients must present this)
        #[arg(long)]
        auth_token: Option<String>,

        /// Use HMAC-SHA256 challenge/response auth instead of plain token
        #[arg(long)]
        auth_challenge: bool,

        /// Enable zstd compression for data frames
        #[arg(long)]
        compression: bool,

        /// Path to TLS certificate PEM file (enables AFTPS)
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key PEM file (enables AFTPS)
        #[arg(long)]
        tls_key: Option<String>,

        /// Maximum bandwidth in bytes/sec (0 = unlimited)
        #[arg(long, default_value = "0")]
        rate_limit: u64,

        /// Maximum number of concurrent connections (0 = unlimited)
        #[arg(long, default_value = "1000")]
        max_connections: usize,

        /// Transport layer: tcp, ws (WebSocket), or quic
        #[arg(long, default_value = "tcp")]
        transport: String,
    },

    /// Manage protocol handler plugins
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },

    /// Cryptographic operations (key generation, encryption, decryption)
    Crypto {
        #[command(subcommand)]
        action: CryptoAction,
    },

    /// Manage anonymous telemetry collection
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum PluginAction {
    /// List all loaded plugins
    List,

    /// Load a plugin from a shared library file
    Load {
        /// Path to the plugin shared library (.dll, .so, .dylib)
        path: String,
    },

    /// Unload a plugin by protocol scheme
    Unload {
        /// Protocol scheme of the plugin to unload
        scheme: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum CryptoAction {
    /// Generate a post-quantum keypair (Kyber1024 / ML-KEM)
    Keygen {
        /// Output file base name (creates .pub and .sec files)
        #[arg(long, short = 'o', default_value = "aft_key")]
        output: String,
    },

    /// Train a neural network cipher (generates .nn model file)
    Train {
        /// Number of training epochs
        #[arg(long, default_value = "5000")]
        epochs: usize,

        /// Learning rate
        #[arg(long, default_value = "0.01")]
        learning_rate: f32,

        /// Random seed for deterministic training
        #[arg(long, default_value = "42")]
        seed: u64,

        /// Output model file path
        #[arg(long, short = 'o', default_value = "cipher.nn")]
        output: String,
    },

    /// Encrypt a file
    Encrypt {
        /// Input file path
        input: String,

        /// Output file path (defaults to input + .enc)
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Encryption method: pqc, neural, hybrid
        #[arg(long, short = 'm', default_value = "pqc")]
        method: String,

        /// Key file (PQC .pub key or neural .nn model)
        #[arg(long, short = 'k')]
        key_file: String,
    },

    /// Decrypt a file
    Decrypt {
        /// Input encrypted file path
        input: String,

        /// Output file path (defaults to input without .enc)
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Key file (PQC .sec key or neural .nn model)
        #[arg(long, short = 'k')]
        key_file: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum TelemetryAction {
    /// Show telemetry status and what data is collected
    Status,

    /// Enable anonymous telemetry collection (default)
    #[command(name = "opt-in")]
    OptIn,

    /// Disable anonymous telemetry collection
    #[command(name = "opt-out")]
    OptOut,

    /// Generate a new anonymous installation ID
    Reset,

    /// Manually sync telemetry data to remote endpoint
    Sync {
        /// Maximum number of records to sync (default: all)
        #[arg(long, short = 'n')]
        limit: Option<usize>,
    },

    /// Clear local telemetry records
    Clear,

    /// Export telemetry records to a file
    Export {
        /// Output file path (defaults to stdout)
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Export format: json, jsonl (default: json)
        #[arg(long, short = 'f', default_value = "json")]
        format: String,

        /// Maximum number of records to export
        #[arg(long, short = 'n')]
        limit: Option<usize>,
    },

    /// Configure telemetry endpoint
    Config {
        /// Set the remote endpoint URL
        #[arg(long)]
        endpoint: Option<String>,

        /// Set the API key for authenticated endpoints
        #[arg(long)]
        api_key: Option<String>,
    },
}
