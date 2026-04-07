import { DocPage } from "@/components/DocPage";

const content = `
## Prerequisites

- **Rust toolchain** — [rustup.rs](https://rustup.rs) (MSRV 1.75)
- **Git** — to clone the repository
- **C/C++ toolchain** — only required for the \`fips\` feature (cmake, clang or gcc)

## Install from Source

\`\`\`bash
git clone https://github.com/nervosys/AgenticFileTransfer.git
cd AgenticFileTransfer
cargo install --path .
\`\`\`

The \`aft\` binary is now available in your \`$PATH\`.

## Build from Source

\`\`\`bash
cargo build --release
# Binary at target/release/aft (or aft.exe on Windows)
\`\`\`

### FIPS 140-3 Build

For DoD and government environments requiring FIPS-validated cryptography:

\`\`\`bash
cargo build --release --features fips
\`\`\`

This switches the TLS provider to aws-lc-rs (FIPS 140-3 validated). Requires cmake and a C/C++ compiler.

### Release Profile

The release binary is optimized with LTO, single codegen unit, stripped symbols, and \`panic=abort\` — resulting in a ~9 MB self-contained executable with zero runtime dependencies.

## Verify Installation

\`\`\`bash
aft --version
# aft 1.3.0

aft --help
\`\`\`

## Your First Transfer

### Download a file

\`\`\`bash
aft get https://example.com/data.tar.gz
\`\`\`

### Upload a file

\`\`\`bash
aft put ./report.pdf https://upload.example.com/files/
\`\`\`

### Copy locally

\`\`\`bash
aft copy ./src/ ./backup/src/ -r
\`\`\`

### Compute a checksum

\`\`\`bash
aft checksum ./file.tar.gz --algorithm sha256
\`\`\`

## Agent Mode

AFT is designed for AI agent integration. Use \`--agent\` for structured JSON output with no interactive elements:

\`\`\`bash
# Structured JSON output
aft --agent get https://example.com/data.json -o /tmp/data.json

# Discover capabilities programmatically
aft --agent capabilities

# Full ontology schema for tool registration
aft --agent schema
\`\`\`

## Configuration

AFT stores configuration and data in \`~/.aft/\`:

| File | Purpose |
|------|---------|
| \`config.toml\` | Persistent settings (created on first use) |
| \`history.jsonl\` | Transfer history (JSON Lines) |
| \`audit.log\` | Security audit trail (JSON Lines) |
| \`plugins/\` | Custom protocol handler shared libraries |

All files are created lazily — \`~/.aft/\` is only populated when needed. AFT requires no configuration to operate; every option can be passed as a CLI flag.

## Turbo Mode

Enable the high-performance turbo transfer engine with a single flag:

\`\`\`bash
aft get aftp://server:2600/payload.bin --turbo
\`\`\`

Turbo mode automatically probes link characteristics (RTT, bandwidth, BDP) and selects the optimal transfer strategy — multi-stream, memory-mapped I/O, or standard — with up to 128 parallel streams and 16 MiB socket buffers.

## Post-Quantum Encryption

Generate a key pair and encrypt files with NIST FIPS 203 ML-KEM (Kyber1024):

\`\`\`bash
# Generate keys
aft crypto keygen -o ./keys/

# Encrypt
aft crypto encrypt -i secret.pdf -o secret.enc --method pqc -k ./keys/aft_public.key

# Decrypt
aft crypto decrypt -i secret.enc -o secret.pdf -k ./keys/aft_secret.key
\`\`\`

## Next Steps

- [Commands Reference](/docs/commands) — Full reference for all commands, subcommands, and flags
- [Security Audit](/docs/security) — CVE, MITRE ATT&CK, FIPS, CMMC 2.0 assessment
- [Benchmarks](/docs/benchmarks) — Criterion performance data
`;

export default function GettingStartedPage() {
  return (
    <DocPage
      title="Getting Started"
      subtitle="Install AFT and run your first transfer in under two minutes."
      content={content}
    />
  );
}
