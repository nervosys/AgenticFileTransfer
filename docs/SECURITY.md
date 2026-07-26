# AFT Security Audit Report

**Tool:** AFT (Agentic File Transfer) v1.3.0  
**Date:** 2026-04-01  
**Scope:** Full codebase audit for Department of Defense (DoD) environment suitability  
**Frameworks:** CVE patterns, MITRE ATT&CK, NIST FIPS 140-3, CMMC 2.0 Level 2  

---

## Quick Assessment

| Environment           | Suitability     | Notes                                                 |
| --------------------- | --------------- | ----------------------------------------------------- |
| **CUI / CMMC L2**     | ✅ Ready         | With `--features fips`, TLS 1.2+, auth, audit logging |
| **SECRET**            | ⚠️ Conditional   | Requires FIPS build, cert pinning, network isolation  |
| **TOP SECRET / SCI**  | ❌ Not certified | Needs formal STIG evaluation and ATO process          |
| **Internet-facing**   | ✅ Ready         | Rate limiting, connection caps, path traversal, TLS   |
| **Air-gapped / SCIF** | ✅ Ready         | No external dependencies at runtime, local-only mode  |

---

## Executive Summary

AFT is a Rust-based file transfer CLI with 10+ protocol handlers, a custom binary wire
protocol (AFTP), a turbo transfer engine, and post-quantum encryption. This audit
evaluates the v1.3.0 codebase against DoD security requirements. Rust's memory safety
eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, data
races). Since v0.1.0, significant security hardening has been applied: structured audit
logging, auth rate limiting, connection semaphores, idle timeouts, session resume with
IP binding, per-frame CRC32 integrity, SMB input whitelisting, and credential scrubbing.

| Severity | Count | Summary                                                                                                                                                  |
| -------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Critical | 1     | Neural cipher is not cryptographically secure (experimental, marked with warnings)                                                                       |
| High     | 2     | Plugin SHA-256 is integrity-only, not authenticity; unsafe FFI plugin boundary with no sandbox                                                           |
| Medium   | 4     | Token auth timing oracle; `--insecure` persistable in config; no connection-rate DoS; unauthenticated encrypted file header                              |
| Low      | 7     | Silent audit failures; no log rotation; TOCTOU in safe_path; predictable temp names; no crash cleanup; rate limiter not persistent; no null-byte defense |
| Info     | 3     | No mTLS; session_id not populated in audit events; no SMB credential forwarding                                                                          |

---

## 1. CVE Pattern Analysis

### 1.1 CWE-22: Path Traversal

**Location:** `src/aftp/server.rs` — `ServerState::safe_path()`

**Current Mitigations (v1.3.0):**
- Rejects paths containing `..`
- Canonicalizes resolved paths via `tokio::fs::canonicalize()`
- Checks `starts_with(root)` after canonicalization
- Rejects absolute paths before join

**Assessment:** ✅ ADEQUATE — The defense-in-depth approach (deny `..`, canonicalize,
verify prefix) is robust. The `..` check as a fast-reject before canonicalization
prevents symlink-based traversal. The `canonicalize()` call resolves symlinks,
and `starts_with()` ensures the final path is within the server root.

**Residual Risk:** LOW — A TOCTOU (time-of-check-to-time-of-use) race exists between
`canonicalize()` and the subsequent file operation if an attacker can swap a symlink
between the two calls. This requires local filesystem access, making it impractical
for remote attackers.

**Recommendation:** Add explicit null-byte checks (`\0`) before path operations for
defense against null-byte injection.

### 1.2 CWE-78: OS Command Injection

**Location:** `src/protocols/smb.rs` — `smbclient_download()`, `smbclient_upload()`, `smbclient_list()`

**Current Mitigations (v1.3.0):**
- `validate_smb_component()` enforces a strict character whitelist: alphanumeric + `.-_ `
- `tokio::process::Command::new("smbclient")` with `.arg()` — no shell interpolation
- URL structure validated before paths reach the command builder

**Assessment:** ✅ ADEQUATE — The v1.3.0 whitelist (`validate_smb_component()`)
restricts share names, hostnames, and workgroups to safe characters. The use of
`Command::arg()` (not `shell()`) prevents argument injection. The `-c` command
string embeds server-validated paths with additional whitelist checking.

**Previous State (v0.1.0):** No input validation on SMB components. Marked as MEDIUM risk.

**Recommendation:** Log all smbclient invocations to the audit log.

### 1.3 CWE-295: Improper Certificate Validation

**Location:** `src/aftp/client.rs` — `InsecureCertVerifier`  
**Location:** `src/aftp/transport.rs` — `InsecureQuicVerifier`

**Current State (v1.3.0):** When `--insecure` flag is set, ALL certificate validation is
bypassed, accepting any server certificate without verification. The `InsecureMode`
event is now logged to the structured audit log when this flag is active.

**Risk:** MITM attacks when `--insecure` is used.

**Assessment:** ⚠️ HIGH — This is a necessary development/testing feature but
represents a significant risk in DoD environments. The `--insecure` flag can be
persisted in `~/.aft/config.toml`, which may lead to accidental insecure usage.

**Improvement since v0.1.0:** Audit log now records `InsecureMode` events.

**Recommendations:**
- Support certificate pinning (`--pin-cert <fingerprint>`)
- Support custom CA bundles (`--ca-bundle <path>`)
- Disable `--insecure` in production builds via feature flag
- Prevent `--insecure` from being persisted in config files

### 1.4 CWE-330: Insufficient Randomness

**Location:** `src/aftp/server.rs` — HMAC challenge nonce generation  
**Location:** `src/crypto/pqc.rs` — AES-256-GCM nonce via `OsRng`

**Current State (v1.3.0):** Challenge nonces use `rand::thread_rng()` (ChaCha20-based
CSPRNG). PQC encryption nonces use `OsRng` (OS-provided entropy).

**Assessment:** ✅ ADEQUATE — Both sources are cryptographically secure. `OsRng`
delegates to the OS CSPRNG (`BCryptGenRandom` on Windows, `getrandom` on Linux).

**Recommendation:** For FIPS environments, use a FIPS-validated DRBG or document
the `rand` CSPRNG as acceptable per the organization's crypto policy.

### 1.5 CWE-532: Information Exposure Through Log Files

**Location:** `src/history.rs` — credential scrubbing  
**Location:** `src/audit.rs` — structured audit logging

**Current Mitigations (v1.3.0):**
- `scrub_credentials()` strips `user:pass@` from URLs
- Scrubs 16 sensitive query parameters: `token`, `secret`, `password`, `key`, `auth`,
  `access_key`, `secret_key`, `api_key`, `sas`, `sig`, `signature`, `credential`,
  `client_secret`, `refresh_token`, `session_token`, `connection_string`
- Audit log file permissions restricted to `0o600` on Unix

**Assessment:** ✅ ADEQUATE — The v1.3.0 credential scrubbing is comprehensive and
covers all common cloud provider credential patterns.

**Previous State (v0.1.0):** No credential scrubbing. Marked as MEDIUM risk.

**Recommendation:** Add log rotation support to prevent unbounded audit log growth.

### 1.6 CWE-502: Deserialization of Untrusted Data

**Location:** `src/aftp/frame.rs` — binary frame parsing

**Current Mitigations (v1.3.0):**
- All binary parsers use bounds-checked helpers (`get_u8`, `get_u16`, `get_str`, etc.)
- `max_payload` limit (negotiated per-connection) prevents memory exhaustion
- Per-frame CRC32 integrity verification rejects corrupted/tampered frames
- Frame type validation with explicit match arms

**Assessment:** ✅ ADEQUATE — The bounds-checking approach prevents buffer over-reads.
The CRC32 per-frame integrity (added in v1.1.0) catches corruption or injection.
Rust's type system prevents buffer overflows at compile time.

### 1.7 CWE-208: Observable Timing Discrepancy (NEW)

**Location:** `src/aftp/server.rs` — simple token authentication

**Current State:** In simple token mode (non-challenge/response), the token comparison
uses standard string equality (`==`), which may short-circuit on the first differing
byte. This creates a timing side-channel that could leak token length or prefix.

**Assessment:** ⚠️ MEDIUM — The challenge/response mode (HMAC-SHA256) is immune to
timing attacks. This only affects installations using simple `--auth-token` mode.

**Recommendation:** Use `constant_time_eq` or `ring::constant_time::verify_slices_are_equal`
for all token comparisons. Deprecate simple token mode.

### 1.8 CWE-353: Missing Support for Integrity Check (NEW)

**Location:** `src/crypto/mod.rs` — encrypted file header

**Current State:** The 20-byte encrypted file header (magic, version, method,
original_len, kem_ct_len) is written in plaintext and not covered by the AES-256-GCM
AEAD authentication tag. An attacker could modify the header (e.g., `original_len`)
without detection.

**Assessment:** ⚠️ MEDIUM — Modifying `original_len` could cause allocation of
arbitrary sizes during decryption. The 1 TiB sanity check provides a ceiling but
doesn't prevent smaller malicious values.

**Recommendation:** Include the header bytes as AAD (Additional Authenticated Data)
in the AES-256-GCM encryption, or compute a separate HMAC over the header.

---

## 2. MITRE ATT&CK Mitigations

### T1190 — Exploit Public-Facing Application

**Applicable Components:** AFTP server (`src/aftp/server.rs`)

**Current Mitigations (v1.3.0):**
- Binary protocol with strict frame validation (magic bytes `0xAF 0x54`, version, type checking)
- Maximum payload size enforcement (`max_payload` negotiated per-connection)
- Path traversal protection in `safe_path()` (reject `..`, canonicalize, prefix verify)
- TLS encryption via `--tls-cert` / `--tls-key`
- Authentication via `--auth-token` with HMAC-SHA256 challenge/response
- **Connection semaphore** (`max_connections`) limits concurrent clients
- **Idle timeout** (`CONNECTION_IDLE_TIMEOUT_SECS = 300`) drops idle connections
- **Session management** (`SESSION_MAX_AGE_SECS = 600`, `MAX_SESSIONS = 10,000`)
- **Per-frame CRC32 integrity** catches corruption and injection

**Gaps:**
- No connection-rate limiting (TCP+TLS handshake completes before auth rate limiter)
- No IP allowlisting/denylisting
- DoS via repeated TLS handshakes (expensive) not mitigated

**Improvements since v0.1.0:** Connection semaphore, idle timeout, session limits, CRC32 per-frame.

**Recommendations:**
- Implement connection-rate limiting per source IP (pre-TLS)
- Add `--allow-ip` / `--deny-ip` ACL options
- Consider integration with OS-level firewalling (iptables, Windows Firewall)

### T1071 — Application Layer Protocol

**Assessment:** The custom AFTP protocol uses a well-defined binary framing format
with magic bytes (`0xAF 0x54`), versioning, and typed frames. This is detectable
by network security tools via the fixed magic bytes.

**Recommendation:** Document the wire protocol for security teams to create IDS/IPS
signatures. The magic bytes `AF 54` at offset 0 of each frame are suitable for
deep packet inspection rules.

### T1573 — Encrypted Channel

**Current State (v1.3.0):** AFTP supports TLS 1.2/1.3 via `tokio-rustls` + `rustls`
(ring backend). HTTP transfers respect HTTPS. FTPS, SFTP, and QUIC encrypted
channels are available. The turbo engine uses QUIC with `quinn`.

**FEC data plane (v1.4):** When `--fec` is used, bulk file data leaves the TLS
control stream and rides a UDP data plane. On an **authenticated** connection
each symbol is encrypted and authenticated with **AES-256-GCM** under a
per-session key (derived from the auth token and a random session id), so the
data plane provides its own confidentiality and integrity — a passive on-path
observer (T1040) recovers neither the file nor a usable oracle. On an
**unauthenticated** connection there is no key and symbols carry only a CRC32
(confidentiality/authenticity absent); this is a trusted-link/lab mode and must
not carry CUI. See the dedicated FEC section below.

**Gaps:**
- No TLS requirement enforcement (server accepts plain TCP by default)
- No minimum TLS version configuration
- No cipher suite restriction
- No mTLS (mutual TLS) for client certificate authentication
- FEC symbol crypto routes through `aws-lc-rs` (FIPS 140-3) under
  `--features fips` and RustCrypto `aes-gcm`/`hmac` otherwise; a default build
  is therefore unvalidated for the data plane (the PQC/neural pipelines remain
  RustCrypto regardless of the feature)

**Recommendations:**
- Add `--require-tls` server option to reject unencrypted connections
- Add `--min-tls-version` option (default TLS 1.2 for DoD)
- Add `--cipher-suites` option to restrict to FIPS-approved suites
- Implement mTLS for bidirectional certificate authentication

### T1078 — Valid Accounts / Brute Force

**Current Mitigations (v1.3.0):**
- HMAC-SHA256 challenge/response authentication (prevents token replay)
- **Auth rate limiting**: `AUTH_MAX_FAILURES = 5` per IP → `AUTH_LOCKOUT_SECS = 60`
- **AuthRateLimiter** struct with per-IP tracking and proactive cleanup
- All auth events logged to structured audit log (success, failure, lockout)
- Session resume requires IP binding + auth token re-verification

**Improvements since v0.1.0:** Auth rate limiting, audit logging, session IP binding.

**Residual Risks:**
- Simple token mode uses non-constant-time comparison (timing oracle)
- Rate limiter state is in-memory and resets on server restart
- Lockout period (60s) may be insufficient for determined attackers
- No progressive backoff (exponential delay)

**Recommendations:**
- Deprecate simple token auth; require challenge/response mode
- Implement persistent rate limiter state (survive restarts)
- Add progressive backoff (exponential delay after repeated failures)
- Require TLS when auth is enabled (`--auth-token` implies `--require-tls`)

### T1041 — Exfiltration Over C2 Channel

**Assessment:** AFT is a file transfer tool; it inherently supports data exfiltration
if accessible. This is a deployment consideration, not a code vulnerability.

**Recommendations:**
- Support `--read-only` server mode to prevent data exfiltration via PUT
- Support `--write-only` server mode to prevent data access via GET
- Implement file size limits for uploads/downloads
- Integrate with DLP (Data Loss Prevention) hooks

### T1059 — Command and Scripting Interpreter (NEW)

**Applicable Components:** Plugin system (`src/plugins.rs`)

**Current Mitigations (v1.3.0):**
- SHA-256 signature verification for plugins (sidecar `.sha256` file required)
- Plugins loaded via `libloading` FFI with explicit symbol resolution

**Gaps:**
- SHA-256 provides integrity only, not authenticity (no asymmetric signature)
- No plugin sandboxing; loaded code runs with full process privileges
- Malicious `.so`/`.dll` that passes SHA-256 check executes arbitrary native code

**Recommendations:**
- Replace SHA-256 with Ed25519 or ECDSA signature verification
- Implement plugin sandboxing (seccomp-bpf on Linux, AppContainer on Windows)
- Add `--disable-plugins` flag for hardened deployments

---

## 3. NIST FIPS 140-3 Compliance

### 3.1 Cryptographic Module Assessment

| Algorithm           | Usage                          | FIPS Approved?              | Implementation                  |
| ------------------- | ------------------------------ | --------------------------- | ------------------------------- |
| SHA-256             | File checksums, AFTP integrity | Yes (FIPS 180-4)            | `sha2` crate (ring backend)     |
| SHA-512             | Optional checksum              | Yes (FIPS 180-4)            | `sha2` crate                    |
| HMAC-SHA-256        | Challenge/response auth, FEC symbol-key KDF | Yes (FIPS 198-1)            | `hmac`+`sha2`; FEC KDF via `aws-lc-rs` under `--features fips` |
| CRC32               | Per-frame integrity (HW accel) | N/A (not crypto)            | `crc32fast` crate               |
| AES-256-GCM         | TLS data encryption, PQC AEAD, FEC symbols | Yes (FIPS 197 + SP 800-38D) | `rustls`/`ring`, `aes-gcm`; FEC via `aws-lc-rs` under `--features fips` |
| ML-KEM-1024         | Post-quantum KEM               | Yes (FIPS 203)              | `ml-kem` crate (RustCrypto)     |
| ChaCha20-Poly1305   | TLS alternative cipher         | Not FIPS-approved           | via `rustls` + `ring`           |
| X25519              | TLS key exchange               | Not FIPS-approved           | via `rustls` + `ring`           |
| ECDHE-P256/P384     | TLS key exchange               | Yes (SP 800-56A)            | via `rustls` + `ring`           |
| RSA                 | TLS signatures                 | Yes (FIPS 186-5)            | via `rustls` + `ring`           |
| MD5                 | Optional checksum              | **No** (deprecated)         | `md-5` crate                    |
| XOR widening (u64)  | Pre-CRC integrity layer        | N/A (not crypto)            | Custom (`src/crypto/mod.rs`)    |
| Neural cipher (OFB) | Experimental autoencoder       | **No** (NOT SECURE)         | Custom (`src/crypto/neural.rs`) |
| zstd                | Data compression               | N/A (not crypto)            | `zstd` crate                    |
| ChaCha20            | CSPRNG (nonce gen)             | Not FIPS-approved for DRBG  | `rand` crate                    |

### 3.2 FIPS Compliance Status

**Current Status: NOT FIPS COMPLIANT (but path available)**

The `ring` cryptographic library (used by `rustls`) is **not** a FIPS 140-2/3
validated module. While it implements FIPS-approved algorithms correctly, it has
not undergone CMVP validation.

**FIPS Feature Flag:** AFT v1.3.0 includes an optional `fips` feature in Cargo.toml
that switches to `aws-lc-rs` (Amazon's fork of BoringCrypto), which has FIPS 140-3
validation (certificate #4631).

**Path to Compliance:**

1. **Short-term:** Build with `--features fips` to use the `aws-lc-rs` backend
   for both TLS **and** the FEC data plane (AES-256-GCM + HMAC-SHA256, via
   `src/aftp/fec/symcrypto.rs`). Document current crypto usage and obtain a
   waiver/exception for algorithms not yet FIPS-validated (PQC, neural).

2. **Medium-term:** Replace `ring` with `aws-lc-rs` as the default backend.
   `rustls` supports `aws-lc-rs` via the `aws-lc-rs` feature flag.

3. **Long-term:** Implement `--fips` CLI mode where:
   - Only FIPS-approved cipher suites are available
   - MD5 checksum is disabled
   - ChaCha20-Poly1305 is excluded from TLS
   - X25519 key exchange is replaced with P-256/P-384 ECDHE
   - DRBG uses FIPS-validated implementation
   - Neural cipher is disabled
   - Kyber1024 is disabled until NIST finalizes ML-KEM validation

### 3.3 Critical Cryptographic Findings

**Neural Cipher (CRITICAL):**  
`src/crypto/neural.rs` implements an experimental autoencoder-based cipher using OFB
mode with PKCS7 padding. This is **NOT cryptographically secure** and must never be
used for protecting sensitive data. The autoencoder weights are static and the cipher
has no formal security proof. It is marked with warnings in the code but remains
callable via the `EncryptionMethod` enum.

**Status (RESOLVED at the CLI):** The `aft crypto encrypt --method neural` and
`aft crypto train` paths — and `--method hybrid`, which encrypts the bulk
payload with the neural cipher — are now gated behind a global
`--experimental-crypto` flag (off by default) and refuse to run without it,
printing an actionable message pointing at `--method pqc`. When the flag is set,
a runtime warning is emitted. Decryption is intentionally left ungated so
existing neural-encrypted data can still be recovered. The underlying library
function remains callable programmatically; the gate is at the CLI boundary.

**Kyber1024 / KyberSlash (RESOLVED):**  
The `pqc_kyber 0.7.1` crate had a timing side-channel (RUSTSEC-2023-0079,
"KyberSlash", CVSS 7.4 HIGH) and was unmaintained. **Fixed:** the PQC pipeline
(`src/crypto/pqc.rs`) was migrated to RustCrypto's maintained **`ml-kem` 0.3.2**
(FIPS-203 final ML-KEM-1024). This is a deliberate algorithm change — round-3
Kyber1024 keys/ciphertexts are not interoperable with ML-KEM-1024 — so the key
file format version was bumped (v1→v2) and legacy files are rejected with a
"regenerate with `aft keygen`" error.

### 3.4 Recommendations for FIPS Mode

```toml
# Cargo.toml change for FIPS crypto backend:
rustls = { version = "0.23", features = ["aws_lc_rs"] }
# Remove default ring dependency
```

Add a `--fips` CLI flag or `FIPS_MODE=1` env var that:
- Restricts TLS to FIPS-approved cipher suites only
- Disables MD5 checksum algorithm
- Disables the neural cipher (ML-KEM-1024 is FIPS 203 and stays enabled)
- Uses FIPS-validated DRBG for nonce generation
- Logs FIPS mode status on startup

---

## 4. CMMC 2.0 Level 2 Assessment

CMMC 2.0 Level 2 maps to NIST SP 800-171 Rev 2, with 110 practices across 14 domains.
Below are the domains most relevant to AFT as a file transfer tool.

### AC — Access Control

| Practice     | Description                                                      | Status    | Notes                                        |
| ------------ | ---------------------------------------------------------------- | --------- | -------------------------------------------- |
| AC.L2-3.1.1  | Limit access to authorized users                                 | ⚠️ Partial | Auth supported, server mode mandatory opt-in |
| AC.L2-3.1.2  | Limit access to authorized functions                             | ❌ Missing | No read-only/write-only mode                 |
| AC.L2-3.1.3  | Control CUI flow                                                 | ❌ Missing | No DLP integration                           |
| AC.L2-3.1.7  | Prevent non-privileged users from executing privileged functions | ✅ N/A     | CLI tool, follows OS-level permissions       |
| AC.L2-3.1.12 | Monitor and control remote access                                | ✅ Present | Auth rate limiting + audit logging           |

**Improvements since v0.1.0:** Auth rate limiting (`AUTH_MAX_FAILURES = 5` per IP,
`AUTH_LOCKOUT_SECS = 60`), connection semaphore (`max_connections`), idle timeout
(`CONNECTION_IDLE_TIMEOUT_SECS = 300`).

**Recommendations:**
- Make authentication mandatory for server mode in DoD deployments
- Implement RBAC (role-based access control): read, write, admin
- Integrate with organization identity providers (LDAP/SAML/OIDC)

### AU — Audit and Accountability

| Practice    | Description                  | Status    | Notes                                          |
| ----------- | ---------------------------- | --------- | ---------------------------------------------- |
| AU.L2-3.3.1 | Create audit records         | ✅ Present | Structured JSON audit log (`~/.aft/audit.log`) |
| AU.L2-3.3.2 | Provide audit record content | ✅ Present | Timestamp, event type, source IP, details      |
| AU.L2-3.3.3 | Review audit records         | ⚠️ Partial | JSON format parseable but no analysis tooling  |
| AU.L2-3.3.4 | Alert on audit failure       | ❌ Missing | Silent fallback on write errors                |
| AU.L2-3.3.5 | Correlate audit processes    | ⚠️ Partial | Session context present but session_id empty   |

**Improvements since v0.1.0:** Full structured audit logging system (`src/audit.rs`)
with 12 event types: `AuthSuccess`, `AuthFailure`, `AuthLockout`, `FileRead`,
`FileWrite`, `FileList`, `TlsHandshake`, `InsecureMode`, `ConnectionOpen`,
`ConnectionClose`, `ServerStart`, `ServerStop`. Log file permissions restricted
to `0o600` on Unix.

**Residual Gaps:**
- `session_id` field not populated in audit events (always empty)
- Audit log write failures are silent (no alerting)
- No log rotation (unbounded growth)
- No HMAC-signed log entries for tamper detection

**Recommendations:**
- Populate `session_id` in all audit events
- Implement log rotation (`--audit-max-size`, `--audit-max-files`)
- Alert on audit write failures (exit or degrade gracefully)
- Support syslog output for SIEM integration

### IA — Identification and Authentication

| Practice     | Description                                               | Status    | Notes                                          |
| ------------ | --------------------------------------------------------- | --------- | ---------------------------------------------- |
| IA.L2-3.5.1  | Identify system users                                     | ⚠️ Partial | Token-based, no user identity                  |
| IA.L2-3.5.2  | Authenticate users                                        | ✅ Present | HMAC-SHA256 challenge/response                 |
| IA.L2-3.5.3  | Use multifactor auth                                      | ❌ Missing | Single-factor only                             |
| IA.L2-3.5.7  | Enforce minimum password complexity                       | ❌ Missing | No token strength requirements                 |
| IA.L2-3.5.10 | Store/transmit only cryptographically-protected passwords | ✅ Present | Challenge/response mode protects token on wire |

**Improvements since v0.1.0:** Challenge/response auth strengthened, auth failures
logged to structured audit log with source IP, session resume binds to client IP.

**Recommendations:**
- Enforce minimum auth token length (16+ characters)
- Deprecate simple token transmission in favor of challenge/response only
- Add support for PKI/certificate-based client authentication (mTLS)
- Implement session tokens with expiration

### SC — System and Communications Protection

| Practice      | Description                                    | Status    | Notes                                       |
| ------------- | ---------------------------------------------- | --------- | ------------------------------------------- |
| SC.L2-3.13.1  | Monitor communications at boundaries           | ✅ Present | Audit logging of connections                |
| SC.L2-3.13.2  | Employ architectural designs to protect CUI    | ⚠️ Partial | TLS available but not enforced              |
| SC.L2-3.13.6  | Deny network traffic by default                | ⚠️ Partial | Connection semaphore limits, no IP ACLs     |
| SC.L2-3.13.8  | Implement crypto mechanisms for CUI in transit | ⚠️ Partial | TLS available, FIPS feature flag present    |
| SC.L2-3.13.11 | Employ FIPS-validated cryptography             | ⚠️ Partial | Available via `--features fips` (aws-lc-rs) |

**Improvements since v0.1.0:** Connection semaphore, idle timeout, session management,
per-frame CRC32 integrity, FIPS feature flag (`aws-lc-rs` backend).

**Recommendations:**
- Default to TLS-enabled connections for DoD deployment
- Implement IP allowlisting for server mode
- Make `--features fips` the default for DoD builds

### MP — Media Protection

| Practice    | Description                  | Status    | Notes                                                |
| ----------- | ---------------------------- | --------- | ---------------------------------------------------- |
| MP.L2-3.8.1 | Protect media containing CUI | ⚠️ Partial | Temp files cleaned up, but crash may leave artifacts |
| MP.L2-3.8.2 | Limit access to CUI on media | ✅ Present | Uses OS file permissions, key files 0o600            |

**Improvements since v0.1.0:** PQC key files restricted to `0o600`, audit log `0o600`,
atomic temp-file-then-rename for PUT operations.

**Recommendations:**
- Implement secure deletion (overwrite before unlink) for temp files
- Add crash handler to clean up temp files
- Use unpredictable temp file names (random suffix)

---

## 4a. FEC Data Plane Security (v1.4)

The `--fec` flag adds a fountain-coded UDP data plane alongside the existing TCP
control plane. Because bulk file data then leaves the TLS-protected control
stream, the data plane carries its own cryptography. This section documents its
security properties; the code is in `src/aftp/fec/`.

### Confidentiality & integrity

| Property               | Authenticated connection (`--auth-token` / `aftps://`)                          | Unauthenticated connection            |
| ---------------------- | ------------------------------------------------------------------------------- | ------------------------------------- |
| Symbol confidentiality | **AES-256-GCM** per symbol                                                      | ❌ none (plaintext)                    |
| Symbol authenticity    | **AES-256-GCM tag**, envelope header bound as AAD                               | ❌ CRC32 only (not a MAC)              |
| Key                    | 32-byte key = HMAC-SHA256(token, "aft-fec-symbol-key-v2" ‖ session_id)          | none                                  |
| Session id             | **cryptographically random** 64-bit, exchanged in the (TLS-protected) offer     | random                                |
| Nonce                  | 96-bit random per datagram                                                      | n/a                                   |
| Block commit           | SHA-256 over the whole object, verified before the file is materialized         | same                                  |

The random per-session id makes the derived key unpredictable and unique, so a
captured datagram cannot be replayed or decrypted into another session. The
GCM tag with the header as AAD means any edit to the session id, block id,
length, nonce, or ciphertext fails verification and the datagram is dropped
before it reaches the decoder.

### Unauthenticated mode is lab-only, and refused by default

With no auth token there is no symbol key, so `--fec` would fall back to a CRC32
that detects corruption but provides **neither confidentiality nor
authenticity**. To prevent that from happening by accident, an **unauthenticated
server refuses FEC by default** (`server.rs`): it does not advertise `CAP_FEC`,
so a client that asked for `--fec` transparently falls back to the reliable
path. The only way to run the cleartext data plane is to start the server with
the explicit `--fec-insecure` flag, which is documented for physically trusted
links exclusively and must **never** carry CUI. For CMMC L2 / CUI, always run
`--fec` with `--auth-token` (preferably over `aftps://`), which gives the
AES-256-GCM path above.

### FIPS status

The FEC symbol crypto (AES-256-GCM AEAD + HMAC-SHA256 KDF) is centralized in
`src/aftp/fec/symcrypto.rs`, which routes to the FIPS 140-3 validated
`aws-lc-rs` module under `--features fips` and to the RustCrypto
`aes-gcm`/`hmac`/`sha2` crates otherwise. **A `--features fips` build therefore
places the `--fec` data plane inside the same validated boundary as the TLS
control plane** — bulk data no longer needs to stay on the TLS path for
validated-crypto CUI. The wire format is byte-identical across backends (a KDF
known-answer test and the AEAD round-trip tests run under both feature sets), so
FIPS and default peers interoperate.

A **default (non-FIPS) build** still uses RustCrypto for the data plane: the
algorithms are FIPS-*approved* but outside the validated module. The PQC
(`pqc_kyber`) and neural pipelines remain RustCrypto/unvalidated regardless of
the feature — FIPS coverage now spans TLS + FEC, not those.

### Denial of service

- **Amplification/reflection:** the sender pins the UDP peer to the control
  connection's IP (`server.rs`, `client.rs`); only the port is peer-supplied, so
  symbols cannot be reflected to a third party.
- **Receiver memory:** downloads stream to a temp file (renamed into place only
  after SHA-256 verification), and the receiver caps concurrent RaptorQ decoders
  to the negotiated window — a malicious sender cannot exhaust memory by
  declaring a huge size or spraying many distinct block ids.
- **Forgery flood:** unverifiable datagrams are rejected before decode; a
  connected UDP socket drops off-path packets at the kernel.

### CMMC mapping (data plane)

| Practice      | With authenticated `--fec`                                  |
| ------------- | ----------------------------------------------------------- |
| SC.L2-3.13.8  | ✅ AES-256-GCM encrypts CUI symbols in transit               |
| SC.L2-3.13.11 | ⚠️ FIPS-approved algorithm, not via the validated module    |
| SC.L2-3.13.16 | ✅ SHA-256 block commit protects integrity of CUI at rest    |

---

## 5. Security Hardening Recommendations Summary

### Priority 1 — Critical (Required for DoD)

| #   | Recommendation                    | Status      | Notes                                          |
| --- | --------------------------------- | ----------- | ---------------------------------------------- |
| 1   | FIPS-validated crypto backend     | ⚠️ Available | `--features fips` flag ready, not default yet  |
| 2   | Enforce TLS for auth              | ❌ Not done  | `--auth-token` should imply `--require-tls`    |
| 3   | Gate neural cipher behind feature | ❌ Not done  | Currently callable via `EncryptionMethod` enum |
| 4   | Plugin Ed25519 signatures         | ❌ Not done  | SHA-256 integrity only, no authenticity        |

### Priority 2 — High (Strongly Recommended)

| #   | Recommendation               | Status     | Notes                                          |
| --- | ---------------------------- | ---------- | ---------------------------------------------- |
| 5   | Auth rate limiting           | ✅ Done     | 5 failures → 60s lockout per IP                |
| 6   | Deprecate simple token auth  | ❌ Not done | Timing oracle in `==` comparison               |
| 7   | `--require-tls` server mode  | ❌ Not done | Server accepts plain TCP by default            |
| 8   | Connection limits            | ✅ Done     | Semaphore-based `max_connections`              |
| 9   | Structured audit logging     | ✅ Done     | 12 event types, JSON format, 0o600 permissions |
| 10  | Credential scrubbing in logs | ✅ Done     | 16 sensitive param names stripped              |

### Priority 3 — Medium (Recommended)

| #   | Recommendation                 | Status     | Notes                                |
| --- | ------------------------------ | ---------- | ------------------------------------ |
| 11  | `--fips` mode flag             | ❌ Not done | Runtime FIPS-only cipher restriction |
| 12  | Certificate pinning            | ❌ Not done | `--pin-cert` for known server certs  |
| 13  | Session timeouts               | ✅ Done     | 300s idle, 600s max age              |
| 14  | IP allowlisting / denylisting  | ❌ Not done | `--allow-ip` / `--deny-ip`           |
| 15  | Encrypt file header as AAD     | ❌ Not done | Header currently unauthenticated     |
| 16  | Constant-time token comparison | ❌ Not done | Simple token mode uses `==`          |
| 17  | Persistent rate limiter state  | ❌ Not done | In-memory, resets on restart         |

### Priority 4 — Low (Nice to Have)

| #   | Recommendation                | Status     | Notes                                  |
| --- | ----------------------------- | ---------- | -------------------------------------- |
| 18  | RBAC for server               | ❌ Not done | Read-only, write-only, admin roles     |
| 19  | Audit log rotation            | ❌ Not done | Unbounded growth currently             |
| 20  | Audit write failure alerting  | ❌ Not done | Silent on errors                       |
| 21  | Populate session_id in events | ❌ Not done | Always empty                           |
| 22  | DLP hooks                     | ❌ Not done | File content scanning before transfer  |
| 23  | SIEM / syslog integration     | ❌ Not done | For enterprise log aggregation         |
| 24  | Secure deletion of temp files | ❌ Not done | Overwrite before unlink                |
| 25  | Plugin sandboxing             | ❌ Not done | seccomp-bpf / AppContainer             |
| 26  | mTLS client certificate auth  | ❌ Not done | Bidirectional certificate verification |

---

## 6. Current Security Strengths

1. **Rust memory safety**: Eliminates buffer overflows, use-after-free, and data races
2. **Bounds-checked binary parsing**: All frame parsers use checked helpers with error returns
3. **Path traversal protection**: Multi-layer defense (string check + canonicalize + prefix verify)
4. **Payload size limits**: Prevents memory exhaustion from oversized frames
5. **Atomic file writes**: PUT uses temp-file-then-rename for integrity
6. **Streaming checksums**: SHA-256 verification during transfer, not after
7. **Modern TLS**: TLS 1.2/1.3 via rustls (no OpenSSL dependency, no legacy protocols)
8. **Challenge/response auth**: HMAC-SHA256 prevents token replay attacks
9. **No unsafe code in core logic**: Only in plugin FFI loading (inherently unsafe)
10. **Dependency minimalism**: Small dependency tree reduces supply chain risk
11. **Structured audit logging**: 12 event types, JSON format, restricted file permissions
12. **Auth rate limiting**: Per-IP tracking with lockout (5 failures → 60s)
13. **Connection management**: Semaphore-based limits, idle timeouts, session max age
14. **Per-frame CRC32 integrity**: Hardware-accelerated, catches corruption and injection
15. **XOR widening**: u64-widened pre-integrity layer for additional tamper detection
16. **Post-quantum encryption**: Kyber1024 KEM + AES-256-GCM AEAD (experimental)
17. **Credential scrubbing**: 16 sensitive parameter names stripped from logs/history
18. **Session resume with IP binding**: Reconnection requires same client IP + re-auth
19. **SMB input whitelisting**: Strict character validation prevents injection
20. **Plugin integrity verification**: SHA-256 sidecar check before loading
21. **FIPS feature flag**: `aws-lc-rs` backend available via `--features fips`
22. **Key file permissions**: PQC key files restricted to `0o600`

---

## Appendix A: Dependency Security Assessment

### Direct Dependencies

| Dependency | Version      | Risk     | Notes                                         |
| ---------- | ------------ | -------- | --------------------------------------------- |
| tokio      | 1.x          | Low      | Well-audited async runtime                    |
| reqwest    | 0.12         | Low      | Uses rustls (no OpenSSL)                      |
| rustls     | 0.23         | Low      | Memory-safe TLS, audited                      |
| ring       | (via rustls) | Medium   | Not FIPS-validated                            |
| sha2       | 0.10         | Low      | Pure Rust, RustCrypto project                 |
| hmac       | 0.12         | Low      | Pure Rust, RustCrypto project                 |
| aes-gcm    | 0.10         | Low      | Pure Rust, RustCrypto project                 |
| rand       | 0.8          | Low      | ChaCha20-based CSPRNG                         |
| zstd       | 0.13         | Low      | Wrapper around well-tested C library          |
| libloading | 0.8          | Medium   | Dynamic library loading (inherently risky)    |
| quinn      | 0.11         | Low      | QUIC implementation using rustls              |
| suppaftp   | 6.x          | Medium   | Less widely audited                           |
| russh      | 0.62         | Low      | SSH; bumped from 0.46 (RUSTSEC-2026-0154/0153 fixed) |
| rust-s3    | 0.37.2       | Low      | S3; bumped from 0.35 — pulls quick-xml 0.38 + webpki 0.103 (advisories cleared) |
| ml-kem     | 0.3.2        | Low      | Post-quantum ML-KEM-1024 (RustCrypto); replaced unmaintained `pqc_kyber` |
| crc32fast  | 1.4          | Low      | Hardware-accelerated CRC32, widely used       |
| aws-lc-rs  | 1.x (opt)    | Low      | FIPS 140-3 validated (cert #4631)             |

### `cargo audit` Results (refreshed 2026-07)

**Fixed in this release** by pulling semver-compatible patched versions (no API
change): the highest-severity, remotely-reachable advisories.

| Advisory          | Crate           | Was → Now          | Description                                            |
| ----------------- | --------------- | ------------------ | ----------------------------------------------------- |
| RUSTSEC-2026-0185 | quinn-proto     | 0.11.14 → 0.11.15  | Remote memory exhaustion via unbounded stream reassembly (QUIC path) |
| RUSTSEC-2026-0098/0099/0104 | rustls-webpki (0.103) | 0.103.10 → 0.103.13 | Name-constraint bypasses + reachable CRL panic in cert validation |
| RUSTSEC-2026-0204 | crossbeam-epoch | 0.9.18 → 0.9.20    | Invalid pointer deref (dev-only, via criterion)       |

**Fixed by the major-bump migration (see HANDOFF §6 #1):**

| Advisory          | Crate           | Was → Now          | Description                                            |
| ----------------- | --------------- | ------------------ | ----------------------------------------------------- |
| RUSTSEC-2026-0154/0153 | russh / russh-cryptovec | 0.46 → 0.62 | Unbounded 32-bit alloc DoS from a malicious SSH server (SFTP/SCP handler). API rework: `russh-keys`→`russh::keys`, native async `Handler`. |
| RUSTSEC-2026-0194/0195 | quick-xml       | 0.32 → 0.38 (via rust-s3 0.37.2) | Quadratic / unbounded-alloc XML DoS in the S3 handler's response parser. |
| RUSTSEC-2026-0098/0099/0104 | rustls-webpki (S3 chain) | 0.101.7 → 0.103.13 (via rust-s3 0.37.2) | Cert-validation flaws on the S3 handler's old TLS stack; now on the same fixed webpki as the main path. |
| RUSTSEC-2023-0079 | pqc_kyber       | 0.7 → `ml-kem` 0.3.2 | KyberSlash timing side-channel; migrated off the unmaintained crate to FIPS-203 ML-KEM-1024 (breaking key-format change). |

**Remaining — no upstream fix (accepted, monitored):**

| Advisory          | Crate           | Severity        | Exposure in AFT                                                  |
| ----------------- | --------------- | --------------- | --------------------------------------------------------------- |
| RUSTSEC-2023-0071 | rsa 0.10.0-rc   | 🟡 MEDIUM (5.9)  | Marvin timing attack. Now transitive-only via `russh`/`ssh-key` (SFTP host keys); AFT performs no RSA decryption itself and no fixed release exists. Removing it entirely would mean dropping RSA SSH host-key support. |

**Unmaintained-crate warnings (informational):** `async-std` (via suppaftp/FTP),
`number_prefix` (via indicatif), `rustls-pemfile`, `spin` (yanked, via
rsa/ssh-key). None are known-exploitable; tracked with their parent crates.

---

## Appendix B: Threat Model Summary

```
                         ┌─────────────────────┐
                         │   AFTP Server        │
                         │   (Public-facing)    │
                         └───────┬──────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
   ┌────▼──────┐           ┌─────▼──────┐          ┌──────▼─────┐
   │ Auth      │           │ File       │          │ Network    │
   │ Attacks   │           │ Access     │          │ Attacks    │
   │           │           │            │          │            │
   │ • Brute   │           │ • Path     │          │ • MITM     │
   │   force   │           │   traversal│          │ • Replay   │
   │ • Token   │           │ • Symlink  │          │ • DoS      │
   │   replay  │           │   escape   │          │ • Sniffing │
   │ • Cred    │           │ • Dir      │          │ • Frame    │
   │   stuffing│           │   listing  │          │   injection│
   │ • Timing  │           │ • TOCTOU   │          │ • TLS      │
   │   oracle  │           │            │          │   downgrade│
   └───────────┘           └────────────┘          └────────────┘

   Mitigations:            Mitigations:            Mitigations:
   ✅ Rate limiting        ✅ safe_path()          ✅ TLS 1.2/1.3
   ✅ HMAC challenge       ✅ Canonicalize         ✅ Per-frame CRC32
   ✅ Audit logging        ✅ Prefix check         ✅ Max payload
   ⚠️ Timing in simple    ✅ Atomic writes        ⚠️ TLS optional
     token mode            ⚠️ TOCTOU race         ❌ No mTLS
```

**Risk Rating for DoD Deployment: LOW-MEDIUM** (improved from MEDIUM in v0.1.0)

AFT v1.3.0 includes auth rate limiting, structured audit logging, connection management,
per-frame integrity, and credential scrubbing. With the recommended hardening measures
(FIPS feature flag, TLS enforcement, constant-time token comparison), AFT is suitable
for DoD environments at the CUI (Controlled Unclassified Information) level.

---

## Appendix C: Version Comparison (v0.1.0 → v1.3.0)

| Finding (v0.1.0)                  | Severity (v0.1.0) | Status (v1.3.0)                             |
| --------------------------------- | ----------------- | ------------------------------------------- |
| No FIPS-validated crypto          | Critical          | ⚠️ FIPS feature flag available               |
| Plugin loads arbitrary code       | Critical          | ⚠️ SHA-256 integrity check added             |
| InsecureCertVerifier bypasses TLS | High              | ⚠️ Audit event logged, still present         |
| No auth rate limiting             | High              | ✅ FIXED — 5 failures → 60s lockout          |
| Plain token auth mode             | High              | ⚠️ Timing oracle, challenge/response avail   |
| No audit logging subsystem        | Medium            | ✅ FIXED — 12 event types, JSON format       |
| rand 0.8 nonce generation         | Medium            | ✅ ADEQUATE — CSPRNG, OsRng for PQC          |
| No session timeout                | Medium            | ✅ FIXED — 300s idle, 600s max age           |
| smbclient command injection risk  | Medium            | ✅ FIXED — whitelist validation              |
| No banner hardening               | Low               | ⚠️ Partial — server version in HELLO_ACK     |
| Temp file cleanup on crash        | Low               | ⚠️ Partial — atomic writes, no crash handler |
| Verbose error messages            | Low               | ✅ FIXED — errors sanitized                  |
