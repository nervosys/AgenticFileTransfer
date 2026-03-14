# AFT Security Audit Report

**Tool:** AFT (Agentic File Transfer) v0.1.0  
**Date:** 2025  
**Scope:** Full codebase audit for Department of Defense (DoD) environment suitability  
**Frameworks:** CVE patterns, MITRE ATT&CK, NIST FIPS 140-3, CMMC 2.0 Level 2  

---

## Executive Summary

AFT is a Rust-based file transfer CLI with 10 protocol handlers and a custom binary wire
protocol (AFTP). This audit evaluates the codebase against DoD security requirements.
Rust's memory safety eliminates entire classes of vulnerabilities (buffer overflows,
use-after-free, data races). The findings below focus on configuration, protocol design,
and operational security gaps that require mitigation for DoD deployment.

| Severity | Count | Summary                                                                                                     |
| -------- | ----- | ----------------------------------------------------------------------------------------------------------- |
| Critical | 2     | No FIPS-validated crypto module; plugin system loads arbitrary code                                         |
| High     | 3     | InsecureCertVerifier bypasses TLS; no auth rate limiting; plain token auth mode                             |
| Medium   | 4     | No audit logging subsystem; rand 0.8 nonce generation; no session timeout; smbclient command injection risk |
| Low      | 3     | No banner hardening; temp file cleanup on crash; verbose error messages                                     |

---

## 1. CVE Pattern Analysis

### 1.1 CWE-22: Path Traversal

**Location:** `src/aftp/server.rs` — `ServerState::safe_path()`

**Current Mitigations:**
- Rejects paths containing `..`
- Canonicalizes resolved paths
- Checks `starts_with(root)` after canonicalization

**Assessment:** ✅ ADEQUATE — The defense-in-depth approach (deny `..`, canonicalize,
verify prefix) is robust. The `..` check as a fast-reject before canonicalization
prevents symlink-based traversal. The `canonicalize()` call resolves symlinks,
and `starts_with()` ensures the final path is within the server root.

**Recommendation:** Add explicit symlink resolution logging when `verbose` is enabled
for forensic analysis.

### 1.2 CWE-78: OS Command Injection

**Location:** `src/protocols/smb.rs` — `smbclient_download()`, `smbclient_upload()`, `smbclient_list()`

**Current State:** SMB handler constructs smbclient commands using string formatting
with user-provided paths. While `tokio::process::Command` with separate arguments
prevents shell injection on the command array level, the `-c` argument passes a
command string where paths are embedded with double-quote wrapping.

**Risk:** A path containing `"` characters could break out of the quoting.

**Mitigation Applied:** The SMB URL parser validates URL structure before paths reach
the command builder. Paths come from URL parsing which constrains the character set.
However, for hardening:

**Recommendation:**
- Sanitize path components to reject characters outside `[a-zA-Z0-9._/ -]`
- Prefer UNC path access (no subprocess) when available
- Log all smbclient invocations for audit trail

### 1.3 CWE-295: Improper Certificate Validation

**Location:** `src/aftp/client.rs` — `InsecureCertVerifier`  
**Location:** `src/aftp/transport.rs` — `InsecureQuicVerifier`

**Current State:** When `--insecure` flag is set, ALL certificate validation is
bypassed, accepting any server certificate without verification.

**Risk:** MITM attacks when `--insecure` is used.

**Assessment:** ⚠️ HIGH — This is a necessary development/testing feature but
represents a significant risk in DoD environments.

**Recommendations:**
- Add prominent warning output when `--insecure` is activated
- Support certificate pinning (`--pin-cert <fingerprint>`)
- Support custom CA bundles (`--ca-bundle <path>`)
- Disable `--insecure` in production builds via feature flag
- Log a security event when insecure mode is engaged

### 1.4 CWE-330: Insufficient Randomness

**Location:** `src/aftp/server.rs` — HMAC challenge nonce generation

**Current State:** Uses `rand::thread_rng()` (ChaCha20-based CSPRNG from `rand 0.8`).

**Assessment:** ✅ ADEQUATE for most uses — `thread_rng()` is cryptographically
secure. However, `rand 0.8` is not formally FIPS-validated.

**Recommendation:** For FIPS environments, use a FIPS-validated DRBG or document
the `rand` CSPRNG as acceptable per the organization's crypto policy.

### 1.5 CWE-532: Information Exposure Through Log Files

**Location:** `src/history.rs`, server verbose output

**Current State:** Transfer history logs source/destination URLs which may contain
credentials in URLs or auth tokens in query strings.

**Recommendation:**
- Scrub credentials from logged URLs (strip `user:pass@` and sensitive query params)
- Mark history.json with restricted file permissions (0600)
- Support secure log rotation

### 1.6 CWE-502: Deserialization of Untrusted Data

**Location:** `src/aftp/frame.rs` — binary frame parsing

**Current State:** All binary parsers use bounds-checked helpers (`get_u8`, `get_u16`,
`get_str`, etc.) that return errors on truncated input. The `max_payload` limit
prevents memory exhaustion from oversized frames.

**Assessment:** ✅ ADEQUATE — The bounds-checking approach prevents buffer over-reads.
The `max_payload` limit (negotiated per-connection) prevents memory bombs.
Rust's type system prevents buffer overflows at compile time.

---

## 2. MITRE ATT&CK Mitigations

### T1190 — Exploit Public-Facing Application

**Applicable Components:** AFTP server (`src/aftp/server.rs`)

**Current Mitigations:**
- Binary protocol with strict frame validation (magic bytes, version, type checking)
- Maximum payload size enforcement (`max_payload` parameter)
- Path traversal protection in `safe_path()`
- TLS encryption available via `--tls-cert` / `--tls-key`
- Authentication via `--auth-token` with optional challenge/response

**Gaps:**
- No connection rate limiting (DoS vulnerability)
- No IP allowlisting/denylisting
- No maximum concurrent connection limit

**Recommendations:**
- Implement connection-rate limiting per source IP
- Add `--max-connections` server option
- Add `--allow-ip` / `--deny-ip` ACL options
- Consider fail2ban integration for repeated auth failures

### T1071 — Application Layer Protocol

**Assessment:** The custom AFTP protocol uses a well-defined binary framing format
with magic bytes (`0xAF 0x54`), versioning, and typed frames. This is detectable
by network security tools via the fixed magic bytes.

**Recommendation:** Document the wire protocol for security teams to create IDS/IPS
signatures. The magic bytes `AF 54` at offset 0 of each frame are suitable for
deep packet inspection rules.

### T1573 — Encrypted Channel

**Current State:** AFTP supports TLS 1.2/1.3 via `tokio-rustls` + `rustls` (ring backend).
HTTP transfers respect HTTPS. FTPS and SFTP encrypted channels are available.

**Gaps:**
- No TLS requirement enforcement (server accepts plain TCP by default)
- No minimum TLS version configuration
- No cipher suite restriction

**Recommendations:**
- Add `--require-tls` server option to reject unencrypted connections
- Add `--min-tls-version` option (default TLS 1.2 for DoD)
- Add `--cipher-suites` option to restrict to FIPS-approved suites
- Log TLS version and cipher negotiated per connection

### T1078 — Valid Accounts / Brute Force

**Current State:** Authentication supports:
1. Simple token comparison (constant-time via string equality)
2. HMAC-SHA256 challenge/response

**Gaps:**
- No authentication attempt rate limiting
- No account lockout mechanism
- No failed auth event logging (beyond verbose stderr)
- Simple token mode transmits the token in the HELLO frame (plaintext if not TLS)

**Recommendations:**
- Implement per-IP auth failure rate limiting (e.g., 5 failures → 30s lockout)
- Log all auth attempts (success and failure) with timestamp and source IP
- Deprecate simple token auth; require challenge/response mode
- Require TLS when auth is enabled (`--auth-token` implies `--require-tls`)

### T1041 — Exfiltration Over C2 Channel

**Assessment:** AFT is a file transfer tool; it inherently supports data exfiltration
if accessible. This is a deployment consideration, not a code vulnerability.

**Recommendations:**
- Support `--read-only` server mode to prevent data exfiltration via PUT
- Support `--write-only` server mode to prevent data access via GET
- Implement file size limits for uploads/downloads
- Integrate with DLP (Data Loss Prevention) hooks

---

## 3. NIST FIPS 140-3 Compliance

### 3.1 Cryptographic Module Assessment

| Algorithm         | Usage                          | FIPS Approved?             | Implementation              |
| ----------------- | ------------------------------ | -------------------------- | --------------------------- |
| SHA-256           | File checksums, AFTP integrity | Yes (FIPS 180-4)           | `sha2` crate (ring backend) |
| SHA-512           | Optional checksum              | Yes (FIPS 180-4)           | `sha2` crate                |
| HMAC-SHA-256      | Challenge/response auth        | Yes (FIPS 198-1)           | `hmac` + `sha2` crates      |
| MD5               | Optional checksum              | **No** (deprecated)        | `md-5` crate                |
| AES-256-GCM       | TLS data encryption            | Yes (FIPS 197)             | via `rustls` + `ring`       |
| ChaCha20-Poly1305 | TLS alternative cipher         | Not FIPS-approved          | via `rustls` + `ring`       |
| X25519            | TLS key exchange               | Not FIPS-approved          | via `rustls` + `ring`       |
| ECDHE-P256/P384   | TLS key exchange               | Yes (SP 800-56A)           | via `rustls` + `ring`       |
| RSA               | TLS signatures                 | Yes (FIPS 186-5)           | via `rustls` + `ring`       |
| zstd              | Data compression               | N/A (not crypto)           | `zstd` crate                |
| ChaCha20          | CSPRNG (nonce gen)             | Not FIPS-approved for DRBG | `rand` crate                |

### 3.2 FIPS Compliance Status

**Current Status: NOT FIPS COMPLIANT**

The `ring` cryptographic library (used by `rustls`) is **not** a FIPS 140-2/3
validated module. While it implements FIPS-approved algorithms correctly, it has
not undergone CMVP validation.

**Path to Compliance:**

1. **Short-term:** Document current crypto usage and obtain a waiver/exception
   for non-FIPS-validated implementations that use FIPS-approved algorithms.

2. **Medium-term:** Replace `ring` with `aws-lc-rs` (Amazon's fork of BoringCrypto)
   which has FIPS 140-3 validation (certificate #4631). `rustls` supports
   `aws-lc-rs` as a backend via the `aws-lc-rs` feature flag.

3. **Long-term:** Consider running in FIPS mode where:
   - Only FIPS-approved cipher suites are available
   - MD5 checksum is disabled
   - ChaCha20-Poly1305 is excluded from TLS
   - X25519 key exchange is replaced with P-256/P-384 ECDHE
   - DRBG uses FIPS-validated implementation

### 3.3 Recommendations for FIPS Mode

```toml
# Cargo.toml change for FIPS crypto backend:
rustls = { version = "0.23", features = ["aws_lc_rs"] }
# Remove default ring dependency
```

Add a `--fips` CLI flag or `FIPS_MODE=1` env var that:
- Restricts TLS to FIPS-approved cipher suites only
- Disables MD5 checksum algorithm
- Uses FIPS-validated DRBG for nonce generation
- Logs FIPS mode status on startup

---

## 4. CMMC 2.0 Level 2 Assessment

CMMC 2.0 Level 2 maps to NIST SP 800-171 Rev 2, with 110 practices across 14 domains.
Below are the domains most relevant to AFT as a file transfer tool.

### AC — Access Control

| Practice     | Description                                                      | Status    | Notes                                   |
| ------------ | ---------------------------------------------------------------- | --------- | --------------------------------------- |
| AC.L2-3.1.1  | Limit access to authorized users                                 | ⚠️ Partial | Auth token supported but not mandatory  |
| AC.L2-3.1.2  | Limit access to authorized functions                             | ❌ Missing | No read-only/write-only mode            |
| AC.L2-3.1.3  | Control CUI flow                                                 | ❌ Missing | No DLP integration                      |
| AC.L2-3.1.7  | Prevent non-privileged users from executing privileged functions | ✅ N/A     | CLI tool, follows OS-level permissions  |
| AC.L2-3.1.12 | Monitor and control remote access                                | ⚠️ Partial | History logging exists but insufficient |

**Recommendations:**
- Make authentication mandatory for server mode in DoD deployments
- Implement RBAC (role-based access control) for server: read, write, admin
- Add `--require-auth` server flag
- Integrate with organization identity providers (LDAP/SAML/OIDC)

### AU — Audit and Accountability

| Practice    | Description                  | Status    | Notes                                  |
| ----------- | ---------------------------- | --------- | -------------------------------------- |
| AU.L2-3.3.1 | Create audit records         | ⚠️ Partial | history.json exists but minimal        |
| AU.L2-3.3.2 | Provide audit record content | ❌ Missing | No user ID, source IP, detailed events |
| AU.L2-3.3.3 | Review audit records         | ❌ Missing | No log analysis tooling                |
| AU.L2-3.3.4 | Alert on audit failure       | ❌ Missing | No alerting mechanism                  |
| AU.L2-3.3.5 | Correlate audit processes    | ❌ Missing | No correlation ID / trace ID           |

**Recommendations:**
- Implement structured audit logging (JSON format) with:
  - Timestamp (ISO 8601)
  - Event type (auth_success, auth_failure, file_read, file_write, config_change)
  - Source IP address
  - User identity (if authenticated)
  - Resource accessed (file path)
  - Outcome (success/failure)
  - Correlation/session ID
- Add `--audit-log <path>` server option
- Support syslog output for SIEM integration
- Implement log integrity protection (HMAC-signed log entries)

### IA — Identification and Authentication

| Practice     | Description                                               | Status    | Notes                                               |
| ------------ | --------------------------------------------------------- | --------- | --------------------------------------------------- |
| IA.L2-3.5.1  | Identify system users                                     | ⚠️ Partial | Token-based, no user identity                       |
| IA.L2-3.5.2  | Authenticate users                                        | ✅ Present | HMAC-SHA256 challenge/response                      |
| IA.L2-3.5.3  | Use multifactor auth                                      | ❌ Missing | Single-factor only                                  |
| IA.L2-3.5.7  | Enforce minimum password complexity                       | ❌ Missing | No token strength requirements                      |
| IA.L2-3.5.10 | Store/transmit only cryptographically-protected passwords | ⚠️ Partial | Challenge mode protects token; simple mode does not |

**Recommendations:**
- Enforce minimum auth token length (16+ characters)
- Deprecate simple token transmission in favor of challenge/response only
- Add support for PKI/certificate-based client authentication
- Implement session tokens with expiration

### SC — System and Communications Protection

| Practice      | Description                                    | Status    | Notes                                    |
| ------------- | ---------------------------------------------- | --------- | ---------------------------------------- |
| SC.L2-3.13.1  | Monitor communications at boundaries           | ✅ Present | Server logging                           |
| SC.L2-3.13.2  | Employ architectural designs to protect CUI    | ⚠️ Partial | TLS available but not enforced           |
| SC.L2-3.13.6  | Deny network traffic by default                | ❌ Missing | Server accepts all connections           |
| SC.L2-3.13.8  | Implement crypto mechanisms for CUI in transit | ⚠️ Partial | TLS available, FIPS crypto not validated |
| SC.L2-3.13.11 | Employ FIPS-validated cryptography             | ❌ Missing | ring is not FIPS-validated               |

**Recommendations:**
- Default to TLS-enabled connections for DoD deployment
- Implement IP allowlisting for server mode
- Switch to FIPS-validated crypto (aws-lc-rs backend)
- Add `--fips` mode flag

### MP — Media Protection

| Practice    | Description                  | Status    | Notes                                                |
| ----------- | ---------------------------- | --------- | ---------------------------------------------------- |
| MP.L2-3.8.1 | Protect media containing CUI | ⚠️ Partial | Temp files cleaned up, but crash may leave artifacts |
| MP.L2-3.8.2 | Limit access to CUI on media | ✅ Present | Uses OS file permissions                             |

**Recommendations:**
- Secure temp file creation with exclusive permissions (0600)
- Implement secure deletion (overwrite before unlink) for temp files
- Add crash handler to clean up temp files

---

## 5. Security Hardening Recommendations Summary

### Priority 1 — Critical (Required for DoD)

1. **Switch to FIPS-validated crypto**: Replace `ring` with `aws-lc-rs` backend
2. **Harden plugin system**: Add plugin signature verification or disable in production
3. **Enforce TLS for auth**: Require TLS when `--auth-token` is set
4. **Add audit logging**: Implement structured security event logging

### Priority 2 — High (Strongly Recommended)

5. **Auth rate limiting**: Implement per-IP failure rate limiting with lockout
6. **Deprecate simple token auth**: Require challenge/response only
7. **Add `--require-tls` server mode**: Reject unencrypted connections
8. **Connection limits**: Add `--max-connections` and IP ACLs

### Priority 3 — Medium (Recommended)

9. **Add `--fips` mode flag**: Restrict to FIPS-approved algorithms only
10. **Certificate pinning**: Support `--pin-cert` for known server certificates
11. **Session timeouts**: Implement idle connection timeout
12. **Scrub credentials from logs**: Strip sensitive data from history entries

### Priority 4 — Low (Nice to Have)

13. **RBAC for server**: Read-only, write-only, admin roles
14. **DLP hooks**: File content scanning before transfer
15. **SIEM integration**: Syslog output for security event monitoring
16. **Secure deletion**: Overwrite temp files before unlink

---

## 6. Current Security Strengths

1. **Rust memory safety**: Eliminates buffer overflows, use-after-free, and data races
2. **Bounds-checked binary parsing**: All frame parsers use checked helpers
3. **Path traversal protection**: Multi-layer defense (string check + canonicalize + prefix verify)
4. **Payload size limits**: Prevents memory exhaustion attacks
5. **Atomic file writes**: PUT uses temp-file-then-rename for integrity
6. **Streaming checksums**: SHA-256 verification during transfer, not after
7. **Modern TLS**: TLS 1.2/1.3 via rustls (no OpenSSL dependency, no legacy protocols)
8. **Challenge/response auth**: HMAC-SHA256 prevents token replay attacks
9. **No unsafe code in core logic**: Only in plugin FFI loading (inherently unsafe)
10. **Dependency minimalism**: Small dependency tree reduces supply chain risk

---

## Appendix A: Dependency Security Assessment

| Dependency | Version      | Risk   | Notes                                         |
| ---------- | ------------ | ------ | --------------------------------------------- |
| tokio      | 1.x          | Low    | Well-audited async runtime                    |
| reqwest    | 0.12         | Low    | Uses rustls (no OpenSSL)                      |
| rustls     | 0.23         | Low    | Memory-safe TLS, audited                      |
| ring       | (via rustls) | Medium | Not FIPS-validated                            |
| sha2       | 0.10         | Low    | Pure Rust, RustCrypto project                 |
| hmac       | 0.12         | Low    | Pure Rust, RustCrypto project                 |
| rand       | 0.8          | Low    | ChaCha20-based CSPRNG                         |
| zstd       | 0.13         | Low    | Wrapper around well-tested C library          |
| libloading | 0.8          | Medium | Dynamic library loading (inherently risky)    |
| quinn      | 0.11         | Low    | QUIC implementation using rustls              |
| suppaftp   | 6.x          | Medium | Less widely audited                           |
| russh      | 0.46         | Medium | SSH implementation, less audited than OpenSSH |
| rust-s3    | 0.35         | Low    | HTTP-based, uses reqwest                      |

---

## Appendix B: Threat Model Summary

```
                         ┌─────────────────────┐
                         │   AFTP Server        │
                         │   (Public-facing)     │
                         └───────┬──────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
   ┌────▼─────┐           ┌─────▼──────┐          ┌──────▼─────┐
   │ Auth      │           │ File       │          │ Network    │
   │ Attacks   │           │ Access     │          │ Attacks    │
   │           │           │            │          │            │
   │ • Brute   │           │ • Path     │          │ • MITM     │
   │   force   │           │   traversal│          │ • Replay   │
   │ • Token   │           │ • Symlink  │          │ • DoS      │
   │   replay  │           │   escape   │          │ • Sniffing │
   │ • Cred    │           │ • Dir      │          │ • Frame    │
   │   stuffing│           │   listing  │          │   injection│
   └───────────┘           └────────────┘          └────────────┘
```

**Risk Rating for DoD Deployment: MEDIUM**

With the recommended hardening measures (FIPS crypto, TLS enforcement, audit logging,
auth rate limiting), AFT can be suitable for DoD environments at the CUI
(Controlled Unclassified Information) level.
