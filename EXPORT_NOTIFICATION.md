# EAR §742.15(b) ENC Notification

> **To:** crypt-supp8@bis.doc.gov, enc@nsa.gov
>
> **Subject:** TSR / ENC Notification — AFT (Agentic File Transfer) v1.0.0, ECCN 5D002

Dear Sir/Madam,

Pursuant to §742.15(b) of the Export Administration Regulations (EAR), this email serves as notification of the public availability of encryption source code classified under **ECCN 5D002**.

## Product Information

| Field            | Value                                                               |
| ---------------- | ------------------------------------------------------------------- |
| **Product**      | AFT — Agentic File Transfer                                         |
| **Version**      | 1.0.0                                                               |
| **Release Date** | 2026-03-23                                                          |
| **Producer**     | Nervosys                                                            |
| **URL**          | https://github.com/nervosys/AgenticFileTransfer                     |
| **Tag**          | https://github.com/nervosys/AgenticFileTransfer/releases/tag/v1.0.0 |
| **License**      | AGPL-3.0-or-later (publicly available open source)                  |

## Cryptographic Functionality

| Algorithm             | Key Length      | Standard                   | Purpose                                              |
| --------------------- | --------------- | -------------------------- | ---------------------------------------------------- |
| AES-256-GCM           | 256-bit         | NIST FIPS 197 / SP 800-38D | Authenticated encryption for file protection and TLS |
| AES-128-GCM           | 128-bit         | NIST FIPS 197 / SP 800-38D | TLS cipher suite                                     |
| ML-KEM (Kyber1024)    | KEM             | NIST FIPS 203              | Post-quantum key encapsulation                       |
| HMAC-SHA256           | 256-bit         | NIST FIPS 198-1            | Challenge/response authentication                    |
| SHA-256, SHA-512      | Hash            | NIST FIPS 180-4            | Integrity verification / checksums                   |
| MD5                   | Hash            | RFC 1321                   | Legacy checksum verification                         |
| TLS 1.2+              | Varies          | RFC 5246 / 8446            | Transport encryption (via rustls library)            |
| QUIC                  | Varies          | RFC 9000 / 9001            | Transport encryption (via quinn library)             |
| Neural network cipher | Model-dependent | N/A (experimental)         | Trainable MLP autoencoder-based symmetric encryption |

## Implementation Notes

- Encryption is performed using published, well-known algorithms implemented by open-source Rust libraries (rustls, ring, aes-gcm, pqc_kyber, quinn).
- The neural network cipher is an experimental trainable autoencoder; it does not implement a novel cryptographic primitive but rather uses standard MLP weights as a symmetric key for a block cipher in OFB/CBC mode.
- An optional FIPS 140-3 build mode switches the TLS backend to aws-lc-rs (FIPS-validated).
- No custom hardware, no classified algorithms, no government-furnished cryptographic material.

## License Exception

This software is publicly available at the URL above and qualifies for License Exception ENC under §740.17(b)(1) as publicly available open-source encryption source code.

Respectfully,

\[Your Name\]
\[Title\]
Nervosys
\[Contact Email\]
\[Contact Phone\]
