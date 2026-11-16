# lh-airgap-sync-protocol

[![CI Pipeline](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-airgap-sync-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-airgap-sync-protocol/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-airgap-sync-protocol/releases/tag/v0.1.0)
[![Standard](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Rust%20std)-brightgreen.svg)](#zero-dependencies)
[![Unsafe Code](https://img.shields.io/badge/unsafe-forbid-success.svg)](#security-guarantees)

**`lh-airgap-sync-protocol`** is a production-grade, zero-dependency **Rust 2021 Edition Unidirectional Optical/QR & UDP Data Diode Synchronization Protocol, Galois Field $GF(2^8)$ Erasure Forward Error Correction (FEC) Engine, Monotonic Anti-Replay Verifier, and 10-Rule Air-Gap Enclave Security Posture Auditor**.

Engineered for mission-critical classified government enclaves, nuclear reactor command networks, defense SCADA perimeters, and air-gapped cryptographic signing HSMs where bidirectional return channels pose catastrophic data exfiltration hazards.

---

## Technical Highlights

1. **Physical & Logical Unidirectionality ($TX \to RX$)**:
   - Designed strictly for one-way physical media: optical fibers with disconnected return strands, display-to-camera QR/optical feeds, laser links, and unidirectional UDP data diodes.
   - Operates with zero backchannel feedback (`ACK`, `NACK`, TCP handshakes, or reverse carrier signals are physically and logically impossible).

2. **Clean-Room Cryptographic Core (Zero External Dependencies)**:
   - FIPS 180-4 SHA-256 cryptographic hash function.
   - RFC 2104 HMAC-SHA256 message authentication per frame.
   - SHA256-CTR keystream encryption and decryption for payload confidentiality across untrusted optical corridors.
   - IEEE 802.3 CRC-32 (`0xEDB88320`) hardware-level pre-filter for optical bit-error rejection.
   - Constant-time slice comparison (`constant_time_eq`) to eliminate timing side-channel leakage.

3. **Galois Field $GF(2^8)$ Systematic Cauchy Erasure Coding**:
   - Constructed over the irreducible primitive polynomial:
     $$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\text{0x11D})$$
   - Generates $M$ redundant parity shards from $K$ systematic data shards using an $M \times K$ Cauchy generator matrix:
     $$G_{m, k} = \frac{1}{x_m \oplus y_k} \quad \text{over } GF(2^8)$$
   - Cauchy construction guarantees that every square submatrix is invertible!
   - Recovers the original payload with **100% bit-accuracy** from **any $K$ surviving shards** out of $N = K + M$ shards using Gauss-Jordan elimination, seamlessly tolerating up to $M$ dropped frames caused by camera occlusion, photodiode jitter, or fiber attenuation.

4. **Self-Verifying `LHAIRGAP` Frame Wire Protocol**:
   - Fixed 71-byte authenticated header featuring magic bytes, session identifier, monotonic sequence counter (`epoch_seq`), shard coordinates ($K, M$), original length, payload root SHA-256, payload shard bytes, CRC-32 checksum, and HMAC-SHA256 authentication tag.
   - Built-in strictly monotonic anti-replay state machine (`DiodeReceiverSession`).

5. **2D Optical Finder-Pattern Matrix Renderer**:
   - Converts framed binary bursts into a 2D optical matrix with $7 \times 7$ corner finder patterns and alternating timing tracks, optimized for display-to-camera air-gap transfer kiosks.

6. **10-Rule Air-Gap Enclave Security Posture Auditor**:
   - Audits air-gap gateway and diode policy manifests against 10 strict security rules.
   - Computes weighted deduction-based posture scores:
     $$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$
   - Exports reports to ANSI colored terminal tables, canonical JSON, and OASIS SARIF v2.1.0 for automated CI/CD compliance validation.

---

## 10-Rule Security Posture Evaluation Matrix

| Rule ID | Severity | Deduction | CWE ID | Rule Name | Description |
|:---|:---:|:---:|:---:|:---|:---|
| **LH-AIRGAP-001** | CRITICAL | -25 | CWE-284 | Strict Physical & Logical Diode Unidirectionality | Bidirectional return channel (ACK/NACK/TCP) physically or logically permitted across enclave boundary. |
| **LH-AIRGAP-002** | CRITICAL | -25 | CWE-345 | Cryptographic Per-Frame Authentication & Root Check | Per-frame cryptographic authentication (HMAC-SHA256) or full-payload root hash verification disabled. |
| **LH-AIRGAP-003** | CRITICAL | -25 | CWE-294 | Monotonic Epoch Anti-Replay Ledger | Monotonic epoch sequence anti-replay verification or persistent replay ledger disabled on receiver. |
| **LH-AIRGAP-004** | HIGH | -10 | CWE-311 | Payload Confidentiality Encryption Across Diode | Cleartext payload transmission across optical/QR or fiber diode link without payload encryption. |
| **LH-AIRGAP-005** | HIGH | -10 | CWE-754 | GF(2^8) FEC Erasure Coding & Parity Margin | Forward Error Correction (FEC) erasure coding disabled or parity ratio below 20.0% statutory threshold. |
| **LH-AIRGAP-006** | HIGH | -10 | CWE-502 | Content Disarm & Reconstruction (CDR) & Executable Blocking | Content Disarm and Reconstruction (CDR), strict schema validation, or executable binary blocking disabled. |
| **LH-AIRGAP-007** | HIGH | -10 | CWE-400 | Bounded Reassembly Memory Pool & Stale Eviction | Unbounded receiver reassembly memory pool (>256 MB) or missing stale-session eviction timeout (>300s). |
| **LH-AIRGAP-008** | MEDIUM | -4 | CWE-682 | Optical Symbol Density & Nyquist Sampling Limits | Optical/QR payload exceeds camera symbol density ceiling (>1024 bytes) or display FPS violates Nyquist sampling rate. |
| **LH-AIRGAP-009** | MEDIUM | -4 | CWE-1300 | Physical Line-of-Sight Shroud & TEMPEST Shielding | Missing optical line-of-sight privacy shroud or acoustic/RF TEMPEST isolation around air-gap kiosk. |
| **LH-AIRGAP-010** | LOW | -1 | CWE-778 | Dual-Custody M-of-N Operator Sign-Off & Audit Logging | Missing dual-custody M-of-N operator sign-off or missing tamper-evident diode transfer audit logging. |

---

## Repository & Module Layout

```
lh-airgap-sync-protocol/
├── Cargo.toml                        # Edition 2021, Apache-2.0, zero external dependencies
├── src/
│   ├── lib.rs                        # #![forbid(unsafe_code)] library root exporting all core modules
│   ├── sha256_hmac.rs                # FIPS 180-4 SHA-256, HMAC-SHA256, SHA256-CTR, CRC-32 & constant-time eq
│   ├── fec_gf256.rs                  # GF(2^8) (0x11D) arithmetic, systematic (K, M) Cauchy FEC & Gauss-Jordan recovery
│   ├── diode_protocol.rs             # Unidirectional LHAIRGAP frame packetizer, CRC-32, anti-replay & optical matrix
│   ├── json.rs                       # Clean-room recursive JSON lexer, parser, and canonical serializer
│   ├── auditor.rs                    # 10-Rule deterministic air-gap data diode posture auditor
│   ├── exporters.rs                  # ANSI Terminal Table, Canonical JSON, and OASIS SARIF v2.1.0 exporters
│   └── main.rs                       # CLI entrypoint (scan, encode-burst, decode-burst, render-optical)
├── fixtures/
│   ├── hardened_airgap_policy.json   # Passes all 10 rules (Score: 100/100, Exit: 0)
│   ├── vulnerable_airgap_policy.json # Triggers all 10 rules (Score: 0/100, Exit: 1)
│   └── sample_sync_bundle.json       # Deterministic air-gap synchronization bundle fixture
├── tests/
│   └── integration_tests.rs          # 66 comprehensive integration & unit test functions (100+ assertions)
├── .github/workflows/
│   └── ci.yml                        # GitHub Actions automated workflow (fmt, clippy, test, CLI smoke)
├── CHANGELOG.md                      # Keep a Changelog 1.1.0 release notes
├── CODE_OF_CONDUCT.md                # Contributor Covenant v2.1 standard
├── CONTRIBUTING.md                   # Developer guidelines and coding standards
├── LICENSE                           # Apache License 2.0
├── NOTICE                            # Attribution & copyright notice
├── README.md                         # Technical documentation
└── SECURITY.md                       # Security & threat model policy
```

---

## Build & Test Instructions

### Prerequisites
- Rust stable toolchain ($\ge 1.75.0$, Edition 2021).
- Cargo package manager.
- Zero external libraries or C toolchains required.

### Compilation
```bash
# Compile library and binary in release mode
cargo build --release

# Run comprehensive test suite (66 tests)
cargo test

# Run strict linter checks
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

---

## Command-Line Usage

The compiled binary is available at `./target/release/lh-airgap-sync`.

### 1. Air-Gap Diode Security Posture Audit (`scan`)
Audit an enclave policy JSON file against all 10 sovereign rules:
```bash
# Human-readable ANSI colored table (Exit 0 on score >= 80, Exit 1 on failure)
./target/release/lh-airgap-sync scan fixtures/hardened_airgap_policy.json

# Machine-readable Canonical JSON
./target/release/lh-airgap-sync scan fixtures/hardened_airgap_policy.json --format json

# OASIS SARIF v2.1.0 for automated CI/CD DevSecOps gates
./target/release/lh-airgap-sync scan fixtures/vulnerable_airgap_policy.json --format sarif --output sarif-report.sarif
```

### 2. Encode & Frame Synchronization Burst (`encode-burst`)
Encrypt a payload, compute $M$ Cauchy parity shards over $K$ data shards, and generate authenticated `LHAIRGAP` frames:
```bash
./target/release/lh-airgap-sync encode-burst fixtures/sample_sync_bundle.json \
  --data-shards 4 \
  --parity-shards 2 \
  --output burst_frames.json
```

### 3. Decode & Lossy Diode Recovery Simulation (`decode-burst`)
Simulate transmission across a lossy unidirectional data diode where up to $M$ shards are erased:
```bash
# Simulates dropping shard 0 and shard 2 (surviving 4 shards >= K=4) -> 100% bit-accurate recovery
./target/release/lh-airgap-sync decode-burst fixtures/sample_sync_bundle.json --drop-shards 0,2

# Simulates dropping 3 shards > M=2 -> unrecoverable loss detected (Exit 1)
./target/release/lh-airgap-sync decode-burst fixtures/sample_sync_bundle.json --drop-shards 0,1,2
```

### 4. 2D Optical Matrix Rendering (`render-optical`)
Render framed bytes into a 2D optical finder-pattern ASCII matrix for display-to-camera kiosks:
```bash
./target/release/lh-airgap-sync render-optical --data "SOVEREIGN ENCLAVE TELEMETRY BURST"
```

---

## Zero Dependencies Guarantee

`lh-airgap-sync-protocol` contains **zero external crate dependencies**:
- `[dependencies]` in `Cargo.toml` is **completely empty**.
- All cryptographic primitives, Galois Field arithmetic, matrix inversion, and JSON parsing are implemented from scratch using the Rust Standard Library (`std`).
- Strictly enforces `#![forbid(unsafe_code)]` across all source files.

---

## Author & Attribution

- **Author**: Sameer Tawade
- **Organization**: Logihertz Systems (OPC) Private Limited
- **Contact**: `ops@logihertz.com` / `security@logihertz.com`

---

## License

Copyright (c) 2026 Logihertz Systems (OPC) Private Limited.  
Licensed under the **Apache License, Version 2.0**.
