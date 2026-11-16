# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-16

### Added
- Clean-room `#![forbid(unsafe_code)]` implementation of FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 without third-party crates.
- SHA-256-CTR stream encryption and decryption for sensitive air-gap payloads.
- IEEE 802.3 CRC-32 checksum implementation for optical signal pre-filtering.
- Constant-time memory comparison (`constant_time_eq`) for cryptographic side-channel resistance.
- Galois Field $GF(2^8)$ arithmetic engine based on primitive polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
- Systematic $(K, M)$ Cauchy matrix Forward Error Correction (FEC) erasure coding with Gauss-Jordan elimination recovery.
- Unidirectional `LHAIRGAP` self-verifying frame protocol with monotonic sequence counter (`epoch_seq`).
- 2D Optical/QR matrix renderer (`render_optical_frame_ascii`) featuring corner finder and timing patterns.
- Zero-dependency recursive JSON parser and serializer.
- 10-Rule deterministic Air-Gap Data Diode Posture Auditor (`LH-AIRGAP-001` through `LH-AIRGAP-010`).
- Multi-format report exporters: ANSI colored terminal table, Canonical JSON, and OASIS SARIF v2.1.0.
- Unified CLI tool `lh-airgap-sync` supporting `scan`, `encode-burst`, `decode-burst`, `render-optical`, `--version`, and `--help`.
- Comprehensive integration test suite with 65+ tests and 95+ assertions.
