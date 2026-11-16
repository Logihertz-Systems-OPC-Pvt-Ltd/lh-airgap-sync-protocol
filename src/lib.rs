//! # lh-airgap-sync-protocol
//!
//! Production-grade, zero-dependency Rust Unidirectional Optical/QR & UDP Data Diode
//! Synchronization Protocol, GF(2^8) Erasure FEC Engine, Monotonic Anti-Replay Verifier,
//! and 10-Rule Air-Gap Enclave Security Posture Auditor.

#![forbid(unsafe_code)]

pub mod auditor;
pub mod diode_protocol;
pub mod exporters;
pub mod fec_gf256;
pub mod json;
pub mod sha256_hmac;

// Re-exports for convenience
pub use auditor::{
    audit_airgap_policy, AirgapAuditFinding, AirgapAuditReport, AirgapPolicy, Severity,
};
pub use diode_protocol::{
    render_optical_frame_ascii, AirgapFrame, DiodeError, DiodeReceiverSession,
};
pub use fec_gf256::{FecCodec, Gf256};
pub use json::JsonValue;
pub use sha256_hmac::{
    constant_time_eq, crc32, hex_decode, hex_encode, hmac_sha256, sha256, sha256_ctr_crypt,
};
