# Security Policy for lh-airgap-sync-protocol

## Security Architecture & Threat Model

`lh-airgap-sync-protocol` (`lh-airgap-sync`) is engineered for mission-critical classified enclaves, nuclear command facilities, SCADA control perimeters, and air-gapped financial signing environments where bidirectional communication poses catastrophic exfiltration risks.

### Core Security Tenets

1. **Physical & Logical Unidirectionality**:
   - The protocol operates strictly in unidirectional mode ($TX \to RX$).
   - Return-channel handshakes (`ACK`, `NACK`, TCP SYN/ACK, optical backscatter) are strictly forbidden across the air-gap barrier.

2. **Per-Frame Cryptographic Authentication & Integrity**:
   - Every individual shard frame is authenticated via HMAC-SHA256 across all header fields, shard data, and payload root hash.
   - CRC-32 provides hardware-level pre-filtering against photodiode noise and optical scanning artifacts.
   - Constant-time slice comparison (`constant_time_eq`) protects HMAC validation against timing side-channels.

3. **Strict Monotonic Epoch Anti-Replay Guard**:
   - Receiver nodes maintain a strictly monotonic sequence ledger (`epoch_seq`).
   - Any replayed, stale, or rolled-back frames ($epoch\_seq \le last\_committed$) are rejected at the edge before reassembly.

4. **Forward Error Correction ($GF(2^8)$ Erasure Coding)**:
   - Eliminates transmission stalls without requiring receiver-to-sender retransmissions.
   - Cauchy generator matrix construction guarantees any $K$ surviving shards out of $N = K + M$ shards achieve $100\%$ bit-accurate payload reconstruction.

5. **Receiver Resource Guardrails**:
   - Strict limits on reassembly buffer sizes (`max_reassembly_buffer_mb`) prevent unbounded memory consumption and denial-of-service attacks.
   - Deterministic session timeouts discard orphaned shards from interrupted bursts.

---

## Reporting a Security Vulnerability

If you discover a vulnerability or security flaw in `lh-airgap-sync-protocol`, please report it via coordinated disclosure:

- **Security Team Email**: `security@logihertz.com`
- **PGP Encryption**: Encrypt reports using the Logihertz Systems Security PGP key.
- **Response Timeline**:
  - **Initial Acknowledgment**: Within 24 hours.
  - **Triage & Reproduction**: Within 72 hours.
  - **Remediation & Patch Release**: Within 14 calendar days.

We request that you do not publicly disclose the issue until an official security advisory and patch have been published.
