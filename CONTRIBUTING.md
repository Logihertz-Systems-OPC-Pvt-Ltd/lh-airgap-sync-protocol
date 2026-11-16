# Contributing to lh-airgap-sync-protocol

Thank you for your interest in contributing to **`lh-airgap-sync-protocol`**, the open-source unidirectional data diode synchronization engine maintained by Logihertz Systems (OPC) Private Limited.

---

## Strict Engineering Standards

1. **Zero External Crate Dependencies**:
   - `[dependencies]` in `Cargo.toml` must remain **completely empty**.
   - All cryptographic primitives (SHA-256, HMAC-SHA256, SHA256-CTR), Galois Field math, erasure coding, optical matrix rendering, JSON lexing/parsing, and SARIF exporting must be implemented exclusively using the Rust Standard Library (`std`).

2. **Forbid Unsafe Code**:
   - Every file must enforce `#![forbid(unsafe_code)]`.
   - Any pull request containing `unsafe` blocks will be automatically rejected.

3. **Deterministic Arithmetic in $GF(2^8)$**:
   - Galois Field arithmetic must use the primitive irreducible polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
   - Cauchy generator matrices must guarantee invertibility for all square submatrices.

4. **Code Formatting & Linting**:
   - Code must pass `cargo fmt --check` without any formatting discrepancies.
   - Code must compile with zero warnings under `cargo clippy --all-targets -- -D warnings`.

5. **Commit Message Conventions**:
   - Use Conventional Commits formatting:
     - `feat(diode): add animated optical finder patterns`
     - `fix(fec): resolve Cauchy matrix pivot zero in Gaussian elimination`
     - `test(auditor): add test cases for LH-AIRGAP-001 through 010`

---

## Local Development Workflow

```bash
# Check code formatting
cargo fmt --check

# Run Clippy lints
cargo clippy --all-targets -- -D warnings

# Run all unit and integration tests
cargo test

# Build release binary
cargo build --release
```
