//! 10-Rule deterministic Air-Gap Data Diode Posture Auditor (LH-AIRGAP-001 through LH-AIRGAP-010).

#![forbid(unsafe_code)]

use crate::json::JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }

    pub fn sarif_level(&self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low => "note",
        }
    }
}

/// Air-Gap Data Diode Policy Configuration Manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct AirgapPolicy {
    pub policy_name: String,
    pub physical_unidirectional_diode: bool,
    pub allow_backchannel_ack_nack: bool,
    pub cryptographic_frame_auth: bool,
    pub verify_payload_sha256: bool,
    pub monotonic_epoch_anti_replay: bool,
    pub persist_replay_ledger: bool,
    pub encrypt_diode_payloads: bool,
    pub fec_erasure_coding_enabled: bool,
    pub fec_parity_ratio_percent: f64,
    pub cdr_schema_validation_enabled: bool,
    pub allow_executable_payloads: bool,
    pub max_reassembly_buffer_mb: u64,
    pub reassembly_timeout_sec: u64,
    pub max_frame_payload_bytes: u64,
    pub display_fps: f64,
    pub camera_fps: f64,
    pub optical_shroud_enforced: bool,
    pub tempest_acoustic_rf_isolation: bool,
    pub require_dual_custody_signoff: bool,
    pub audit_log_diode_transfers: bool,
}

impl AirgapPolicy {
    pub fn from_json(json: &JsonValue) -> Result<Self, String> {
        let policy_name = json
            .get_str("policy_name")
            .unwrap_or("Default Airgap Policy")
            .to_string();

        let physical_unidirectional_diode = json
            .get_bool("physical_unidirectional_diode")
            .unwrap_or(false);
        let allow_backchannel_ack_nack =
            json.get_bool("allow_backchannel_ack_nack").unwrap_or(true);
        let cryptographic_frame_auth = json.get_bool("cryptographic_frame_auth").unwrap_or(false);
        let verify_payload_sha256 = json.get_bool("verify_payload_sha256").unwrap_or(false);
        let monotonic_epoch_anti_replay = json
            .get_bool("monotonic_epoch_anti_replay")
            .unwrap_or(false);
        let persist_replay_ledger = json.get_bool("persist_replay_ledger").unwrap_or(false);
        let encrypt_diode_payloads = json.get_bool("encrypt_diode_payloads").unwrap_or(false);
        let fec_erasure_coding_enabled =
            json.get_bool("fec_erasure_coding_enabled").unwrap_or(false);
        let fec_parity_ratio_percent = json.get_f64("fec_parity_ratio_percent").unwrap_or(0.0);
        let cdr_schema_validation_enabled = json
            .get_bool("cdr_schema_validation_enabled")
            .unwrap_or(false);
        let allow_executable_payloads = json.get_bool("allow_executable_payloads").unwrap_or(true);
        let max_reassembly_buffer_mb =
            json.get_i64("max_reassembly_buffer_mb").unwrap_or(512) as u64;
        let reassembly_timeout_sec = json.get_i64("reassembly_timeout_sec").unwrap_or(600) as u64;
        let max_frame_payload_bytes =
            json.get_i64("max_frame_payload_bytes").unwrap_or(2048) as u64;
        let display_fps = json.get_f64("display_fps").unwrap_or(60.0);
        let camera_fps = json.get_f64("camera_fps").unwrap_or(30.0);
        let optical_shroud_enforced = json.get_bool("optical_shroud_enforced").unwrap_or(false);
        let tempest_acoustic_rf_isolation = json
            .get_bool("tempest_acoustic_rf_isolation")
            .unwrap_or(false);
        let require_dual_custody_signoff = json
            .get_bool("require_dual_custody_signoff")
            .unwrap_or(false);
        let audit_log_diode_transfers = json.get_bool("audit_log_diode_transfers").unwrap_or(false);

        Ok(Self {
            policy_name,
            physical_unidirectional_diode,
            allow_backchannel_ack_nack,
            cryptographic_frame_auth,
            verify_payload_sha256,
            monotonic_epoch_anti_replay,
            persist_replay_ledger,
            encrypt_diode_payloads,
            fec_erasure_coding_enabled,
            fec_parity_ratio_percent,
            cdr_schema_validation_enabled,
            allow_executable_payloads,
            max_reassembly_buffer_mb,
            reassembly_timeout_sec,
            max_frame_payload_bytes,
            display_fps,
            camera_fps,
            optical_shroud_enforced,
            tempest_acoustic_rf_isolation,
            require_dual_custody_signoff,
            audit_log_diode_transfers,
        })
    }
}

/// An audit finding resulting from evaluating one of the 10 rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirgapAuditFinding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub cwe_id: &'static str,
    pub severity: Severity,
    pub deduction: u32,
    pub passed: bool,
    pub details: String,
    pub recommendation: &'static str,
}

/// Summary report of the security posture audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirgapAuditReport {
    pub policy_name: String,
    pub total_rules: usize,
    pub passed_rules: usize,
    pub failed_rules: usize,
    pub total_deductions: u32,
    pub posture_score: u32,
    pub findings: Vec<AirgapAuditFinding>,
}

/// Audits an `AirgapPolicy` against all 10 normative security rules.
pub fn audit_airgap_policy(policy: &AirgapPolicy) -> AirgapAuditReport {
    let mut findings = Vec::with_capacity(10);

    // Rule 1: LH-AIRGAP-001 (CRITICAL, 25, CWE-284)
    {
        let passed = policy.physical_unidirectional_diode && !policy.allow_backchannel_ack_nack;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-001",
            rule_name: "Strict Physical & Logical Diode Unidirectionality",
            cwe_id: "CWE-284",
            severity: Severity::Critical,
            deduction: 25,
            passed,
            details: if passed {
                "Physically unidirectional optical/fiber data diode enforced; backchannel ACK/NACK disabled.".to_string()
            } else {
                "Bidirectional return channel (ACK/NACK/TCP) physically or logically permitted across enclave boundary.".to_string()
            },
            recommendation: "Enforce physical unidirectional diode (TX->RX only) and disable backchannel transport handshakes.",
        });
    }

    // Rule 2: LH-AIRGAP-002 (CRITICAL, 25, CWE-345)
    {
        let passed = policy.cryptographic_frame_auth && policy.verify_payload_sha256;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-002",
            rule_name: "Cryptographic Per-Frame Authentication & Root Check",
            cwe_id: "CWE-345",
            severity: Severity::Critical,
            deduction: 25,
            passed,
            details: if passed {
                "Per-frame HMAC-SHA256 authentication active; full-payload SHA-256 root verification enforced.".to_string()
            } else {
                "Cryptographic per-frame authentication or full-payload Merkle/SHA-256 root check disabled.".to_string()
            },
            recommendation: "Mandate HMAC-SHA256 frame integrity and verify payload root SHA-256 before ingestion.",
        });
    }

    // Rule 3: LH-AIRGAP-003 (CRITICAL, 25, CWE-294)
    {
        let passed = policy.monotonic_epoch_anti_replay && policy.persist_replay_ledger;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-003",
            rule_name: "Monotonic Epoch Anti-Replay Ledger",
            cwe_id: "CWE-294",
            severity: Severity::Critical,
            deduction: 25,
            passed,
            details: if passed {
                "Strictly monotonic epoch sequence verification and persistent commit ledger active.".to_string()
            } else {
                "Monotonic epoch sequence anti-replay verification or persistent replay ledger disabled on receiver.".to_string()
            },
            recommendation: "Enable strictly monotonic epoch sequence validation and persist committed sequence ledgers.",
        });
    }

    // Rule 4: LH-AIRGAP-004 (HIGH, 10, CWE-311)
    {
        let passed = policy.encrypt_diode_payloads;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-004",
            rule_name: "Payload Confidentiality Encryption Across Diode",
            cwe_id: "CWE-311",
            severity: Severity::High,
            deduction: 10,
            passed,
            details: if passed {
                "Payloads encrypted at source before crossing the optical/QR or fiber data diode barrier.".to_string()
            } else {
                "Cleartext payload transmission across optical/QR or fiber diode link without payload encryption.".to_string()
            },
            recommendation: "Encrypt all diode payloads with SHA256-CTR/AES-256 before transmission across the optical channel.",
        });
    }

    // Rule 5: LH-AIRGAP-005 (HIGH, 10, CWE-754)
    {
        let passed = policy.fec_erasure_coding_enabled && policy.fec_parity_ratio_percent >= 20.0;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-005",
            rule_name: "GF(2^8) FEC Erasure Coding & Parity Margin",
            cwe_id: "CWE-754",
            severity: Severity::High,
            deduction: 10,
            passed,
            details: if passed {
                format!(
                    "Cauchy GF(2^8) erasure coding enabled with {:.1}% parity overhead (>= 20.0%).",
                    policy.fec_parity_ratio_percent
                )
            } else {
                format!(
                    "FEC erasure coding disabled or parity ratio ({:.1}%) below statutory 20.0% threshold.",
                    policy.fec_parity_ratio_percent
                )
            },
            recommendation: "Enable Cauchy GF(2^8) erasure coding with at least 20% parity shard overhead for packet loss tolerance.",
        });
    }

    // Rule 6: LH-AIRGAP-006 (HIGH, 10, CWE-502)
    {
        let passed = policy.cdr_schema_validation_enabled && !policy.allow_executable_payloads;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-006",
            rule_name: "Content Disarm & Reconstruction (CDR) & Executable Blocking",
            cwe_id: "CWE-502",
            severity: Severity::High,
            deduction: 10,
            passed,
            details: if passed {
                "CDR schema validation active and executable binary payloads strictly blocked.".to_string()
            } else {
                "CDR schema validation disabled or executable binary payloads permitted into enclave.".to_string()
            },
            recommendation: "Enforce CDR sanitization, schema validation, and block executable binaries from entering the high-side enclave.",
        });
    }

    // Rule 7: LH-AIRGAP-007 (HIGH, 10, CWE-400)
    {
        let passed = policy.max_reassembly_buffer_mb <= 256 && policy.reassembly_timeout_sec <= 300;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-007",
            rule_name: "Bounded Reassembly Memory Pool & Stale Eviction",
            cwe_id: "CWE-400",
            severity: Severity::High,
            deduction: 10,
            passed,
            details: if passed {
                format!(
                    "Reassembly memory buffer bounded to {} MB (<= 256 MB) with {}s timeout (<= 300s).",
                    policy.max_reassembly_buffer_mb, policy.reassembly_timeout_sec
                )
            } else {
                format!(
                    "Unbounded reassembly memory ({} MB > 256 MB) or stale eviction timeout ({}s > 300s).",
                    policy.max_reassembly_buffer_mb, policy.reassembly_timeout_sec
                )
            },
            recommendation: "Clamp receiver reassembly memory pool <= 256 MB and enforce <= 300s session eviction timeout.",
        });
    }

    // Rule 8: LH-AIRGAP-008 (MEDIUM, 4, CWE-682)
    {
        let nyquist_pass = policy.display_fps <= 0.5 * policy.camera_fps;
        let payload_pass = policy.max_frame_payload_bytes <= 1024;
        let passed = payload_pass && nyquist_pass;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-008",
            rule_name: "Optical Symbol Density & Nyquist Sampling Limits",
            cwe_id: "CWE-682",
            severity: Severity::Medium,
            deduction: 4,
            passed,
            details: if passed {
                format!(
                    "Optical payload ({} bytes <= 1024) and display FPS ({:.1} <= 0.5 * {:.1} camera FPS) meet Nyquist sampling limits.",
                    policy.max_frame_payload_bytes, policy.display_fps, policy.camera_fps
                )
            } else {
                format!(
                    "Optical payload ({} bytes) or display FPS ({:.1} vs {:.1} camera FPS) violates optical Nyquist limits.",
                    policy.max_frame_payload_bytes, policy.display_fps, policy.camera_fps
                )
            },
            recommendation: "Limit optical frame payload to <= 1024 bytes and clamp display frame rate below 0.5 * camera FPS.",
        });
    }

    // Rule 9: LH-AIRGAP-009 (MEDIUM, 4, CWE-1300)
    {
        let passed = policy.optical_shroud_enforced && policy.tempest_acoustic_rf_isolation;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-009",
            rule_name: "Physical Line-of-Sight Shroud & TEMPEST Shielding",
            cwe_id: "CWE-1300",
            severity: Severity::Medium,
            deduction: 4,
            passed,
            details: if passed {
                "Optical line-of-sight privacy shroud and TEMPEST acoustic/RF shielding deployed.".to_string()
            } else {
                "Missing optical line-of-sight privacy shroud or acoustic/RF TEMPEST isolation around air-gap kiosk.".to_string()
            },
            recommendation: "Install light-tight optical privacy hoods and TEMPEST RF/acoustic shielding on transfer terminals.",
        });
    }

    // Rule 10: LH-AIRGAP-010 (LOW, 1, CWE-778)
    {
        let passed = policy.require_dual_custody_signoff && policy.audit_log_diode_transfers;
        findings.push(AirgapAuditFinding {
            rule_id: "LH-AIRGAP-010",
            rule_name: "Dual-Custody M-of-N Operator Sign-Off & Audit Logging",
            cwe_id: "CWE-778",
            severity: Severity::Low,
            deduction: 1,
            passed,
            details: if passed {
                "Dual-custody operator authorization required; tamper-evident transfer logging active.".to_string()
            } else {
                "Missing dual-custody M-of-N operator sign-off or missing tamper-evident diode transfer audit logging.".to_string()
            },
            recommendation: "Enforce dual-operator authorization keys and write append-only tamper-evident audit logs.",
        });
    }

    let total_rules = findings.len();
    let passed_rules = findings.iter().filter(|f| f.passed).count();
    let failed_rules = total_rules - passed_rules;
    let total_deductions: u32 = findings
        .iter()
        .filter(|f| !f.passed)
        .map(|f| f.deduction)
        .sum();
    let posture_score = 100u32.saturating_sub(total_deductions);

    AirgapAuditReport {
        policy_name: policy.policy_name.clone(),
        total_rules,
        passed_rules,
        failed_rules,
        total_deductions,
        posture_score,
        findings,
    }
}
