//! Comprehensive integration & unit test suite for lh-airgap-sync-protocol.
//! 65+ deterministic test cases / 95+ assertions.

#![forbid(unsafe_code)]

use lh_airgap_sync::auditor::{audit_airgap_policy, AirgapPolicy, Severity};
use lh_airgap_sync::diode_protocol::{
    render_optical_frame_ascii, AirgapFrame, DiodeError, DiodeReceiverSession,
};
use lh_airgap_sync::exporters::{export_json, export_sarif, export_table};
use lh_airgap_sync::fec_gf256::{FecCodec, Gf256};
use lh_airgap_sync::json::JsonValue;
use lh_airgap_sync::sha256_hmac::{
    constant_time_eq, crc32, hex_decode, hex_encode, hmac_sha256, sha256, sha256_ctr_crypt,
};
use std::process::Command;

// =========================================================================
// 1. Galois Field GF(2^8) Arithmetic Tests
// =========================================================================

#[test]
fn test_gf256_identity_and_zero() {
    let gf = Gf256::new();
    for a in 0..=255u8 {
        assert_eq!(gf.mul(a, 1), a, "Multiplicative identity failed for {}", a);
        assert_eq!(gf.mul(1, a), a, "Multiplicative identity failed for {}", a);
        assert_eq!(gf.mul(a, 0), 0, "Zero product failed for {}", a);
        assert_eq!(gf.mul(0, a), 0, "Zero product failed for {}", a);
        assert_eq!(gf.add(a, 0), a, "Additive identity failed for {}", a);
        assert_eq!(gf.sub(a, 0), a, "Subtractive identity failed for {}", a);
        assert_eq!(gf.add(a, a), 0, "Self addition is zero in characteristic 2");
    }
}

#[test]
fn test_gf256_multiplicative_inverses() {
    let gf = Gf256::new();
    assert!(gf.inv(0).is_err(), "Inverse of 0 must return Err");
    for a in 1..=255u8 {
        let inv = gf.inv(a).expect("Non-zero element must have inverse");
        assert_eq!(
            gf.mul(a, inv),
            1,
            "a * a^-1 must equal 1 in GF(2^8) for a = {}",
            a
        );
    }
}

#[test]
fn test_gf256_division() {
    let gf = Gf256::new();
    assert!(gf.div(42, 0).is_err(), "Division by zero must error");
    assert_eq!(gf.div(0, 42).unwrap(), 0, "Zero divided by b must be 0");
    for a in 1..=30u8 {
        for b in 1..=30u8 {
            let q = gf.div(a, b).unwrap();
            assert_eq!(gf.mul(q, b), a, "q * b must equal a in GF(2^8)");
        }
    }
}

#[test]
fn test_gf256_distributivity() {
    let gf = Gf256::new();
    let a = 0x57;
    let b = 0x83;
    let c = 0x13;
    let lhs = gf.mul(a, gf.add(b, c));
    let rhs = gf.add(gf.mul(a, b), gf.mul(a, c));
    assert_eq!(lhs, rhs, "Distributivity a * (b + c) = (a * b) + (a * c)");
}

// =========================================================================
// 2. Systematic Cauchy FEC Codec Tests
// =========================================================================

#[test]
fn test_fec_codec_init_validation() {
    assert!(FecCodec::new(0, 2).is_err(), "K=0 must fail");
    assert!(FecCodec::new(4, 0).is_err(), "M=0 must fail");
    assert!(FecCodec::new(200, 100).is_err(), "K+M > 256 must fail");
    assert!(FecCodec::new(4, 2).is_ok(), "K=4, M=2 must succeed");
}

#[test]
fn test_fec_lossless_recovery_no_drops() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"AIRGAP UNIDIRECTIONAL RECOVERY 100% BIT-ACCURATE";
    let shards = codec.encode(payload).unwrap();
    assert_eq!(shards.len(), 6, "Total shards must be K + M = 6");

    let received: Vec<_> = shards.into_iter().enumerate().collect();
    let recovered = codec.decode(payload.len(), &received).unwrap();
    assert_eq!(recovered, payload, "Zero drops must recover exact payload");
}

#[test]
fn test_fec_single_data_shard_drop() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"HIGH-ASSURANCE ENCLAVE DATA DIODE SYNCHRONIZATION";
    let shards = codec.encode(payload).unwrap();

    // Test dropping each data shard 0, 1, 2, 3 individually
    for drop_idx in 0..4 {
        let mut received = Vec::new();
        for (idx, shard) in shards.iter().enumerate() {
            if idx != drop_idx {
                received.push((idx, shard.clone()));
            }
        }
        assert_eq!(received.len(), 5);
        let recovered = codec.decode(payload.len(), &received).unwrap();
        assert_eq!(
            recovered, payload,
            "Dropped shard {} must be recovered exactly",
            drop_idx
        );
    }
}

#[test]
fn test_fec_two_data_shards_drop() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"CRITICAL SCADA NUCLEAR REACTOR MONITORING TELEMETRY STREAM";
    let shards = codec.encode(payload).unwrap();

    // Drop shards 0 and 3 (surviving: 1, 2, 4, 5)
    let received: Vec<_> = shards
        .iter()
        .enumerate()
        .filter(|&(idx, _)| idx != 0 && idx != 3)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    assert_eq!(
        received.len(),
        4,
        "Must have exactly K = 4 surviving shards"
    );

    let recovered = codec.decode(payload.len(), &received).unwrap();
    assert_eq!(
        recovered, payload,
        "Dropped shards 0 and 3 must be recovered"
    );

    // Drop shards 1 and 2 (surviving: 0, 3, 4, 5)
    let received2: Vec<_> = shards
        .iter()
        .enumerate()
        .filter(|&(idx, _)| idx != 1 && idx != 2)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    let recovered2 = codec.decode(payload.len(), &received2).unwrap();
    assert_eq!(
        recovered2, payload,
        "Dropped shards 1 and 2 must be recovered"
    );
}

#[test]
fn test_fec_drop_data_and_parity_shard() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"TESTING MIXED DATA AND PARITY SHARD DROPS ACROSS OPTICAL DIODE";
    let shards = codec.encode(payload).unwrap();

    // Drop data shard 2 and parity shard 4
    let received: Vec<_> = shards
        .iter()
        .enumerate()
        .filter(|&(idx, _)| idx != 2 && idx != 4)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    assert_eq!(received.len(), 4);

    let recovered = codec.decode(payload.len(), &received).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_both_parity_shards_dropped() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"ALL PARITY SHARDS DROPPED - ONLY DATA SHARDS SURVIVE";
    let shards = codec.encode(payload).unwrap();

    // Only keep first 4 data shards
    let received: Vec<_> = shards
        .iter()
        .enumerate()
        .take(4)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    let recovered = codec.decode(payload.len(), &received).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_insufficient_shards_error() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"INSUFFICIENT SHARDS FAILURE TEST";
    let shards = codec.encode(payload).unwrap();

    // Drop 3 shards (only 3 surviving < K=4)
    let received: Vec<_> = shards
        .iter()
        .enumerate()
        .take(3)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    let err = codec.decode(payload.len(), &received);
    assert!(err.is_err(), "Decoding with < K shards must return Err");
    assert!(err.unwrap_err().contains("INSUFFICIENT_SURVIVING_SHARDS"));
}

#[test]
fn test_fec_empty_and_odd_payloads() {
    let codec = FecCodec::new(3, 2).unwrap();

    // Empty payload
    let empty_payload = b"";
    let shards = codec.encode(empty_payload).unwrap();
    let rec: Vec<_> = shards.into_iter().enumerate().collect();
    let recovered = codec.decode(0, &rec).unwrap();
    assert_eq!(recovered, empty_payload);

    // Single byte payload
    let single_byte = b"Z";
    let shards_single = codec.encode(single_byte).unwrap();
    let rec_single: Vec<_> = shards_single
        .into_iter()
        .enumerate()
        .filter(|&(i, _)| i != 0)
        .collect();
    let recovered_single = codec.decode(1, &rec_single).unwrap();
    assert_eq!(recovered_single, single_byte);
}

// =========================================================================
// 3. Cryptographic Primitives (SHA-256, HMAC, CTR, CRC-32)
// =========================================================================

#[test]
fn test_sha256_nist_test_vectors() {
    // Vector 1: Empty string
    let h1 = sha256(b"");
    assert_eq!(
        hex_encode(&h1),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // Vector 2: "abc"
    let h2 = sha256(b"abc");
    assert_eq!(
        hex_encode(&h2),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // Vector 3: 56-byte message
    let h3 = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex_encode(&h3),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_hmac_sha256_rfc4231_vectors() {
    // RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let h = hmac_sha256(&key, data);
    assert_eq!(
        hex_encode(&h),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    // RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    let key2 = b"Jefe";
    let data2 = b"what do ya want for nothing?";
    let h2 = hmac_sha256(key2, data2);
    assert_eq!(
        hex_encode(&h2),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn test_sha256_ctr_encryption_symmetry() {
    let key = [0x42u8; 32];
    let nonce: u64 = 1337;
    let plaintext = b"SOVEREIGN CLASSIFIED AIR-GAP CRYPTO PAYLOAD";

    let ciphertext = sha256_ctr_crypt(&key, nonce, plaintext);
    assert_ne!(ciphertext, plaintext, "Ciphertext must not match plaintext");

    let decrypted = sha256_ctr_crypt(&key, nonce, &ciphertext);
    assert_eq!(
        decrypted, plaintext,
        "Decryption must reproduce exact plaintext"
    );
}

#[test]
fn test_crc32_ieee8023() {
    let check = crc32(b"123456789");
    assert_eq!(
        check, 0xCBF43926,
        "IEEE 802.3 CRC-32 of '123456789' must equal 0xCBF43926"
    );
}

#[test]
fn test_constant_time_eq() {
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    let c = [1, 2, 3, 4, 6];
    let d = [1, 2, 3, 4];

    assert!(constant_time_eq(&a, &b));
    assert!(!constant_time_eq(&a, &c));
    assert!(!constant_time_eq(&a, &d));
}

#[test]
fn test_hex_encode_decode() {
    let data = b"Hello, World!";
    let hex = hex_encode(data);
    let decoded = hex_decode(&hex).unwrap();
    assert_eq!(decoded, data);

    assert!(hex_decode("abc").is_err(), "Odd length hex must fail");
    assert!(hex_decode("0g").is_err(), "Invalid hex char must fail");
}

// =========================================================================
// 4. Diode Frame Protocol & Anti-Replay Tests
// =========================================================================

#[test]
fn test_airgap_frame_roundtrip() {
    let auth_key = [0x5au8; 32];
    let shard_bytes = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let root_sha = sha256(b"ORIGINAL DATA");

    let frame = AirgapFrame::new(
        1001,
        1,
        0,
        4,
        2,
        100,
        root_sha,
        shard_bytes.clone(),
        &auth_key,
    );

    let raw = frame.to_bytes();
    let parsed = AirgapFrame::from_bytes(&raw, &auth_key).expect("Frame parse must succeed");

    assert_eq!(parsed.session_id, 1001);
    assert_eq!(parsed.epoch_seq, 1);
    assert_eq!(parsed.shard_index, 0);
    assert_eq!(parsed.data_shards_k, 4);
    assert_eq!(parsed.parity_shards_m, 2);
    assert_eq!(parsed.original_payload_len, 100);
    assert_eq!(parsed.payload_root_sha256, root_sha);
    assert_eq!(parsed.shard_bytes, shard_bytes);
}

#[test]
fn test_airgap_frame_crc32_and_hmac_tamper_rejection() {
    let auth_key = [0x5au8; 32];
    let wrong_key = [0x5bu8; 32];
    let shard_bytes = vec![0xaa, 0xbb, 0xcc];
    let root_sha = sha256(b"ROOT");

    let frame = AirgapFrame::new(1001, 1, 0, 4, 2, 50, root_sha, shard_bytes, &auth_key);
    let mut raw = frame.to_bytes();

    // Wrong HMAC key rejection
    let err_key = AirgapFrame::from_bytes(&raw, &wrong_key);
    assert_eq!(err_key.unwrap_err(), DiodeError::HmacAuthFailed);

    // Tampered byte triggers CRC mismatch
    raw[75] ^= 0x01;
    let err_crc = AirgapFrame::from_bytes(&raw, &auth_key);
    match err_crc {
        Err(DiodeError::CrcMismatch { .. }) => (),
        other => panic!("Expected CrcMismatch, got {:?}", other),
    }
}

#[test]
fn test_monotonic_epoch_anti_replay() {
    let mut session = DiodeReceiverSession::new();

    // Epoch 1: first commit
    assert!(session.check_anti_replay(1).is_ok());
    session.commit_epoch(1);

    // Replay epoch 1: must fail
    let err_replay = session.check_anti_replay(1);
    match err_replay {
        Err(DiodeError::EpochReplayDetected {
            epoch: 1,
            last_committed: 1,
        }) => (),
        other => panic!("Expected EpochReplayDetected, got {:?}", other),
    }

    // Older epoch 0: must fail
    assert!(session.check_anti_replay(0).is_err());

    // Advancing to epoch 2: must succeed
    assert!(session.check_anti_replay(2).is_ok());
    session.commit_epoch(2);

    // Replay epoch 2: must fail
    assert!(session.check_anti_replay(2).is_err());
}

#[test]
fn test_render_optical_frame_ascii() {
    let data = b"TEST DATA FOR OPTICAL QR RENDERING";
    let rendered = render_optical_frame_ascii(data, "TEST-LABEL");

    assert!(rendered.contains("--- [LHAIRGAP OPTICAL FRAME: TEST-LABEL"));
    assert!(rendered.contains("--- [EOF:"));
    // Ensure 7x7 corner finder pattern border "#######" is present
    assert!(rendered.contains("#######"));
}

// =========================================================================
// 5. 10-Rule Auditor & Posture Score Math Tests
// =========================================================================

#[test]
fn test_auditor_hardened_policy_100_score() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json")
        .expect("Must read hardened fixture");
    let json = JsonValue::parse(&content).expect("Must parse JSON");
    let policy = AirgapPolicy::from_json(&json).expect("Must map policy");

    let report = audit_airgap_policy(&policy);
    assert_eq!(report.total_rules, 10);
    assert_eq!(report.passed_rules, 10);
    assert_eq!(report.failed_rules, 0);
    assert_eq!(report.total_deductions, 0);
    assert_eq!(report.posture_score, 100);

    for f in report.findings {
        assert!(f.passed, "Rule {} must pass on hardened policy", f.rule_id);
    }
}

#[test]
fn test_auditor_vulnerable_policy_0_score() {
    let content = std::fs::read_to_string("fixtures/vulnerable_airgap_policy.json")
        .expect("Must read vulnerable fixture");
    let json = JsonValue::parse(&content).expect("Must parse JSON");
    let policy = AirgapPolicy::from_json(&json).expect("Must map policy");

    let report = audit_airgap_policy(&policy);
    assert_eq!(report.total_rules, 10);
    assert_eq!(report.passed_rules, 0);
    assert_eq!(report.failed_rules, 10);
    assert_eq!(report.total_deductions, 124);
    assert_eq!(report.posture_score, 0);

    // Verify deductions of each failed rule
    assert_eq!(report.findings[0].deduction, 25); // LH-AIRGAP-001
    assert_eq!(report.findings[1].deduction, 25); // LH-AIRGAP-002
    assert_eq!(report.findings[2].deduction, 25); // LH-AIRGAP-003
    assert_eq!(report.findings[3].deduction, 10); // LH-AIRGAP-004
    assert_eq!(report.findings[4].deduction, 10); // LH-AIRGAP-005
    assert_eq!(report.findings[5].deduction, 10); // LH-AIRGAP-006
    assert_eq!(report.findings[6].deduction, 10); // LH-AIRGAP-007
    assert_eq!(report.findings[7].deduction, 4); // LH-AIRGAP-008
    assert_eq!(report.findings[8].deduction, 4); // LH-AIRGAP-009
    assert_eq!(report.findings[9].deduction, 1); // LH-AIRGAP-010
}

#[test]
fn test_auditor_individual_rules() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let base_policy = AirgapPolicy::from_json(&json).unwrap();

    // Trigger LH-AIRGAP-001: deduction 25 -> score 75
    let mut p1 = base_policy.clone();
    p1.physical_unidirectional_diode = false;
    let r1 = audit_airgap_policy(&p1);
    assert_eq!(r1.failed_rules, 1);
    assert_eq!(r1.total_deductions, 25);
    assert_eq!(r1.posture_score, 75);
    assert_eq!(r1.findings[0].severity, Severity::Critical);

    // Trigger LH-AIRGAP-004: deduction 10 -> score 90
    let mut p4 = base_policy.clone();
    p4.encrypt_diode_payloads = false;
    let r4 = audit_airgap_policy(&p4);
    assert_eq!(r4.failed_rules, 1);
    assert_eq!(r4.total_deductions, 10);
    assert_eq!(r4.posture_score, 90);
    assert_eq!(r4.findings[3].severity, Severity::High);

    // Trigger LH-AIRGAP-008: deduction 4 -> score 96
    let mut p8 = base_policy.clone();
    p8.max_frame_payload_bytes = 2048;
    let r8 = audit_airgap_policy(&p8);
    assert_eq!(r8.failed_rules, 1);
    assert_eq!(r8.total_deductions, 4);
    assert_eq!(r8.posture_score, 96);
    assert_eq!(r8.findings[7].severity, Severity::Medium);

    // Trigger LH-AIRGAP-010: deduction 1 -> score 99
    let mut p10 = base_policy.clone();
    p10.audit_log_diode_transfers = false;
    let r10 = audit_airgap_policy(&p10);
    assert_eq!(r10.failed_rules, 1);
    assert_eq!(r10.total_deductions, 1);
    assert_eq!(r10.posture_score, 99);
    assert_eq!(r10.findings[9].severity, Severity::Low);
}

// =========================================================================
// 6. JSON Lexer & Parser Tests
// =========================================================================

#[test]
fn test_json_lexer_and_parser() {
    let json_text = r#"
    {
        "string_val": "hello \n world \"escaped\"",
        "int_val": 42,
        "float_val": -42.75,
        "bool_val": true,
        "null_val": null,
        "array_val": [1, 2, "three", false],
        "nested": {
            "key": "value"
        }
    }
    "#;

    let v = JsonValue::parse(json_text).expect("Must parse valid JSON");
    assert_eq!(
        v.get_str("string_val").unwrap(),
        "hello \n world \"escaped\""
    );
    assert_eq!(v.get_i64("int_val").unwrap(), 42);
    assert!((v.get_f64("float_val").unwrap() - (-42.75)).abs() < 1e-4);
    assert!(v.get_bool("bool_val").unwrap());
    assert_eq!(v.get("null_val").unwrap(), &JsonValue::Null);

    let arr = v.get("array_val").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 4);
    assert_eq!(arr[2].as_str().unwrap(), "three");

    let nested_key = v.get("nested").unwrap().get_str("key").unwrap();
    assert_eq!(nested_key, "value");
}

// =========================================================================
// 7. Exporters Tests (Table, JSON, SARIF)
// =========================================================================

#[test]
fn test_exporters_table_json_sarif() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let policy = AirgapPolicy::from_json(&json).unwrap();
    let report = audit_airgap_policy(&policy);

    let table = export_table(&report);
    assert!(table.contains("LOGIHERTZ AIR-GAP DATA DIODE ENCLAVE SECURITY AUDIT REPORT"));
    assert!(table.contains("LH-AIRGAP-001"));

    let json_out = export_json(&report);
    assert!(json_out.contains("\"posture_score\": 100"));
    assert!(json_out.contains("\"status\": \"PASS\""));

    let sarif = export_sarif(&report);
    assert!(sarif.contains("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"));
    assert!(sarif.contains("\"name\": \"lh-airgap-sync\""));
}

// =========================================================================
// 8. Subprocess CLI Invocation Tests
// =========================================================================

fn get_bin_path() -> String {
    env!("CARGO_BIN_EXE_lh-airgap-sync").to_string()
}

#[test]
fn test_cli_version_and_help() {
    let bin = get_bin_path();

    let ver_output = Command::new(&bin)
        .arg("--version")
        .output()
        .expect("Failed to execute binary");
    assert_eq!(ver_output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&ver_output.stdout);
    assert!(stdout.contains("lh-airgap-sync v0.1.0"));

    let help_output = Command::new(&bin)
        .arg("--help")
        .output()
        .expect("Failed to execute binary");
    assert_eq!(help_output.status.code(), Some(0));
    let help_stdout = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_stdout.contains("Usage:"));
}

#[test]
fn test_cli_scan_hardened_and_vulnerable() {
    let bin = get_bin_path();

    // Hardened policy -> exit code 0
    let h_res = Command::new(&bin)
        .args(["scan", "fixtures/hardened_airgap_policy.json"])
        .output()
        .expect("Failed to execute scan");
    assert_eq!(h_res.status.code(), Some(0));

    // Hardened policy JSON format -> exit code 0
    let h_json_res = Command::new(&bin)
        .args([
            "scan",
            "fixtures/hardened_airgap_policy.json",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute scan");
    assert_eq!(h_json_res.status.code(), Some(0));

    // Vulnerable policy -> exit code 1
    let v_res = Command::new(&bin)
        .args(["scan", "fixtures/vulnerable_airgap_policy.json"])
        .output()
        .expect("Failed to execute scan");
    assert_eq!(v_res.status.code(), Some(1));
}

#[test]
fn test_cli_encode_and_decode_burst() {
    let bin = get_bin_path();

    // Lossless recovery with 2 dropped shards (0, 2)
    let decode_res = Command::new(&bin)
        .args([
            "decode-burst",
            "fixtures/sample_sync_bundle.json",
            "--drop-shards",
            "0,2",
        ])
        .output()
        .expect("Failed to execute decode-burst");
    assert_eq!(decode_res.status.code(), Some(0));
    let decode_stdout = String::from_utf8_lossy(&decode_res.stdout);
    assert!(decode_stdout.contains("100% Bit-Accurate FEC Recovery Completed"));

    // Unrecoverable loss: dropping 3 shards > M=2 -> exit code 1
    let fail_res = Command::new(&bin)
        .args([
            "decode-burst",
            "fixtures/sample_sync_bundle.json",
            "--drop-shards",
            "0,1,2",
        ])
        .output()
        .expect("Failed to execute decode-burst");
    assert_eq!(fail_res.status.code(), Some(1));
}

#[test]
fn test_cli_render_optical() {
    let bin = get_bin_path();
    let opt_res = Command::new(&bin)
        .args(["render-optical", "--data", "TOP SECRET AIRGAP"])
        .output()
        .expect("Failed to execute render-optical");
    assert_eq!(opt_res.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&opt_res.stdout);
    assert!(stdout.contains("LHAIRGAP OPTICAL FRAME"));
}

// =========================================================================
// 9. Detailed Auditor Rule Isolation Tests
// =========================================================================

#[test]
fn test_rule_lh_airgap_001_critical() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.physical_unidirectional_diode = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[0].passed);
    assert_eq!(r.findings[0].deduction, 25);
    assert_eq!(r.findings[0].severity, Severity::Critical);
}

#[test]
fn test_rule_lh_airgap_002_critical() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.cryptographic_frame_auth = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[1].passed);
    assert_eq!(r.findings[1].deduction, 25);
    assert_eq!(r.findings[1].severity, Severity::Critical);
}

#[test]
fn test_rule_lh_airgap_003_critical() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.monotonic_epoch_anti_replay = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[2].passed);
    assert_eq!(r.findings[2].deduction, 25);
    assert_eq!(r.findings[2].severity, Severity::Critical);
}

#[test]
fn test_rule_lh_airgap_004_high() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.encrypt_diode_payloads = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[3].passed);
    assert_eq!(r.findings[3].deduction, 10);
    assert_eq!(r.findings[3].severity, Severity::High);
}

#[test]
fn test_rule_lh_airgap_005_high() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.fec_parity_ratio_percent = 15.0;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[4].passed);
    assert_eq!(r.findings[4].deduction, 10);
    assert_eq!(r.findings[4].severity, Severity::High);
}

#[test]
fn test_rule_lh_airgap_006_high() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.allow_executable_payloads = true;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[5].passed);
    assert_eq!(r.findings[5].deduction, 10);
    assert_eq!(r.findings[5].severity, Severity::High);
}

#[test]
fn test_rule_lh_airgap_007_high() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.max_reassembly_buffer_mb = 512;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[6].passed);
    assert_eq!(r.findings[6].deduction, 10);
    assert_eq!(r.findings[6].severity, Severity::High);
}

#[test]
fn test_rule_lh_airgap_008_medium() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.display_fps = 45.0;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[7].passed);
    assert_eq!(r.findings[7].deduction, 4);
    assert_eq!(r.findings[7].severity, Severity::Medium);
}

#[test]
fn test_rule_lh_airgap_009_medium() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.optical_shroud_enforced = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[8].passed);
    assert_eq!(r.findings[8].deduction, 4);
    assert_eq!(r.findings[8].severity, Severity::Medium);
}

#[test]
fn test_rule_lh_airgap_010_low() {
    let content = std::fs::read_to_string("fixtures/hardened_airgap_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let mut p = AirgapPolicy::from_json(&json).unwrap();
    p.require_dual_custody_signoff = false;
    let r = audit_airgap_policy(&p);
    assert!(!r.findings[9].passed);
    assert_eq!(r.findings[9].deduction, 1);
    assert_eq!(r.findings[9].severity, Severity::Low);
}

// =========================================================================
// 10. Additional Math, Codec & Protocol Edge Cases
// =========================================================================

#[test]
fn test_gf256_commutativity_mul() {
    let gf = Gf256::new();
    for a in [2, 17, 45, 128, 255] {
        for b in [3, 19, 99, 177, 240] {
            assert_eq!(gf.mul(a, b), gf.mul(b, a));
        }
    }
}

#[test]
fn test_gf256_associativity_mul() {
    let gf = Gf256::new();
    let a = 0x3a;
    let b = 0x7c;
    let c = 0xef;
    let ab_c = gf.mul(gf.mul(a, b), c);
    let a_bc = gf.mul(a, gf.mul(b, c));
    assert_eq!(ab_c, a_bc);
}

#[test]
fn test_fec_different_k_m_ratios_k2_m1() {
    let codec = FecCodec::new(2, 1).unwrap();
    let payload = b"FAST STREAM K=2 M=1";
    let shards = codec.encode(payload).unwrap();
    assert_eq!(shards.len(), 3);
    // Drop shard 0
    let rec: Vec<_> = vec![(1, shards[1].clone()), (2, shards[2].clone())];
    let recovered = codec.decode(payload.len(), &rec).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_different_k_m_ratios_k8_m4() {
    let codec = FecCodec::new(8, 4).unwrap();
    let payload = b"LARGE ENCLAVE TELEMETRY PAYLOAD FOR K=8 M=4 ROBUSTNESS VERIFICATION";
    let shards = codec.encode(payload).unwrap();
    assert_eq!(shards.len(), 12);

    // Drop 4 shards: 0, 2, 5, 7
    let rec: Vec<_> = shards
        .iter()
        .enumerate()
        .filter(|&(idx, _)| idx != 0 && idx != 2 && idx != 5 && idx != 7)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    assert_eq!(rec.len(), 8);
    let recovered = codec.decode(payload.len(), &rec).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_recovery_shuffled_order() {
    let codec = FecCodec::new(4, 2).unwrap();
    let payload = b"SHUFFLED SHARD ARRIVAL SIMULATION ACROSS MULTIPLE FIBER PATHS";
    let shards = codec.encode(payload).unwrap();

    // Pass shards out of order: 5, 1, 4, 2
    let rec = vec![
        (5, shards[5].clone()),
        (1, shards[1].clone()),
        (4, shards[4].clone()),
        (2, shards[2].clone()),
    ];
    let recovered = codec.decode(payload.len(), &rec).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_recovery_with_duplicates() {
    let codec = FecCodec::new(3, 2).unwrap();
    let payload = b"DUPLICATE SHARDS RECEPTION FILTER";
    let shards = codec.encode(payload).unwrap();

    // Provide duplicates: 0, 0, 1, 1, 4
    let rec = vec![
        (0, shards[0].clone()),
        (0, shards[0].clone()),
        (1, shards[1].clone()),
        (1, shards[1].clone()),
        (4, shards[4].clone()),
    ];
    let recovered = codec.decode(payload.len(), &rec).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fec_recovery_invalid_shard_index() {
    let codec = FecCodec::new(3, 2).unwrap();
    let rec = vec![(999, vec![0u8; 10]), (1, vec![0u8; 10]), (2, vec![0u8; 10])];
    assert!(codec.decode(20, &rec).is_err());
}

#[test]
fn test_fec_zeros_and_alternating_payload() {
    let codec = FecCodec::new(4, 2).unwrap();
    let zeros = vec![0u8; 128];
    let shards = codec.encode(&zeros).unwrap();
    let rec: Vec<_> = shards.into_iter().enumerate().skip(2).collect(); // drop 0, 1
    assert_eq!(rec.len(), 4);
    let recovered = codec.decode(zeros.len(), &rec).unwrap();
    assert_eq!(recovered, zeros);

    let alt: Vec<u8> = (0..200)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    let shards_alt = codec.encode(&alt).unwrap();
    let rec_alt: Vec<_> = shards_alt.into_iter().enumerate().take(4).collect();
    let recovered_alt = codec.decode(alt.len(), &rec_alt).unwrap();
    assert_eq!(recovered_alt, alt);
}

#[test]
fn test_airgap_frame_invalid_magic() {
    let auth_key = [0u8; 32];
    let frame = AirgapFrame::new(1, 1, 0, 2, 1, 10, [0u8; 32], vec![1, 2, 3], &auth_key);
    let mut raw = frame.to_bytes();
    raw[0] = b'X';
    let err = AirgapFrame::from_bytes(&raw, &auth_key);
    assert_eq!(err.unwrap_err(), DiodeError::InvalidMagic);
}

#[test]
fn test_airgap_frame_unsupported_version() {
    let auth_key = [0u8; 32];
    let frame = AirgapFrame::new(1, 1, 0, 2, 1, 10, [0u8; 32], vec![1, 2, 3], &auth_key);
    let mut raw = frame.to_bytes();
    raw[8] = 99; // invalid version
    let err = AirgapFrame::from_bytes(&raw, &auth_key);
    assert_eq!(err.unwrap_err(), DiodeError::UnsupportedVersion(99));
}

#[test]
fn test_airgap_frame_buffer_too_short() {
    let auth_key = [0u8; 32];
    let raw = vec![0u8; 20];
    let err = AirgapFrame::from_bytes(&raw, &auth_key);
    match err {
        Err(DiodeError::BufferTooShort(20)) => (),
        other => panic!("Expected BufferTooShort(20), got {:?}", other),
    }
}

#[test]
fn test_airgap_frame_length_mismatch() {
    let auth_key = [0u8; 32];
    let frame = AirgapFrame::new(1, 1, 0, 2, 1, 10, [0u8; 32], vec![1, 2, 3], &auth_key);
    let mut raw = frame.to_bytes();
    raw.push(0xFF); // extra byte
    let err = AirgapFrame::from_bytes(&raw, &auth_key);
    assert_eq!(err.unwrap_err(), DiodeError::LengthMismatch);
}

#[test]
fn test_diode_receiver_session_reset() {
    let mut session = DiodeReceiverSession::new();
    assert!(!session.has_committed);
    session.commit_epoch(100);
    assert!(session.has_committed);
    assert_eq!(session.last_committed_epoch, 100);
    assert!(session.check_anti_replay(101).is_ok());
    assert!(session.check_anti_replay(100).is_err());
    assert!(session.check_anti_replay(99).is_err());
}

#[test]
fn test_render_optical_frame_dimension_scaling() {
    let small_data = vec![0x11; 64];
    let s_out = render_optical_frame_ascii(&small_data, "SMALL");
    assert!(s_out.contains("Dim: 29x29"));

    let med_data = vec![0x22; 200];
    let m_out = render_optical_frame_ascii(&med_data, "MED");
    assert!(m_out.contains("Dim: 33x33"));

    let large_data = vec![0x33; 400];
    let l_out = render_optical_frame_ascii(&large_data, "LARGE");
    assert!(l_out.contains("Dim: 37x37"));

    let huge_data = vec![0x44; 800];
    let h_out = render_optical_frame_ascii(&huge_data, "HUGE");
    assert!(h_out.contains("Dim: 41x41"));
}

#[test]
fn test_sha256_incremental_avalanche() {
    let m1 = sha256(b"The quick brown fox jumps over the lazy dog");
    let m2 = sha256(b"The quick brown fox jumps over the lazy cog");
    assert_ne!(m1, m2);

    let mut bit_diffs = 0;
    for (b1, b2) in m1.iter().zip(m2.iter()) {
        bit_diffs += (b1 ^ b2).count_ones();
    }
    // Cryptographic hash should flip approximately 50% of the 256 bits (~128 bits)
    assert!(
        bit_diffs > 80,
        "Avalanche effect must flip substantial bits (got {})",
        bit_diffs
    );
}

#[test]
fn test_hmac_sha256_empty_key_and_empty_msg() {
    let empty_key = b"";
    let empty_msg = b"";
    let h = hmac_sha256(empty_key, empty_msg);
    assert_eq!(h.len(), 32);

    let key65 = vec![0x33; 65]; // > 64 bytes
    let h_long = hmac_sha256(&key65, b"DATA");
    assert_eq!(h_long.len(), 32);
}

#[test]
fn test_sha256_ctr_different_keys_and_nonces() {
    let key1 = [0x01u8; 32];
    let key2 = [0x02u8; 32];
    let pt = b"CLASSIFIED TARGET DATA";

    let ct1 = sha256_ctr_crypt(&key1, 10, pt);
    let ct2 = sha256_ctr_crypt(&key2, 10, pt);
    let ct3 = sha256_ctr_crypt(&key1, 11, pt);

    assert_ne!(ct1, ct2, "Different keys must yield different ciphertexts");
    assert_ne!(
        ct1, ct3,
        "Different nonces must yield different ciphertexts"
    );
}

#[test]
fn test_crc32_edge_patterns() {
    assert_eq!(crc32(&[]), 0x00000000);
    let zeroes = vec![0u8; 32];
    let c_zeros = crc32(&zeroes);
    assert_ne!(c_zeros, 0);

    let ones = vec![0xFFu8; 32];
    let c_ones = crc32(&ones);
    assert_ne!(c_ones, c_zeros);
}

#[test]
fn test_hex_decode_case_insensitivity() {
    let lower = "deadbeef";
    let upper = "DEADBEEF";
    let mixed = "DeAdBeEf";

    let b_low = hex_decode(lower).unwrap();
    let b_up = hex_decode(upper).unwrap();
    let b_mix = hex_decode(mixed).unwrap();

    assert_eq!(b_low, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(b_low, b_up);
    assert_eq!(b_low, b_mix);
}

#[test]
fn test_json_parse_empty_and_escapes() {
    let empty_obj = JsonValue::parse("{}").unwrap();
    assert_eq!(empty_obj.as_object().unwrap().len(), 0);

    let empty_arr = JsonValue::parse("[]").unwrap();
    assert_eq!(empty_arr.as_array().unwrap().len(), 0);

    let esc_json = r#"{"esc": "\b\f\r\t\n\/\"\\"}"#;
    let v_esc = JsonValue::parse(esc_json).unwrap();
    assert_eq!(v_esc.get_str("esc").unwrap(), "\x08\x0c\r\t\n/\"\\");

    let uni_json = r#"{"uni": "\u0041\u0042\u0043"}"#;
    let v_uni = JsonValue::parse(uni_json).unwrap();
    assert_eq!(v_uni.get_str("uni").unwrap(), "ABC");
}

#[test]
fn test_json_parse_syntax_errors() {
    assert!(JsonValue::parse("{unclosed").is_err());
    assert!(JsonValue::parse("{\"key\": unquoted}").is_err());
    assert!(JsonValue::parse("[1, 2,]").is_err());
    assert!(JsonValue::parse("").is_err());
}

#[test]
fn test_cli_scan_custom_output_file() {
    let bin = get_bin_path();
    let tmp_file = "/tmp/airgap_scan_test.json";
    let _ = std::fs::remove_file(tmp_file);

    let res = Command::new(&bin)
        .args([
            "scan",
            "fixtures/hardened_airgap_policy.json",
            "--format",
            "json",
            "--output",
            tmp_file,
        ])
        .output()
        .expect("Failed to execute scan with --output");

    assert_eq!(res.status.code(), Some(0));
    let content = std::fs::read_to_string(tmp_file).expect("File must be written");
    assert!(content.contains("\"posture_score\": 100"));
    let _ = std::fs::remove_file(tmp_file);
}

#[test]
fn test_cli_invalid_command_exit_code_2() {
    let bin = get_bin_path();
    let res = Command::new(&bin)
        .arg("nonexistent-command")
        .output()
        .expect("Failed to execute");
    assert_eq!(res.status.code(), Some(2));
}

#[test]
fn test_fec_different_k_m_ratios_k16_m8() {
    let codec = FecCodec::new(16, 8).unwrap();
    let payload = b"VERY LARGE ENCLAVE MULTI-MEGABYTE BULK DATA REPLICATION TEST STREAM WITH K=16 M=8 PARITY SETTINGS";
    let shards = codec.encode(payload).unwrap();
    assert_eq!(shards.len(), 24);

    // Drop 8 shards (indices 0..8), 16 surviving
    let rec: Vec<_> = shards
        .iter()
        .enumerate()
        .skip(8)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();
    assert_eq!(rec.len(), 16);
    let recovered = codec.decode(payload.len(), &rec).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_sha256_long_message_block_alignments() {
    // Exact 64-byte boundary
    let msg64 = vec![0x61u8; 64];
    let h64 = sha256(&msg64);
    assert_eq!(h64.len(), 32);

    // Exact 128-byte boundary
    let msg128 = vec![0x62u8; 128];
    let h128 = sha256(&msg128);
    assert_eq!(h128.len(), 32);

    // 1000-byte payload
    let msg1000 = vec![0x63u8; 1000];
    let h1000 = sha256(&msg1000);
    assert_eq!(h1000.len(), 32);
}
