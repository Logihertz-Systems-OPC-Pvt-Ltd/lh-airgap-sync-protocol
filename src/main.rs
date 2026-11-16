//! Command-line interface for the Logihertz Air-Gap Synchronization Protocol (lh-airgap-sync).

#![forbid(unsafe_code)]

use lh_airgap_sync::auditor::{audit_airgap_policy, AirgapPolicy};
use lh_airgap_sync::diode_protocol::{
    render_optical_frame_ascii, AirgapFrame, DiodeReceiverSession,
};
use lh_airgap_sync::exporters::{export_json, export_sarif, export_table};
use lh_airgap_sync::fec_gf256::FecCodec;
use lh_airgap_sync::json::JsonValue;
use lh_airgap_sync::sha256_hmac::{hex_decode, hex_encode, sha256, sha256_ctr_crypt};
use std::env;
use std::fs;
use std::process::exit;

const VERSION: &str = "0.1.0";

fn print_version() {
    println!("lh-airgap-sync v{}", VERSION);
    println!("Logihertz Systems (OPC) Private Limited - Air-Gap Data Diode Synchronization Engine");
}

fn print_help(prog_name: &str) {
    println!("Usage: {} <command> [options]\n", prog_name);
    println!("Production-grade, zero-dependency Rust Unidirectional Optical/QR & UDP Data Diode");
    println!(
        "Synchronization Protocol, GF(2^8) Erasure FEC Engine, and 10-Rule Security Auditor.\n"
    );
    println!("Commands:");
    println!("  scan <policy.json>         Audit air-gap diode policy against 10 enclave rules");
    println!(
        "  encode-burst <bundle.json> Encrypt, FEC shard, and frame a synchronization payload"
    );
    println!(
        "  decode-burst <bundle.json> Simulate lossy diode transmission & recover via GF(2^8)"
    );
    println!(
        "  render-optical             Render frame bytes into a 2D optical finder-pattern matrix"
    );
    println!("  --version, -v              Print version information and exit");
    println!("  --help, -h                 Print this help documentation and exit\n");
    println!("Options for 'scan':");
    println!("  --format table|json|sarif  Output report format (default: table)");
    println!("  --output <file>            Write report to file instead of stdout\n");
    println!("Options for 'encode-burst':");
    println!("  --data-shards <K>          Number of systematic data shards (default: 4)");
    println!("  --parity-shards <M>        Number of Cauchy parity shards (default: 2)");
    println!("  --output <file>            Write serialized burst frames to file\n");
    println!("Options for 'decode-burst':");
    println!("  --drop-shards <0,2,...>    Comma-separated list of shard indices to drop/erase");
    println!("  --data-shards <K>          K data shards (default: from bundle or 4)");
    println!("  --parity-shards <M>        M parity shards (default: from bundle or 2)\n");
    println!("Options for 'render-optical':");
    println!("  --data <string>            Input text data to encode into optical matrix");
    println!(
        "  --file <path>              Read binary or text file to render into optical matrix\n"
    );
    println!("Exit Codes:");
    println!("  0  Success / Pass (Posture Score >= 80, Lossless Recovery, Authentic)");
    println!("  1  Failure / Policy Violation (Score < 80, Unrecoverable Loss, HMAC Failure)");
    println!("  2  Invalid CLI usage / file I/O error / JSON parse error");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help(&args[0]);
        exit(2);
    }

    match args[1].as_str() {
        "--version" | "-v" => {
            print_version();
            exit(0);
        }
        "--help" | "-h" => {
            print_help(&args[0]);
            exit(0);
        }
        "scan" => cmd_scan(&args),
        "encode-burst" => cmd_encode_burst(&args),
        "decode-burst" => cmd_decode_burst(&args),
        "render-optical" => cmd_render_optical(&args),
        unknown => {
            eprintln!(
                "Error: Unknown command '{}'. Run '{} --help' for usage.",
                unknown, args[0]
            );
            exit(2);
        }
    }
}

fn cmd_scan(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Error: 'scan' requires a policy JSON file path.");
        exit(2);
    }

    let policy_path = &args[2];
    let mut format = "table";
    let mut output_path: Option<&str> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                if i + 1 < args.len() {
                    format = &args[i + 1];
                    i += 2;
                } else {
                    eprintln!("Error: --format requires an argument");
                    exit(2);
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].as_str());
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a file path");
                    exit(2);
                }
            }
            opt if opt.starts_with("--format=") => {
                format = &opt[9..];
                i += 1;
            }
            opt if opt.starts_with("--output=") => {
                output_path = Some(&opt[9..]);
                i += 1;
            }
            other => {
                eprintln!("Error: Unknown option '{}'", other);
                exit(2);
            }
        }
    }

    let content = match fs::read_to_string(policy_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading policy file '{}': {}", policy_path, e);
            exit(2);
        }
    };

    let json_val = match JsonValue::parse(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing JSON in '{}': {}", policy_path, e);
            exit(2);
        }
    };

    let policy = match AirgapPolicy::from_json(&json_val) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error interpreting policy structure: {}", e);
            exit(2);
        }
    };

    let report = audit_airgap_policy(&policy);

    let output_str = match format {
        "json" => export_json(&report),
        "sarif" => export_sarif(&report),
        _ => export_table(&report),
    };

    if let Some(path) = output_path {
        if let Err(e) = fs::write(path, output_str) {
            eprintln!("Error writing output file '{}': {}", path, e);
            exit(2);
        }
    } else {
        print!("{}", output_str);
    }

    if report.posture_score >= 80 {
        exit(0);
    } else {
        exit(1);
    }
}

fn cmd_encode_burst(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Error: 'encode-burst' requires a bundle JSON file path.");
        exit(2);
    }

    let bundle_path = &args[2];
    let mut data_shards_k: usize = 4;
    let mut parity_shards_m: usize = 2;
    let mut output_path: Option<&str> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--data-shards" => {
                data_shards_k = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(4);
                i += 2;
            }
            "--parity-shards" => {
                parity_shards_m = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
                i += 2;
            }
            "--output" => {
                output_path = args.get(i + 1).map(|s| s.as_str());
                i += 2;
            }
            opt if opt.starts_with("--output=") => {
                output_path = Some(&opt[9..]);
                i += 1;
            }
            _ => i += 1,
        }
    }

    let content = match fs::read_to_string(bundle_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading bundle file: {}", e);
            exit(2);
        }
    };

    let json = match JsonValue::parse(&content) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error parsing bundle JSON: {}", e);
            exit(2);
        }
    };

    let payload_str = json
        .get_str("payload")
        .unwrap_or("LOGIHERTZ AIRGAP SYNC DATA");
    let session_id = json.get_i64("session_id").unwrap_or(1001) as u64;
    let epoch_seq = json.get_i64("epoch_seq").unwrap_or(1) as u64;

    let auth_key = parse_or_default_key(json.get_str("auth_key_hex"));
    let cipher_key = parse_or_default_key(json.get_str("cipher_key_hex"));

    // 1. Encrypt payload via SHA256-CTR
    let plaintext_bytes = payload_str.as_bytes();
    let ciphertext = sha256_ctr_crypt(&cipher_key, epoch_seq, plaintext_bytes);
    let payload_root_sha = sha256(&ciphertext);

    // 2. Systematic Cauchy FEC erasure coding
    let codec = match FecCodec::new(data_shards_k, parity_shards_m) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FEC configuration error: {}", e);
            exit(2);
        }
    };

    let shards = match codec.encode(&ciphertext) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FEC encoding error: {}", e);
            exit(2);
        }
    };

    // 3. Frame each shard with LHAIRGAP headers, CRC-32, and HMAC-SHA256
    let mut frame_hexes = Vec::new();
    for (idx, shard) in shards.into_iter().enumerate() {
        let frame = AirgapFrame::new(
            session_id,
            epoch_seq,
            idx as u16,
            data_shards_k as u16,
            parity_shards_m as u16,
            ciphertext.len() as u32,
            payload_root_sha,
            shard,
            &auth_key,
        );
        frame_hexes.push(hex_encode(&frame.to_bytes()));
    }

    println!(
        "[ENCODE-BURST] Encrypted payload: {} bytes",
        ciphertext.len()
    );
    println!(
        "[ENCODE-BURST] Generated {} shards (K = {}, M = {})",
        frame_hexes.len(),
        data_shards_k,
        parity_shards_m
    );

    let output_json = format!(
        "{{\n  \"session_id\": {},\n  \"epoch_seq\": {},\n  \"data_shards_k\": {},\n  \"parity_shards_m\": {},\n  \"original_payload_len\": {},\n  \"payload_root_sha256\": \"{}\",\n  \"frames\": [\n{}\n  ]\n}}\n",
        session_id,
        epoch_seq,
        data_shards_k,
        parity_shards_m,
        ciphertext.len(),
        hex_encode(&payload_root_sha),
        frame_hexes.iter().map(|f| format!("    \"{}\"", f)).collect::<Vec<_>>().join(",\n")
    );

    if let Some(path) = output_path {
        if let Err(e) = fs::write(path, output_json) {
            eprintln!("Error writing burst file: {}", e);
            exit(2);
        }
        println!("[ENCODE-BURST] Saved burst frames to '{}'", path);
    } else {
        println!("{}", output_json);
    }

    exit(0);
}

fn cmd_decode_burst(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Error: 'decode-burst' requires a bundle or burst JSON file path.");
        exit(2);
    }

    let bundle_path = &args[2];
    let mut dropped_indices = Vec::new();

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--drop-shards" => {
                if let Some(s) = args.get(i + 1) {
                    for part in s.split(',') {
                        if let Ok(idx) = part.trim().parse::<usize>() {
                            dropped_indices.push(idx);
                        }
                    }
                }
                i += 2;
            }
            opt if opt.starts_with("--drop-shards=") => {
                for part in opt[14..].split(',') {
                    if let Ok(idx) = part.trim().parse::<usize>() {
                        dropped_indices.push(idx);
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }

    let content = match fs::read_to_string(bundle_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            exit(2);
        }
    };

    let json = match JsonValue::parse(&content) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            exit(2);
        }
    };

    let auth_key = parse_or_default_key(json.get_str("auth_key_hex"));
    let cipher_key = parse_or_default_key(json.get_str("cipher_key_hex"));

    // If frames are already packaged in the JSON:
    let frames_arr = json.get("frames").and_then(|v| v.as_array());

    let (mut raw_frames, k, m, orig_len, root_sha, epoch) = if let Some(arr) = frames_arr {
        let mut frames = Vec::new();
        for item in arr {
            if let Some(hex_str) = item.as_str() {
                if let Ok(bytes) = hex_decode(hex_str) {
                    frames.push(bytes);
                }
            }
        }
        let k = json.get_i64("data_shards_k").unwrap_or(4) as usize;
        let m = json.get_i64("parity_shards_m").unwrap_or(2) as usize;
        let orig_len = json.get_i64("original_payload_len").unwrap_or(0) as usize;
        let root_sha = json
            .get_str("payload_root_sha256")
            .unwrap_or("")
            .to_string();
        let epoch = json.get_i64("epoch_seq").unwrap_or(1) as u64;
        (frames, k, m, orig_len, root_sha, epoch)
    } else {
        // Fallback: encode payload dynamically on the fly then simulate decode
        let payload = json
            .get_str("payload")
            .unwrap_or("LOGIHERTZ AIRGAP TEST PAYLOAD");
        let k = 4;
        let m = 2;
        let epoch = json.get_i64("epoch_seq").unwrap_or(1) as u64;
        let cipher = sha256_ctr_crypt(&cipher_key, epoch, payload.as_bytes());
        let root = sha256(&cipher);
        let codec = FecCodec::new(k, m).unwrap();
        let shards = codec.encode(&cipher).unwrap();
        let mut frames = Vec::new();
        for (idx, shard) in shards.into_iter().enumerate() {
            let f = AirgapFrame::new(
                1001,
                epoch,
                idx as u16,
                k as u16,
                m as u16,
                cipher.len() as u32,
                root,
                shard,
                &auth_key,
            );
            frames.push(f.to_bytes());
        }
        (frames, k, m, cipher.len(), hex_encode(&root), epoch)
    };

    println!(
        "[DECODE-BURST] Total transmitted frames: {}",
        raw_frames.len()
    );
    println!(
        "[DECODE-BURST] Simulating lossy diode: dropping shards {:?}",
        dropped_indices
    );

    let mut surviving_shards = Vec::new();
    let receiver_session = DiodeReceiverSession::new();

    for (i, raw) in raw_frames.drain(..).enumerate() {
        if dropped_indices.contains(&i) {
            println!(
                "  -> [ERASURE] Shard {} dropped by optical diode attenuation / camera occlusion",
                i
            );
            continue;
        }

        // Verify frame integrity (CRC32, HMAC) and anti-replay
        match AirgapFrame::from_bytes(&raw, &auth_key) {
            Ok(frame) => {
                if let Err(e) = receiver_session.check_anti_replay(frame.epoch_seq) {
                    eprintln!("  -> Frame {} failed anti-replay: {}", i, e);
                    exit(1);
                }
                surviving_shards.push((frame.shard_index as usize, frame.shard_bytes));
            }
            Err(e) => {
                eprintln!("  -> Frame {} corrupted / failed auth: {}", i, e);
                exit(1);
            }
        }
    }

    println!(
        "[DECODE-BURST] Surviving valid shards: {} (K = {}, M = {})",
        surviving_shards.len(),
        k,
        m
    );

    if surviving_shards.len() < k {
        eprintln!(
            "\x1b[1;31m[FAIL]\x1b[0m Insufficient surviving shards (received {}, need {}). Unidirectional recovery impossible.",
            surviving_shards.len(),
            k
        );
        exit(1);
    }

    let codec = match FecCodec::new(k, m) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FEC codec error: {}", e);
            exit(2);
        }
    };

    let reconstructed_cipher = match codec.decode(orig_len, &surviving_shards) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("\x1b[1;31m[FAIL]\x1b[0m FEC reconstruction failed: {}", e);
            exit(1);
        }
    };

    // Check payload root hash
    let computed_root = hex_encode(&sha256(&reconstructed_cipher));
    if !root_sha.is_empty() && computed_root != root_sha {
        eprintln!(
            "\x1b[1;31m[FAIL]\x1b[0m Payload root SHA-256 mismatch (expected {}, computed {})",
            root_sha, computed_root
        );
        exit(1);
    }

    // Decrypt payload
    let decrypted = sha256_ctr_crypt(&cipher_key, epoch, &reconstructed_cipher);
    let plaintext = String::from_utf8_lossy(&decrypted);

    println!("\x1b[1;32m[PASS]\x1b[0m 100% Bit-Accurate FEC Recovery Completed!");
    println!(
        "  -> Reconstructed Ciphertext Length: {} bytes",
        reconstructed_cipher.len()
    );
    println!("  -> Root SHA-256: {}", computed_root);
    println!("  -> Decrypted Plaintext: \"{}\"", plaintext);
    exit(0);
}

fn cmd_render_optical(args: &[String]) {
    let mut data_str = "LHAIRGAP AIR-GAP ENCLAVE SYNCHRONIZATION TEST".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--data" => {
                if let Some(s) = args.get(i + 1) {
                    data_str = s.clone();
                }
                i += 2;
            }
            "--file" => {
                if let Some(f) = args.get(i + 1) {
                    if let Ok(c) = fs::read_to_string(f) {
                        data_str = c;
                    }
                }
                i += 2;
            }
            opt if opt.starts_with("--data=") => {
                data_str = opt[7..].to_string();
                i += 1;
            }
            _ => i += 1,
        }
    }

    let rendered = render_optical_frame_ascii(data_str.as_bytes(), "OPTICAL-BURST-0");
    print!("{}", rendered);
    exit(0);
}

fn parse_or_default_key(opt_hex: Option<&str>) -> [u8; 32] {
    if let Some(hex_str) = opt_hex {
        if let Ok(bytes) = hex_decode(hex_str) {
            if bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                return k;
            }
        }
    }
    // Default 256-bit key for local verification
    [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
        0xef, 0x97,
    ]
}
