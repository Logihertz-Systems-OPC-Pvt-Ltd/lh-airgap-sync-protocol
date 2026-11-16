//! Unidirectional LHAIRGAP frame packetizer, CRC-32 integrity filter,
//! monotonic anti-replay guard, and 2D optical finder-pattern matrix renderer.

#![forbid(unsafe_code)]

use crate::sha256_hmac::{constant_time_eq, crc32, hex_encode, hmac_sha256};

pub const LHAIRGAP_MAGIC: &[u8; 8] = b"LHAIRGAP";
pub const LHAIRGAP_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 71; // 8+1+8+8+2+2+2+4+32+4

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiodeError {
    InvalidMagic,
    UnsupportedVersion(u8),
    BufferTooShort(usize),
    LengthMismatch,
    CrcMismatch { expected: u32, computed: u32 },
    HmacAuthFailed,
    EpochReplayDetected { epoch: u64, last_committed: u64 },
    InsufficientShards { received: usize, required: usize },
    PayloadHashMismatch,
    InvalidConfiguration(String),
}

impl std::fmt::Display for DiodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "ERR_INVALID_MAGIC: Frame does not start with LHAIRGAP"),
            Self::UnsupportedVersion(v) => write!(f, "ERR_UNSUPPORTED_VERSION: Version {} not supported", v),
            Self::BufferTooShort(sz) => write!(f, "ERR_BUFFER_TOO_SHORT: Buffer length {} is below header minimum", sz),
            Self::LengthMismatch => write!(f, "ERR_LENGTH_MISMATCH: Declared shard length does not match payload size"),
            Self::CrcMismatch { expected, computed } => {
                write!(f, "ERR_CRC32_MISMATCH: Frame CRC32 0x{:08X} != computed 0x{:08X}", expected, computed)
            }
            Self::HmacAuthFailed => write!(f, "ERR_HMAC_AUTH_FAILED: Frame authentication failed (tampered data or wrong key)"),
            Self::EpochReplayDetected { epoch, last_committed } => {
                write!(f, "ERR_EPOCH_REPLAY_DETECTED: Epoch {} <= last committed {}", epoch, last_committed)
            }
            Self::InsufficientShards { received, required } => {
                write!(f, "ERR_INSUFFICIENT_SHARDS: Received {} unique shards, need at least K = {}", received, required)
            }
            Self::PayloadHashMismatch => write!(f, "ERR_PAYLOAD_HASH_MISMATCH: Reconstructed payload root SHA-256 does not match frame header"),
            Self::InvalidConfiguration(msg) => write!(f, "ERR_INVALID_CONFIG: {}", msg),
        }
    }
}

impl std::error::Error for DiodeError {}

/// An authenticated, self-verifying unidirectional data diode shard frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirgapFrame {
    pub magic: [u8; 8],
    pub version: u8,
    pub session_id: u64,
    pub epoch_seq: u64,
    pub shard_index: u16,
    pub data_shards_k: u16,
    pub parity_shards_m: u16,
    pub original_payload_len: u32,
    pub payload_root_sha256: [u8; 32],
    pub shard_bytes: Vec<u8>,
    pub crc32: u32,
    pub hmac_tag: [u8; 32],
}

impl AirgapFrame {
    /// Creates and signs a new `AirgapFrame` using `auth_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u64,
        epoch_seq: u64,
        shard_index: u16,
        data_shards_k: u16,
        parity_shards_m: u16,
        original_payload_len: u32,
        payload_root_sha256: [u8; 32],
        shard_bytes: Vec<u8>,
        auth_key: &[u8; 32],
    ) -> Self {
        let mut frame = Self {
            magic: *LHAIRGAP_MAGIC,
            version: LHAIRGAP_VERSION,
            session_id,
            epoch_seq,
            shard_index,
            data_shards_k,
            parity_shards_m,
            original_payload_len,
            payload_root_sha256,
            shard_bytes,
            crc32: 0,
            hmac_tag: [0u8; 32],
        };

        // Compute CRC-32 and HMAC over the authenticated body
        let body = frame.serialize_authenticated_body();
        frame.crc32 = crc32(&body);
        frame.hmac_tag = hmac_sha256(auth_key, &body);
        frame
    }

    /// Serializes the authenticated body (Header + Shard Bytes).
    fn serialize_authenticated_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.shard_bytes.len());
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.epoch_seq.to_be_bytes());
        buf.extend_from_slice(&self.shard_index.to_be_bytes());
        buf.extend_from_slice(&self.data_shards_k.to_be_bytes());
        buf.extend_from_slice(&self.parity_shards_m.to_be_bytes());
        buf.extend_from_slice(&self.original_payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload_root_sha256);
        buf.extend_from_slice(&(self.shard_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.shard_bytes);
        buf
    }

    /// Serializes the full frame into bytes for transmission across the data diode.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.serialize_authenticated_body();
        buf.extend_from_slice(&self.crc32.to_be_bytes());
        buf.extend_from_slice(&self.hmac_tag);
        buf
    }

    /// Deserializes and cryptographically verifies a frame from raw wire bytes.
    pub fn from_bytes(raw: &[u8], auth_key: &[u8; 32]) -> Result<Self, DiodeError> {
        if raw.len() < HEADER_SIZE + 36 {
            return Err(DiodeError::BufferTooShort(raw.len()));
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&raw[0..8]);
        if &magic != LHAIRGAP_MAGIC {
            return Err(DiodeError::InvalidMagic);
        }

        let version = raw[8];
        if version != LHAIRGAP_VERSION {
            return Err(DiodeError::UnsupportedVersion(version));
        }

        let session_id = u64::from_be_bytes(raw[9..17].try_into().unwrap());
        let epoch_seq = u64::from_be_bytes(raw[17..25].try_into().unwrap());
        let shard_index = u16::from_be_bytes(raw[25..27].try_into().unwrap());
        let data_shards_k = u16::from_be_bytes(raw[27..29].try_into().unwrap());
        let parity_shards_m = u16::from_be_bytes(raw[29..31].try_into().unwrap());
        let original_payload_len = u32::from_be_bytes(raw[31..35].try_into().unwrap());

        let mut payload_root_sha256 = [0u8; 32];
        payload_root_sha256.copy_from_slice(&raw[35..67]);

        let shard_len = u32::from_be_bytes(raw[67..71].try_into().unwrap()) as usize;
        let expected_total = HEADER_SIZE + shard_len + 36;
        if raw.len() != expected_total {
            return Err(DiodeError::LengthMismatch);
        }

        let shard_bytes = raw[HEADER_SIZE..HEADER_SIZE + shard_len].to_vec();
        let body_end = HEADER_SIZE + shard_len;

        let expected_crc = u32::from_be_bytes(raw[body_end..body_end + 4].try_into().unwrap());
        let computed_crc = crc32(&raw[..body_end]);
        if computed_crc != expected_crc {
            return Err(DiodeError::CrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let mut hmac_tag = [0u8; 32];
        hmac_tag.copy_from_slice(&raw[body_end + 4..body_end + 36]);
        let computed_hmac = hmac_sha256(auth_key, &raw[..body_end]);

        if !constant_time_eq(&hmac_tag, &computed_hmac) {
            return Err(DiodeError::HmacAuthFailed);
        }

        Ok(Self {
            magic,
            version,
            session_id,
            epoch_seq,
            shard_index,
            data_shards_k,
            parity_shards_m,
            original_payload_len,
            payload_root_sha256,
            shard_bytes,
            crc32: expected_crc,
            hmac_tag,
        })
    }
}

/// Receiver state machine tracking strictly monotonic epochs and reassembling bursts.
#[derive(Debug, Clone)]
pub struct DiodeReceiverSession {
    pub last_committed_epoch: u64,
    pub has_committed: bool,
}

impl Default for DiodeReceiverSession {
    fn default() -> Self {
        Self::new()
    }
}

impl DiodeReceiverSession {
    pub fn new() -> Self {
        Self {
            last_committed_epoch: 0,
            has_committed: false,
        }
    }

    /// Verifies that an incoming frame's `epoch_seq` is strictly greater than `last_committed_epoch`.
    pub fn check_anti_replay(&self, epoch: u64) -> Result<(), DiodeError> {
        if self.has_committed && epoch <= self.last_committed_epoch {
            return Err(DiodeError::EpochReplayDetected {
                epoch,
                last_committed: self.last_committed_epoch,
            });
        }
        Ok(())
    }

    /// Commits an epoch upon successful bundle reconstruction and validation.
    pub fn commit_epoch(&mut self, epoch: u64) {
        self.last_committed_epoch = epoch;
        self.has_committed = true;
    }
}

/// Renders a frame or raw byte slice into a 2D optical matrix with standard 7x7 corner finder patterns.
#[allow(clippy::needless_range_loop)]
pub fn render_optical_frame_ascii(frame_bytes: &[u8], label: &str) -> String {
    // Dimension chosen based on payload size: minimum 29x29, up to 41x41
    let dim: usize = if frame_bytes.len() < 128 {
        29
    } else if frame_bytes.len() < 256 {
        33
    } else if frame_bytes.len() < 512 {
        37
    } else {
        41
    };

    let mut grid = vec![vec!['.'; dim]; dim];

    // Helper to draw 7x7 finder pattern at (top, left)
    let draw_finder = |g: &mut Vec<Vec<char>>, top: usize, left: usize| {
        for r in 0..7 {
            for c in 0..7 {
                let is_border = r == 0 || r == 6 || c == 0 || c == 6;
                let is_inner_center = (2..=4).contains(&r) && (2..=4).contains(&c);
                if is_border || is_inner_center {
                    g[top + r][left + c] = '#';
                } else {
                    g[top + r][left + c] = '.';
                }
            }
        }
    };

    // Place 3 standard finder patterns: Top-Left, Top-Right, Bottom-Left
    draw_finder(&mut grid, 0, 0);
    draw_finder(&mut grid, 0, dim - 7);
    draw_finder(&mut grid, dim - 7, 0);

    // Place timing patterns along row 6 and column 6
    for i in 7..(dim - 7) {
        let ch = if i % 2 == 0 { '#' } else { '.' };
        grid[6][i] = ch;
        grid[i][6] = ch;
    }

    // Populate data modules from bits of frame_bytes
    let mut bit_idx = 0;
    let total_bits = frame_bytes.len() * 8;

    for r in 0..dim {
        for c in 0..dim {
            // Skip finder patterns
            let in_top_left = r < 8 && c < 8;
            let in_top_right = r < 8 && c >= dim - 8;
            let in_bottom_left = r >= dim - 8 && c < 8;
            let on_timing = (r == 6 && c >= 7 && c < dim - 7) || (c == 6 && r >= 7 && r < dim - 7);

            if !in_top_left && !in_top_right && !in_bottom_left && !on_timing {
                if bit_idx < total_bits {
                    let byte_val = frame_bytes[bit_idx / 8];
                    let bit_val = (byte_val >> (7 - (bit_idx % 8))) & 1;
                    grid[r][c] = if bit_val == 1 { '#' } else { '.' };
                    bit_idx += 1;
                } else {
                    // Padding mask
                    grid[r][c] = if (r + c) % 2 == 0 { '#' } else { '.' };
                }
            }
        }
    }

    // Render to string
    let mut out = String::new();
    out.push_str(&format!(
        "--- [LHAIRGAP OPTICAL FRAME: {} (Dim: {}x{})] ---\n",
        label, dim, dim
    ));
    for row in grid {
        let line: String = row.into_iter().collect();
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!(
        "--- [EOF: {} bytes, SHA-256: {}] ---\n",
        frame_bytes.len(),
        hex_encode(&crate::sha256_hmac::sha256(frame_bytes))
    ));
    out
}
