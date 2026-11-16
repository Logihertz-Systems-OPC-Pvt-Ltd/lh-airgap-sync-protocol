//! Galois Field GF(2^8) arithmetic (polynomial 0x11D) and systematic (K, M)
//! Cauchy Forward Error Correction (FEC) erasure coding with Gauss-Jordan recovery.

#![forbid(unsafe_code)]

/// Galois Field GF(2^8) lookup tables and operations.
#[derive(Debug, Clone)]
pub struct Gf256 {
    exp: [u8; 510],
    log: [u8; 256],
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf256 {
    /// Constructs lookup tables using the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
    pub fn new() -> Self {
        let mut exp = [0u8; 510];
        let mut log = [0u8; 256];

        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;

            x <<= 1;
            if (x & 0x100) != 0 {
                x ^= 0x11D;
            }
        }
        log[0] = 0; // Not mathematically defined, but avoids panics

        Self { exp, log }
    }

    #[inline]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline]
    pub fn sub(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let log_a = self.log[a as usize] as usize;
            let log_b = self.log[b as usize] as usize;
            self.exp[log_a + log_b]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> Result<u8, &'static str> {
        if a == 0 {
            Err("Cannot invert zero in GF(2^8)")
        } else {
            let log_a = self.log[a as usize] as usize;
            Ok(self.exp[255 - log_a])
        }
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> Result<u8, &'static str> {
        if b == 0 {
            Err("Division by zero in GF(2^8)")
        } else if a == 0 {
            Ok(0)
        } else {
            let log_a = self.log[a as usize] as usize;
            let log_b = self.log[b as usize] as usize;
            let diff = (log_a + 255 - log_b) % 255;
            Ok(self.exp[diff])
        }
    }
}

/// Systematic (K, M) Cauchy Forward Error Correction (FEC) Codec.
#[derive(Debug, Clone)]
pub struct FecCodec {
    pub k: usize,
    pub m: usize,
    gf: Gf256,
    cauchy_matrix: Vec<Vec<u8>>,
}

impl FecCodec {
    /// Creates a new FEC codec with `k` data shards and `m` parity shards.
    ///
    /// Requires `k >= 1`, `m >= 1`, and `k + m <= 256`.
    #[allow(clippy::needless_range_loop)]
    pub fn new(k: usize, m: usize) -> Result<Self, String> {
        if k == 0 || m == 0 {
            return Err("K and M must both be greater than 0".to_string());
        }
        if k + m > 256 {
            return Err(format!(
                "Total shards (K + M = {}) cannot exceed 256",
                k + m
            ));
        }

        let gf = Gf256::new();

        // Build Cauchy matrix G of size M x K:
        // Let X = {0, ..., M - 1} and Y = {M, ..., M + K - 1}.
        // Then G[i][j] = 1 / (X[i] ^ Y[j]).
        // Since X and Y are disjoint, X[i] ^ Y[j] != 0, ensuring G is well-defined.
        let mut cauchy_matrix = vec![vec![0u8; k]; m];
        for i in 0..m {
            let x_i = i as u8;
            for j in 0..k {
                let y_j = (m + j) as u8;
                let denom = gf.add(x_i, y_j);
                cauchy_matrix[i][j] = gf.inv(denom).map_err(|e| e.to_string())?;
            }
        }

        Ok(Self {
            k,
            m,
            gf,
            cauchy_matrix,
        })
    }

    /// Partitions `payload` into `k` data shards and generates `m` Cauchy parity shards.
    /// Returns a vector of `k + m` shards, all of equal length.
    #[allow(clippy::needless_range_loop)]
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let shard_len = if payload.is_empty() {
            1
        } else {
            payload.len().div_ceil(self.k)
        };

        let mut data_shards = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let mut shard = vec![0u8; shard_len];
            let start = i * shard_len;
            if start < payload.len() {
                let end = (start + shard_len).min(payload.len());
                shard[..end - start].copy_from_slice(&payload[start..end]);
            }
            data_shards.push(shard);
        }

        let mut parity_shards = Vec::with_capacity(self.m);
        for m_idx in 0..self.m {
            let mut p_shard = vec![0u8; shard_len];
            for k_idx in 0..self.k {
                let coeff = self.cauchy_matrix[m_idx][k_idx];
                for b_idx in 0..shard_len {
                    let term = self.gf.mul(coeff, data_shards[k_idx][b_idx]);
                    p_shard[b_idx] = self.gf.add(p_shard[b_idx], term);
                }
            }
            parity_shards.push(p_shard);
        }

        let mut all_shards = Vec::with_capacity(self.k + self.m);
        all_shards.extend(data_shards);
        all_shards.extend(parity_shards);
        Ok(all_shards)
    }

    /// Reconstructs original payload from any `k` surviving shards.
    /// `received_shards` is a slice of `(shard_index, shard_data)`.
    #[allow(clippy::needless_range_loop)]
    pub fn decode(
        &self,
        original_len: usize,
        received_shards: &[(usize, Vec<u8>)],
    ) -> Result<Vec<u8>, String> {
        if received_shards.len() < self.k {
            return Err(format!(
                "INSUFFICIENT_SURVIVING_SHARDS: received {} shards, need at least K = {}",
                received_shards.len(),
                self.k
            ));
        }

        // Deduplicate received shards by index, taking first K unique shards
        let mut selected_shards: Vec<(usize, &Vec<u8>)> = Vec::with_capacity(self.k);
        let mut seen = vec![false; self.k + self.m];

        for (idx, data) in received_shards {
            if *idx >= self.k + self.m {
                return Err(format!(
                    "Invalid shard index {} (exceeds K + M = {})",
                    idx,
                    self.k + self.m
                ));
            }
            if !seen[*idx] {
                seen[*idx] = true;
                selected_shards.push((*idx, data));
                if selected_shards.len() == self.k {
                    break;
                }
            }
        }

        if selected_shards.len() < self.k {
            return Err("INSUFFICIENT_SURVIVING_SHARDS: not enough unique shards".to_string());
        }

        let shard_len = selected_shards[0].1.len();
        for (_, data) in &selected_shards {
            if data.len() != shard_len {
                return Err("Mismatched shard length in received shards".to_string());
            }
        }

        // Fast path: if all first K data shards are present in order, no inversion needed!
        let all_data = selected_shards
            .iter()
            .enumerate()
            .all(|(i, (idx, _))| *idx == i);
        if all_data {
            let mut payload = Vec::with_capacity(original_len);
            for i in 0..self.k {
                payload.extend_from_slice(selected_shards[i].1);
            }
            payload.truncate(original_len);
            return Ok(payload);
        }

        // Build the K x K submatrix S corresponding to the K selected shards.
        // For a data shard i (< K): row is standard unit vector e_i.
        // For a parity shard idx (>= K): row is Cauchy matrix row (idx - K).
        let mut s_matrix = vec![vec![0u8; self.k]; self.k];
        for (row_idx, (shard_idx, _)) in selected_shards.iter().enumerate() {
            if *shard_idx < self.k {
                s_matrix[row_idx][*shard_idx] = 1;
            } else {
                let p_idx = *shard_idx - self.k;
                s_matrix[row_idx].copy_from_slice(&self.cauchy_matrix[p_idx]);
            }
        }

        // Invert S using Gauss-Jordan elimination
        let s_inv = self.invert_matrix(&s_matrix)?;

        // Reconstruct original K data shards: D = S_inv * Received
        let mut reconstructed_data = vec![vec![0u8; shard_len]; self.k];
        for row in 0..self.k {
            for col in 0..self.k {
                let coeff = s_inv[row][col];
                if coeff == 0 {
                    continue;
                }
                let shard_bytes = selected_shards[col].1;
                for b_idx in 0..shard_len {
                    let term = self.gf.mul(coeff, shard_bytes[b_idx]);
                    reconstructed_data[row][b_idx] =
                        self.gf.add(reconstructed_data[row][b_idx], term);
                }
            }
        }

        // Flatten reconstructed shards and truncate to original_len
        let mut payload = Vec::with_capacity(original_len);
        for shard in reconstructed_data {
            payload.extend_from_slice(&shard);
        }
        payload.truncate(original_len);
        Ok(payload)
    }

    /// Inverts an N x N matrix over GF(2^8) using Gauss-Jordan elimination.
    #[allow(clippy::needless_range_loop)]
    fn invert_matrix(&self, matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        let n = matrix.len();
        let mut a: Vec<Vec<u8>> = matrix.to_vec();
        let mut inv: Vec<Vec<u8>> = vec![vec![0u8; n]; n];

        for i in 0..n {
            inv[i][i] = 1;
        }

        for i in 0..n {
            // Find pivot
            let mut pivot_row = i;
            while pivot_row < n && a[pivot_row][i] == 0 {
                pivot_row += 1;
            }

            if pivot_row == n {
                return Err("Singular matrix: cannot invert submatrix for FEC recovery".to_string());
            }

            if pivot_row != i {
                a.swap(i, pivot_row);
                inv.swap(i, pivot_row);
            }

            // Scale pivot row so diagonal becomes 1
            let pivot_val = a[i][i];
            let pivot_inv = self.gf.inv(pivot_val).map_err(|e| e.to_string())?;

            for j in 0..n {
                a[i][j] = self.gf.mul(a[i][j], pivot_inv);
                inv[i][j] = self.gf.mul(inv[i][j], pivot_inv);
            }

            // Eliminate column entries in other rows
            for r in 0..n {
                if r != i {
                    let factor = a[r][i];
                    if factor != 0 {
                        for c in 0..n {
                            let term_a = self.gf.mul(factor, a[i][c]);
                            a[r][c] = self.gf.sub(a[r][c], term_a);

                            let term_inv = self.gf.mul(factor, inv[i][c]);
                            inv[r][c] = self.gf.sub(inv[r][c], term_inv);
                        }
                    }
                }
            }
        }

        Ok(inv)
    }
}
