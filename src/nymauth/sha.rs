// SPDX-License-Identifier: MPL-2.0

//! SHA-256 compression with the per-block "face" the nym_auth hash circuit consumes
//! (SPEC.md section L4.1).

pub(super) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Appends the low `n` bits of `v` to `out`, bit 0 first.
pub(super) fn word(out: &mut Vec<u8>, v: u64, n: u32) {
    out.extend((0..n).map(|j| ((v >> j) & 1) as u8));
}

/// Compresses `block` (64 bytes) into `state`. With `face`, appends the block's face: 208 words
/// of 32 bits (H_in, the schedule, e and a after every round, H_out).
pub(super) fn compress(state: &mut [u32; 8], block: &[u8], face: Option<&mut Vec<u8>>) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let h_in = *state;
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut es = [0u32; 64];
    let mut as_ = [0u32; 64];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        es[i] = e;
        as_[i] = a;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
    if let Some(out) = face {
        for x in h_in
            .iter()
            .chain(&w)
            .chain(&es)
            .chain(&as_)
            .chain(state.iter())
        {
            word(out, u64::from(*x), 32);
        }
    }
}

/// SHA-256 padding of `m`, then zero bytes up to `64 * blocks` bytes. `None` if `m` does not fit.
pub(super) fn pad(m: &[u8], blocks: usize) -> Option<Vec<u8>> {
    let n = 64usize.checked_mul(blocks)?;
    if m.len().checked_add(9)? > n {
        return None;
    }
    let full = (m.len() + 9).div_ceil(64) * 64;
    let mut out = vec![0u8; n];
    out[..m.len()].copy_from_slice(m);
    out[m.len()] = 0x80;
    out[full - 8..full].copy_from_slice(&(8 * m.len() as u64).to_be_bytes());
    Some(out)
}

/// Appends the faces of every block of the padded message `p`, chained from `state`.
pub(super) fn faces_padded(p: &[u8], mut state: [u32; 8], out: &mut Vec<u8>) -> [u32; 8] {
    for block in p.as_chunks::<64>().0 {
        compress(&mut state, block, Some(out));
    }
    state
}

/// faces(m, B) of the specification; `None` if `m` does not fit `blocks` blocks.
pub(super) fn faces(m: &[u8], blocks: usize, out: &mut Vec<u8>) -> Option<()> {
    // The message can be secret (the seed); its padded copy is wiped.
    let padded = super::wipe::Wiped::new(pad(m, blocks)?, 0u8);
    faces_padded(&padded, IV, out);
    Some(())
}

/// SHA-256 of `m`.
pub(super) fn sha256(m: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(m).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_chain_matches_sha2() {
        for len in [0usize, 3, 55, 56, 64, 119, 200] {
            let m: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let blocks = (len + 9).div_ceil(64);
            let p = pad(&m, blocks).unwrap();
            let mut face = Vec::new();
            let st = faces_padded(&p, IV, &mut face);
            let mut out = [0u8; 32];
            for (i, w) in st.iter().enumerate() {
                out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
            }
            assert_eq!(out, sha256(&m), "len {len}");
            assert_eq!(face.len(), blocks * 208 * 32);
        }
    }

    #[test]
    fn pad_refuses_oversized() {
        assert!(pad(&[0u8; 56], 1).is_none());
        assert!(pad(&[0u8; 55], 1).is_some());
    }
}
