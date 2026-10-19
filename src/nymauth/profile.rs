// SPDX-License-Identifier: MPL-2.0

//! The allowlist of nym_auth circuit builds, and what the prover trusts about each.
//!
//! Nothing about a circuit is taken from the catalog descriptor or from the artifact itself. A
//! build is usable only if it has an [`Entry`] in [`ENTRIES`], keyed by its hash circuit id; an
//! unlisted build is refused (`UnsupportedCircuit`) before any parsing. A build whose artifact,
//! parameters or ids differ from its entry is refused (`Circuit`).
//!
//! ## Adding a circuit build
//!
//! The circuit author supplies, per build:
//!
//! 1. the decompressed artifact (signature circuit, then hash circuit, LFC2): its exact length and
//!    SHA-256;
//! 2. the two circuit ids (hex) and the two Ligero `block_enc` values (the descriptor's `params`);
//! 3. the input counts of both circuits (`ninputs`, `npub`);
//! 4. `hash-semantic.tsv`: the profile line (`profile B_sig B_item B_ssc`) and the slot map.
//!
//! Then: add the `.tsv` under `profiles/` and append one [`Entry`] below. No other code names a
//! circuit. A build whose input layout differs from SPEC.md section L3 (slot order, tag and MAC
//! placement) needs code, not just an entry.

use super::error::NymAuthError;

/// One supported circuit build.
struct Entry {
    hash_circuit_id: &'static str,
    sig_circuit_id: &'static str,
    /// Exact length and SHA-256 (hex) of the decompressed LFC2 artifact. Checked before the
    /// artifact is parsed.
    artifact_len: usize,
    artifact_sha256: &'static str,
    /// Canonical Ligero widths.
    block_enc_hash: usize,
    block_enc_sig: usize,
    hash_ninputs: usize,
    hash_npub: usize,
    sig_ninputs: usize,
    sig_npub: usize,
    /// `hash-semantic.tsv`: the profile line and the slot map.
    map: &'static str,
}

const ENTRIES: &[Entry] = &[Entry {
    hash_circuit_id: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
    sig_circuit_id: "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
    artifact_len: 1_062_842,
    artifact_sha256: "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f",
    block_enc_hash: 6983,
    block_enc_sig: 4679,
    hash_ninputs: 97_032,
    hash_npub: 586,
    sig_ninputs: 4_765,
    sig_npub: 1_155,
    map: include_str!(
        "profiles/mdoc-5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729.tsv"
    ),
}];

pub(super) struct Profile {
    pub b_sig: usize,
    pub b_item: usize,
    pub b_ssc: usize,
    /// (slot_from, sem_from, len)
    pub runs: Vec<(usize, usize, usize)>,
    pub semantic_len: usize,
    pub hash_ninputs: usize,
    pub hash_npub: usize,
    pub sig_ninputs: usize,
    pub sig_npub: usize,
    pub sig_circuit_id: &'static str,
    pub artifact_len: usize,
    pub artifact_sha256: &'static str,
    pub block_enc_hash: usize,
    pub block_enc_sig: usize,
}

/// Slots of the signature circuit's input vector (SPEC.md L3.2), from `sig_npub`: the public part
/// ends with the six tags (768 bits) after a_v (128 bits); the private part is a_p (768), e, x and
/// y (256 each), then the issuer and device traces.
impl Profile {
    pub fn sig_tags(&self) -> usize {
        self.sig_npub - 768
    }
    pub fn sig_av(&self) -> usize {
        self.sig_tags() - 128
    }
    pub fn sig_ap(&self) -> usize {
        self.sig_npub
    }
    pub fn sig_e(&self) -> usize {
        self.sig_ap() + 768
    }
    pub fn sig_x(&self) -> usize {
        self.sig_e() + 256
    }
    pub fn sig_y(&self) -> usize {
        self.sig_x() + 256
    }
    pub fn sig_issuer_trace(&self) -> usize {
        self.sig_y() + 256
    }
}

fn bad(m: &str) -> NymAuthError {
    NymAuthError::Circuit(format!("internal profile table: {m}"))
}

pub(super) fn for_hash_circuit(id: &str) -> Result<Profile, NymAuthError> {
    let entry = ENTRIES
        .iter()
        .find(|e| e.hash_circuit_id.eq_ignore_ascii_case(id))
        .ok_or_else(|| {
            NymAuthError::UnsupportedCircuit(format!("no nym_auth profile for hash circuit {id}"))
        })?;
    let mut lines = entry.map.lines();
    let first: Vec<usize> = lines
        .next()
        .ok_or_else(|| bad("empty"))?
        .split_whitespace()
        .skip(1)
        .map(|x| x.parse().map_err(|_| bad("profile line")))
        .collect::<Result<_, _>>()?;
    let [b_sig, b_item, b_ssc] = first[..] else {
        return Err(bad("profile line arity"));
    };
    let mut runs = Vec::new();
    for l in lines.filter(|l| l.starts_with(|c: char| c.is_ascii_digit())) {
        let v: Vec<usize> = l
            .split('\t')
            .map(|x| x.parse().map_err(|_| bad("run")))
            .collect::<Result<_, _>>()?;
        let [a, b, c] = v[..] else {
            return Err(bad("run arity"));
        };
        runs.push((a, b, c));
    }
    let semantic_len: usize = runs.iter().map(|r| r.2).sum();
    // The runs must tile the hash circuit's private input slots, each exactly once.
    let mut seen = vec![false; entry.hash_ninputs];
    for &(slot, _, len) in &runs {
        for k in 0..len {
            match seen.get_mut(slot + k) {
                Some(s) if !*s => *s = true,
                _ => return Err(bad("slot map overlaps or exceeds the circuit")),
            }
        }
    }
    if !seen[entry.hash_npub..entry.hash_ninputs - 6]
        .iter()
        .all(|&s| s)
        || seen[..entry.hash_npub].iter().any(|&s| s)
        || seen[entry.hash_ninputs - 6..].iter().any(|&s| s)
    {
        return Err(bad(
            "slot map does not cover the private semantic slots exactly",
        ));
    }
    Ok(Profile {
        b_sig,
        b_item,
        b_ssc,
        runs,
        semantic_len,
        hash_ninputs: entry.hash_ninputs,
        hash_npub: entry.hash_npub,
        sig_ninputs: entry.sig_ninputs,
        sig_npub: entry.sig_npub,
        sig_circuit_id: entry.sig_circuit_id,
        artifact_len: entry.artifact_len,
        artifact_sha256: entry.artifact_sha256,
        block_enc_hash: entry.block_enc_hash,
        block_enc_sig: entry.block_enc_sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_ID: &str = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729";

    #[test]
    fn mdoc_profile_matches_the_archive() {
        let p = for_hash_circuit(HASH_ID).unwrap();
        assert_eq!((p.b_sig, p.b_item, p.b_ssc), (7, 2, 2));
        assert_eq!(p.runs.len(), 1_918);
        assert_eq!(p.semantic_len, 96_440);
        assert_eq!((p.block_enc_hash, p.block_enc_sig), (6983, 4679));
        assert_eq!(p.artifact_len, 289_503 + 773_339);
        // The signature circuit's slot layout (SPEC.md L3.2).
        assert_eq!(
            (
                p.sig_av(),
                p.sig_tags(),
                p.sig_ap(),
                p.sig_e(),
                p.sig_x(),
                p.sig_y(),
                p.sig_issuer_trace()
            ),
            (259, 387, 1155, 1923, 2179, 2435, 2691)
        );
    }

    #[test]
    fn unknown_circuit_is_refused() {
        assert!(matches!(
            for_hash_circuit(&"0".repeat(64)),
            Err(NymAuthError::UnsupportedCircuit(_))
        ));
    }

    #[test]
    fn every_entry_is_well_formed() {
        // Appending an entry must not need any other change: its table parses and tiles.
        for e in ENTRIES {
            let p = for_hash_circuit(e.hash_circuit_id).unwrap();
            assert_eq!(p.hash_ninputs, e.hash_ninputs);
            assert_eq!(e.hash_circuit_id.len(), 64);
            assert_eq!(e.sig_circuit_id.len(), 64);
            assert_eq!(e.artifact_sha256.len(), 64);
        }
    }
}
