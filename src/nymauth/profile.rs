//! The per-circuit profile of the hash circuit: message block counts and the map from the
//! semantic bits S to input slots (`hash-semantic.tsv` of the circuit archive, SPEC.md L4.4).
//!
//! The catalog descriptor carries only the circuit ids and the Ligero `block_enc` values; the slot
//! map is a property of how the circuit was generated, so it is compiled in here, keyed by the
//! hash circuit's id. A circuit with an unknown id is refused rather than guessed at.

use super::error::NymAuthError;

/// The hash circuit id (hex) of the mdoc nym_auth circuit.
pub const MDOC_HASH_CIRCUIT_ID: &str =
    "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729";
/// The signature circuit id (hex) shared by every nym_auth format.
pub const SIG_CIRCUIT_ID: &str = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb";

const MDOC_MAP: &str = include_str!(
    "profiles/mdoc-5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729.tsv"
);

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
}

fn bad(m: &str) -> NymAuthError {
    NymAuthError::Circuit(format!("internal profile table: {m}"))
}

pub(super) fn for_hash_circuit(id: &str) -> Result<Profile, NymAuthError> {
    if !id.eq_ignore_ascii_case(MDOC_HASH_CIRCUIT_ID) {
        return Err(NymAuthError::UnsupportedCircuit(format!(
            "no nym_auth witness profile for hash circuit {id}"
        )));
    }
    let mut lines = MDOC_MAP.lines();
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
    let semantic_len = runs.iter().map(|r| r.2).sum();
    Ok(Profile {
        b_sig,
        b_item,
        b_ssc,
        runs,
        semantic_len,
        hash_ninputs: 97_032,
        hash_npub: 586,
        sig_ninputs: 4_765,
        sig_npub: 1_155,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdoc_profile_matches_the_archive() {
        let p = for_hash_circuit(MDOC_HASH_CIRCUIT_ID).unwrap();
        assert_eq!((p.b_sig, p.b_item, p.b_ssc), (7, 2, 2));
        assert_eq!(p.runs.len(), 1_918);
        assert_eq!(p.semantic_len, 96_440);
        // The runs cover slots npub ... ninputs - 7 exactly once.
        let mut seen = vec![false; p.hash_ninputs];
        for &(slot, _, len) in &p.runs {
            for k in 0..len {
                assert!(!seen[slot + k]);
                seen[slot + k] = true;
            }
        }
        assert!(seen[p.hash_npub..p.hash_ninputs - 6].iter().all(|&s| s));
        assert!(!seen[..p.hash_npub].iter().any(|&s| s));
    }

    #[test]
    fn unknown_circuit_is_refused() {
        assert!(matches!(
            for_hash_circuit(&"0".repeat(64)),
            Err(NymAuthError::UnsupportedCircuit(_))
        ));
    }
}
