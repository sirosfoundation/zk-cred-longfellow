#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zk_cred_longfellow::nymauth::{
    MDOC_HASH_CIRCUIT_ID, NymAuthCircuitParams, NymAuthRequest, NymAuthVerifier, SIG_CIRCUIT_ID,
};

const CIRCUITS_ZST: &[u8] = include_bytes!("../../test-vectors/nymauth/mdoc-circuits.zst");

fn params() -> NymAuthCircuitParams {
    NymAuthCircuitParams {
        block_enc_hash: 6983,
        block_enc_sig: 4679,
        hash_circuit_id: MDOC_HASH_CIRCUIT_ID.into(),
        sig_circuit_id: SIG_CIRCUIT_ID.into(),
    }
}

fn verifier() -> &'static NymAuthVerifier {
    static V: OnceLock<NymAuthVerifier> = OnceLock::new();
    V.get_or_init(|| {
        let circuit = zstd::decode_all(CIRCUITS_ZST).unwrap();
        NymAuthVerifier::new(&circuit, &params()).unwrap()
    })
}

// The first byte picks the target: the circuit artifact reader (LFC2 and legacy) or the proof
// decoder and verifier. Neither may panic.
fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    if which & 1 == 0 {
        let _ = NymAuthVerifier::new(rest, &params());
    } else {
        let request = NymAuthRequest {
            issuer_key_x: &[0u8; 32],
            issuer_key_y: &[0u8; 32],
            time: "2026-10-07T12:00:00Z",
            earliest: "0000-00-00",
            cutoff: "2008-10-07",
            challenge_digest: &[0u8; 32],
            verifier_input: &[0u8; 32],
            transcript_seed: b"fuzz",
        };
        let _ = verifier().verify(&request, &[0u8; 32], rest);
    }
});
