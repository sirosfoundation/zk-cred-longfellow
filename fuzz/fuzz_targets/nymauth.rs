#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zk_cred_longfellow::nymauth::{
    NymAuthCircuitParams, NymAuthRequest, NymAuthVerifier, derive_challenge, verifier_input,
};

const CIRCUITS_ZST: &[u8] = include_bytes!("../../test-vectors/nymauth/mdoc-circuits.zst");

fn params() -> NymAuthCircuitParams {
    NymAuthCircuitParams {
        block_enc_hash: 6983,
        block_enc_sig: 4679,
        hash_circuit_id: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729".into(),
        sig_circuit_id: "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb".into(),
    }
}

fn verifier() -> &'static NymAuthVerifier {
    static V: OnceLock<NymAuthVerifier> = OnceLock::new();
    V.get_or_init(|| {
        let circuit = zstd::decode_all(CIRCUITS_ZST).unwrap();
        NymAuthVerifier::new(&circuit, &params()).unwrap()
    })
}

// The first byte picks the target: the circuit artifact loader (pin, LFC2 reader) or the proof
// decoder and verifier. Neither may panic. The verify request is the fixture's, so the seed
// proof (`fuzz/seeds/nymauth/proof-seed`: 0x01 followed by the archive's reference proof) reaches
// the verifier's deepest checks before mutation breaks it.
fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    if which & 1 == 0 {
        let _ = NymAuthVerifier::new(rest, &params());
    } else {
        let c = derive_challenge(
            "https://verifier.example",
            "pOA0oqEAhLnqug2r7Ve4tQ",
            "eu.europa.ec.eudi.nym_auth.1",
            None,
        )
        .unwrap();
        let qx = hex_literal("b626aa933b215bc28f3b4924bf675454d2121f28bbb146415c181092f7fd9080");
        let qy = hex_literal("bf779357652d68be5ab61c667bde4ebff67b9efa2535c1138508fad656a2ab63");
        let vi = verifier_input("x509_san_dns:verifier.example").unwrap();
        let pseudonym =
            hex_literal("155f433796d1f282268a87100cd08510893f97f6e5607bc5e4c66afadb71aad1");
        let request = NymAuthRequest {
            issuer_key_x: &qx,
            issuer_key_y: &qy,
            time: "2026-10-07T12:00:00Z",
            earliest: "0000-00-00",
            cutoff: "2008-10-07",
            challenge_digest: &c.challenge_digest,
            verifier_input: &vi,
            transcript_seed: &c.session_transcript,
        };
        let _ = verifier().verify(&request, &pseudonym, rest);
    }
});

fn hex_literal(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
