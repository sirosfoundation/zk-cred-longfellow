//! Regression tests for the review findings on artifact loading, parameters, request validation
//! and secret handling. Each was checked non-vacuous by reverting the fix.

use super::*;
use wasm_bindgen_test::wasm_bindgen_test;

fn uleb(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// One LFC2 circuit (P-256 or GF(2^128)) whose single layer is `seg_len * ntok` identical
/// terms: a few KB of input that would expand to hundreds of MB.
fn lfc2_bomb(fid: u32, seg_len: usize, ntok: usize) -> Vec<u8> {
    let mut o = b"LFC2".to_vec();
    for v in [fid, 1, 1, 1, 1, 2, 1, 1] {
        uleb(v, &mut o);
    }
    o.extend(std::iter::repeat_n(1u8, if fid == 1 { 32 } else { 16 }));
    uleb(1, &mut o);
    uleb(2, &mut o);
    uleb(1, &mut o);
    for _ in 0..4 {
        uleb(0, &mut o);
    }
    uleb(1, &mut o);
    uleb(seg_len as u32, &mut o);
    for _ in 0..seg_len {
        uleb(0, &mut o);
    }
    uleb(ntok as u32, &mut o);
    for _ in 0..ntok {
        uleb(0, &mut o);
    }
    o.extend_from_slice(&[0u8; 32]);
    o
}

fn load_error(artifact: &[u8], p: &NymAuthCircuitParams) -> NymAuthError {
    NymAuthVerifier::new(artifact, p)
        .err()
        .expect("must be refused")
}

fn is_pin_error(e: &NymAuthError) -> bool {
    matches!(e, NymAuthError::Circuit(m) if m.contains("SHA-256"))
}

// ---------------------------------------------------------------------------------------------
// CIRCUIT-1: the artifact is authenticated before anything is parsed or allocated
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn artifact_is_authenticated_before_it_is_parsed() {
    let genuine = circuit();
    let mut flipped = genuine.clone();
    flipped[1000] ^= 1;
    let mut longer = genuine.clone();
    longer.push(0);
    let sz = |v: u32| [v as u8, (v >> 8) as u8, (v >> 16) as u8];
    // The legacy layout: a 12-byte header that asks for 0xFFFFFF constants.
    let mut legacy = vec![1u8];
    for v in [1, 1, 1, 1, 1, 2, 0, 0xFFFFFF] {
        legacy.extend_from_slice(&sz(v));
    }
    let six: Vec<u8> = (0..6).flat_map(|_| lfc2_bomb(1, 1000, 16_000)).collect();
    for (name, a) in [
        ("empty", Vec::new()),
        ("expansion bomb", lfc2_bomb(1, 1000, 16_000)),
        ("six bombs", six),
        ("legacy allocation bomb", legacy),
        ("one flipped byte", flipped),
        ("one trailing byte", longer),
        ("truncated", genuine[..genuine.len() - 1].to_vec()),
    ] {
        let e = load_error(&a, &params());
        assert!(is_pin_error(&e), "{name}: {e}");
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn converter_output_is_bounded_whatever_the_caller_did() {
    // Defence in depth: even if an unauthenticated artifact reached the converter, it stops at
    // its output budget, and reads exactly two circuits.
    let two = [lfc2_bomb(1, 1000, 16_000), lfc2_bomb(4, 1000, 16_000)].concat();
    let e = lfc2::to_legacy_pair(&two).unwrap_err();
    assert!(e.to_string().contains("size limit"), "{e}");
    let three = [lfc2_bomb(1, 1, 1), lfc2_bomb(4, 1, 1), lfc2_bomb(4, 1, 1)].concat();
    let e = lfc2::to_legacy_pair(&three).unwrap_err();
    assert!(e.to_string().contains("left over"), "{e}");
    // A legacy-layout artifact is not accepted by the converter.
    assert!(lfc2::to_legacy_pair(&[1u8, 1, 0, 0]).is_err());
    // The genuine artifact converts.
    lfc2::to_legacy_pair(&circuit()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// CIRCUIT-2: the transcript binds the stored id, so it must equal the recomputed one
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn stored_circuit_id_must_equal_the_recomputed_id() {
    let genuine = circuit();
    let (sig_part, sig_used) = lfc2::one(&genuine).unwrap();
    let legacy = lfc2::to_legacy_pair(&genuine).unwrap();
    let profile = || profile::for_hash_circuit(MDOC_HASH_CIRCUIT_ID).unwrap();
    // control: the genuine pair decodes.
    decode_pair(&legacy, &params(), profile()).unwrap();
    assert!(sig_used < genuine.len());
    // The stored ids are the last 32 bytes of each circuit.
    for (name, at) in [
        ("signature", sig_part.len() - 1),
        ("hash", legacy.len() - 1),
    ] {
        let mut t = legacy.clone();
        t[at] ^= 0x55;
        let e = decode_pair(&t, &params(), profile()).err().unwrap();
        assert!(
            matches!(&e, NymAuthError::Circuit(m) if m.contains("stored id")),
            "{name}: {e}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// CIRCUIT-3: Ligero widths and ids come from the profile, not the descriptor
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn descriptor_parameters_must_equal_the_profile() {
    let c = circuit();
    for (h, s) in [
        (6983 + 9, 4679),
        (6983, 4679 + 9),
        (6983 + 4, 4679 + 3),
        (6983, 1196),
        (1 << 22, 1 << 22),
    ] {
        let p = NymAuthCircuitParams {
            block_enc_hash: h,
            block_enc_sig: s,
            ..params()
        };
        let e = load_error(&c, &p);
        assert!(
            matches!(&e, NymAuthError::Circuit(m) if m.contains("block_enc")),
            "{h},{s}: {e}"
        );
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn an_unlisted_build_fails_closed_before_any_parsing() {
    // Unknown hash circuit id: refused as unsupported, with any artifact at all.
    for artifact in [
        Vec::new(),
        vec![0u8; 100],
        circuit(),
        lfc2_bomb(1, 1000, 16_000),
    ] {
        let p = NymAuthCircuitParams {
            hash_circuit_id: "ab".repeat(32),
            ..params()
        };
        assert!(matches!(
            load_error(&artifact, &p),
            NymAuthError::UnsupportedCircuit(_)
        ));
    }
    // A listed id with an artifact that is not that build's.
    let other = zstd::decode_all(
        &include_bytes!(
            "../../../test-vectors/mdoc_zk/7_1_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
        )[..],
    )
    .unwrap();
    assert!(is_pin_error(&load_error(&other, &params())));
}

// ---------------------------------------------------------------------------------------------
// CIRCUIT-4 / CIRCUIT-5: request validation, at prove and at verify
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn transcript_seed_length_is_bounded() {
    let fx = Fx::load(0);
    let long = vec![7u8; 65_537];
    assert_eq!(
        (MIN_TRANSCRIPT_SEED_LEN, MAX_TRANSCRIPT_SEED_LEN),
        (32, 65_536)
    );
    let short = [7u8; 31];
    let floor = [7u8; 32];
    for bad in [&[][..], &short[..], &long[..]] {
        let rq = NymAuthRequest {
            transcript_seed: bad,
            ..fx.request()
        };
        assert!(matches!(
            prover().prove(&rq, &fx.witness()),
            Err(NymAuthError::InvalidInput(_))
        ));
        assert!(matches!(
            verifier().verify(&rq, &fx.pseudonym, REFERENCE_PROOF),
            Err(NymAuthError::InvalidInput(_))
        ));
    }
    // The floor itself passes validation (the proof is then refused for the wrong transcript).
    let rq = NymAuthRequest {
        transcript_seed: &floor,
        ..fx.request()
    };
    assert!(matches!(
        verifier().verify(&rq, &fx.pseudonym, REFERENCE_PROOF),
        Err(NymAuthError::Verification(_))
    ));
}

#[wasm_bindgen_test(unsupported = test)]
fn time_and_dates_must_be_calendar_valid_digits() {
    let fx = Fx::load(0);
    let bad_times = [
        "2026-13-07T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "2025-02-29T12:00:00Z",
        "1900-02-29T12:00:00Z",
        "2026-10-07T24:00:00Z",
        "2026-10-07T12:60:00Z",
        "2026-10-07T12:00:60Z",
        "2026-10-07 12:00:00Z",
        "2026-10-07T12:00:00z",
        "ABCDEFGHIJKLMNOPQRST",
        "0000-00-00T00:00:00Z",
        "2026-10-07T12:00:00\u{7f}",
    ];
    let bad_dates = [
        "2008-02-30",
        "1900-02-29",
        "2008-00-10",
        "2008-10-00",
        "2008/10/07",
        "2008-1-007",
        "\u{7f}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}",
        "0000-00-00", // not a cutoff
    ];
    let invalid = |rq: NymAuthRequest<'_>, what: &str| {
        assert!(
            matches!(
                verifier().verify(&rq, &fx.pseudonym, REFERENCE_PROOF),
                Err(NymAuthError::InvalidInput(_))
            ),
            "verify {what}"
        );
        assert!(
            matches!(
                prover().prove(&rq, &fx.witness()),
                Err(NymAuthError::InvalidInput(_))
            ),
            "prove {what}"
        );
    };
    for t in bad_times {
        invalid(
            NymAuthRequest {
                time: t,
                ..fx.request()
            },
            t,
        );
    }
    for d in bad_dates {
        invalid(
            NymAuthRequest {
                cutoff: d,
                ..fx.request()
            },
            d,
        );
    }
    for d in &bad_dates[..6] {
        invalid(
            NymAuthRequest {
                earliest: d,
                ..fx.request()
            },
            d,
        );
    }
    // earliest after cutoff
    invalid(
        NymAuthRequest {
            earliest: "2009-01-01",
            cutoff: "2008-10-07",
            ..fx.request()
        },
        "E > C",
    );
    // Valid edge cases are accepted by validation (the proofs are then refused on content).
    for (t, e, c) in [
        ("2024-02-29T23:59:59Z", "0000-00-00", "9999-12-31"),
        ("2000-02-29T00:00:00Z", "1900-01-01", "1900-01-01"),
    ] {
        let rq = NymAuthRequest {
            time: t,
            earliest: e,
            cutoff: c,
            ..fx.request()
        };
        assert!(matches!(
            verifier().verify(&rq, &fx.pseudonym, REFERENCE_PROOF),
            Err(NymAuthError::Verification(_))
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// CIRCUIT-6: secrets in Debug output and error strings; wiping of the extra buffers
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn debug_output_is_redacted() {
    let fx = Fx::load(0);
    let w = format!("{:?}", fx.witness());
    assert!(w.contains("redacted"));
    let proof = proof();
    let d = format!("{proof:?}");
    assert!(d.contains("redacted"));
    assert!(!d.contains(&hex::encode(&proof.pseudonym[..8])));
    assert!(d.len() < 100);
}

#[cfg(feature = "uniffi")]
#[wasm_bindgen_test(unsupported = test)]
fn uniffi_records_are_redacted_in_debug() {
    use crate::nymauth::ffi_uniffi::{NymAuthProveRequest, NymAuthProveResponse};
    let r = NymAuthProveRequest {
        issuer_signed: vec![1; 4],
        secret_seed: vec![0xab; 16],
        issuer_key_x: vec![],
        issuer_key_y: vec![],
        time: String::new(),
        earliest: String::new(),
        cutoff: String::new(),
        challenge_digest: vec![],
        device_signature: vec![],
        verifier_input: vec![],
        transcript_seed: vec![],
    };
    let d = format!("{r:?}");
    assert!(d.contains("redacted") && !d.contains("171") && !d.contains("ab"));
    let d = format!(
        "{:?}",
        NymAuthProveResponse {
            proof: vec![0xcd; 8],
            pseudonym: vec![0xef; 32]
        }
    );
    assert!(d.contains("redacted") && !d.contains("205") && !d.contains("cd"));
}

#[wasm_bindgen_test(unsupported = test)]
fn refusals_do_not_leak_circuit_state() {
    let fx = Fx::load(0);
    let mut seed = fx.seed;
    seed[0] ^= 1;
    let e = prover()
        .prove(
            &fx.request(),
            &NymAuthWitnessInput {
                secret_seed: &seed,
                ..fx.witness()
            },
        )
        .unwrap_err();
    // Fixed text: no gate or layer indices, no element values.
    assert_eq!(
        e.to_string(),
        "nymauth statement not satisfied: an in-circuit assertion failed"
    );
}

#[wasm_bindgen_test(unsupported = test)]
fn parsed_credential_is_wiped_on_drop() {
    use std::mem::ManuallyDrop;
    let mut p = ManuallyDrop::new(mdoc::Parsed {
        signed: super::super::wipe::Wiped::new(vec![5; 8], 0),
        issuer_sig: [6; 64],
        x: [7; 32],
        y: [8; 32],
    });
    // SAFETY: dropped once; the inline arrays stay valid in the ManuallyDrop storage. The Vec is
    // freed by the drop and is not read.
    unsafe { ManuallyDrop::drop(&mut p) };
    assert!(p.issuer_sig.iter().chain(&p.x).chain(&p.y).all(|&b| b == 0));
}

#[wasm_bindgen_test(unsupported = test)]
fn the_fuzz_seed_proof_is_a_valid_proof() {
    // `fuzz/seeds/nymauth/proof-seed` is 0x01 followed by the archive's proof; the fuzz target
    // verifies it against the fixture request, so it must keep verifying.
    let seed: &[u8] = include_bytes!("../../../fuzz/seeds/nymauth/proof-seed");
    assert_eq!(seed[0], 1);
    assert_eq!(&seed[1..], REFERENCE_PROOF);
}

#[wasm_bindgen_test(unsupported = test)]
fn every_credential_buffer_is_wiped_when_the_witness_builder_returns() {
    // review finding: the padded copies and the item and signed-message copies were freed
    // without wiping. The wipe counter (test-only) sums the bytes zeroed on this thread.
    let fx = Fx::load(0);
    let profile = profile::for_hash_circuit(MDOC_HASH_CIRCUIT_ID).unwrap();
    let before = wipe::WIPED_BYTES.with(|c| c.get());
    let (s, parsed) = mdoc::semantic(&fx.credential, &fx.seed, &fx.vi, &profile).unwrap();
    assert_eq!(s.len(), profile.semantic_len);
    drop((s, parsed));
    let wiped = wipe::WIPED_BYTES.with(|c| c.get()) - before;
    let expected = [
        ("signed message (Sig_structure, 7 blocks used: 423 B)", 423),
        ("birth_date item", 95),
        ("ssc item", 108),
        ("padded signed message, 7 blocks", 7 * 64),
        ("padded birth_date item, 2 blocks", 2 * 64),
        ("padded ssc item, 2 blocks", 2 * 64),
        ("padded seed, 1 block", 64),
        ("padded nym message, 2 blocks", 2 * 64),
        ("nym message", 119),
        ("semantic bits S", 96_440),
        ("issuer signature", 64),
        ("device key x and y", 64),
    ];
    let total: usize = expected.iter().map(|e| e.1).sum();
    assert_eq!(
        wiped, total,
        "bytes wiped vs. the buffers listed: {expected:?}"
    );
}
