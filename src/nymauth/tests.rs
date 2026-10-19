// SPDX-License-Identifier: MPL-2.0

//! End-to-end tests over the credential fixtures of the `nym-auth-circuits` archive (copied to
//! `test-vectors/nymauth/`): the witness against the archive's complete input vectors, the
//! archive's own proof, and real proofs made and checked here.

use super::*;
use crate::fields::{field2_128::Field2_128, fieldp256::FieldP256};
use std::sync::OnceLock;

/// The fixture build's circuit ids (also the profile table's entry).
pub(super) const MDOC_HASH_CIRCUIT_ID: &str =
    "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729";
pub(super) const SIG_CIRCUIT_ID: &str =
    "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb";

const CIRCUITS_ZST: &[u8] = include_bytes!("../../test-vectors/nymauth/mdoc-circuits.zst");
const HASH_WITNESS_ZST: &[u8] =
    include_bytes!("../../test-vectors/nymauth/mdoc-hash-witness.bin.zst");
const SIG_WITNESS_ZST: &[u8] =
    include_bytes!("../../test-vectors/nymauth/mdoc-sig-witness.bin.zst");
const REFERENCE_PROOF: &[u8] = include_bytes!("../../test-vectors/nymauth/mdoc-proof.bin");
const CREDENTIAL_TXT: &str = include_str!("../../test-vectors/nymauth/nym-auth-mdoc.txt");
const PSEUDONYM_JSON: &str = include_str!("../../test-vectors/nymauth/pseudonym.json");
const VERIFIER_JSON: &str = include_str!("../../test-vectors/nymauth/verifier.json");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn b64url(t: &str) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut out, mut acc, mut n) = (Vec::new(), 0u32, 0u32);
    for c in t.trim().bytes() {
        acc = (acc << 6) | B64.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    out
}

fn cbor_head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=255 => vec![m | 24, n as u8],
        _ => vec![m | 25, (n >> 8) as u8, n as u8],
    }
}

fn tstr(s: &str) -> Vec<u8> {
    [cbor_head(3, s.len()), s.as_bytes().to_vec()].concat()
}

fn bstr(b: &[u8]) -> Vec<u8> {
    [cbor_head(2, b.len()), b.to_vec()].concat()
}

/// SessionTranscript and e2 for the DC API handover (SPEC.md section 3).
fn session_transcript_and_e2(origin: &str, nonce: &str) -> (Vec<u8>, [u8; 32]) {
    let info = [cbor_head(4, 3), tstr(origin), tstr(nonce), vec![0xf6]].concat();
    let st = [
        cbor_head(4, 3),
        vec![0xf6, 0xf6],
        cbor_head(4, 2),
        tstr("OpenID4VPDCAPIHandover"),
        bstr(&sha256(&info)),
    ]
    .concat();
    let auth = [
        cbor_head(4, 4),
        tstr("DeviceAuthentication"),
        st.clone(),
        tstr(mdoc::DOC_TYPE),
        cbor_head(6, 24),
        bstr(&[0xa0]),
    ]
    .concat();
    let payload = [cbor_head(6, 24), bstr(&auth)].concat();
    let msg = [
        cbor_head(4, 4),
        tstr("Signature1"),
        bstr(&[0xa1, 0x01, 0x26]),
        bstr(&[]),
        bstr(&payload),
    ]
    .concat();
    (st, sha256(&msg))
}

struct Fx {
    credential: Vec<u8>,
    seed: [u8; 16],
    qx: Vec<u8>,
    qy: Vec<u8>,
    time: String,
    earliest: String,
    cutoff: String,
    e2: [u8; 32],
    vi: [u8; 32],
    dev_sig: [u8; 64],
    transcript: Vec<u8>,
    pseudonym: [u8; 32],
}

impl Fx {
    fn load(v: usize) -> Self {
        let ver: serde_json::Value = serde_json::from_str(VERIFIER_JSON).unwrap();
        let nym: serde_json::Value = serde_json::from_str(PSEUDONYM_JSON).unwrap();
        let s = |x: &serde_json::Value| x.as_str().unwrap().to_string();
        let (qx, qy) = s(&ver["issuer_key"])
            .split_once(',')
            .map(|(a, b)| (unhex(a), unhex(b)))
            .unwrap();
        let vr = &nym["verifiers"][v];
        let (transcript, e2) = session_transcript_and_e2(&s(&vr["origin"]), &s(&vr["nonce"]));
        assert_eq!(
            e2.to_vec(),
            unhex(&s(&vr["mdoc"]["challenge_digest"])),
            "e2 derivation"
        );
        Fx {
            credential: b64url(CREDENTIAL_TXT),
            seed: unhex(&s(&nym["holder"]["secret_seed"])).try_into().unwrap(),
            qx,
            qy,
            time: s(&ver["mdoc"]["time"]),
            earliest: s(&ver["mdoc"]["earliest"]),
            cutoff: s(&ver["mdoc"]["cutoff"]),
            e2,
            vi: sha256(s(&vr["client_id"]).as_bytes()),
            dev_sig: unhex(&s(&vr["mdoc"]["device_signature"]))
                .try_into()
                .unwrap(),
            transcript,
            pseudonym: unhex(&s(&vr["pseudonym"])).try_into().unwrap(),
        }
    }

    fn request(&self) -> NymAuthRequest<'_> {
        NymAuthRequest {
            issuer_key_x: &self.qx,
            issuer_key_y: &self.qy,
            time: &self.time,
            earliest: &self.earliest,
            cutoff: &self.cutoff,
            challenge_digest: &self.e2,
            verifier_input: &self.vi,
            transcript_seed: &self.transcript,
        }
    }

    fn witness(&self) -> NymAuthWitnessInput<'_> {
        NymAuthWitnessInput {
            issuer_signed: &self.credential,
            secret_seed: &self.seed,
            device_signature: &self.dev_sig,
        }
    }
}

fn circuit() -> Vec<u8> {
    zstd::decode_all(CIRCUITS_ZST).unwrap()
}

fn params() -> NymAuthCircuitParams {
    NymAuthCircuitParams {
        block_enc_hash: 6983,
        block_enc_sig: 4679,
        hash_circuit_id: MDOC_HASH_CIRCUIT_ID.into(),
        sig_circuit_id: SIG_CIRCUIT_ID.into(),
    }
}

fn prover() -> &'static NymAuthProver {
    static P: OnceLock<NymAuthProver> = OnceLock::new();
    P.get_or_init(|| NymAuthProver::new(&circuit(), &params()).unwrap())
}

fn verifier() -> &'static NymAuthVerifier {
    static V: OnceLock<NymAuthVerifier> = OnceLock::new();
    V.get_or_init(|| NymAuthVerifier::new(&circuit(), &params()).unwrap())
}

/// One real proof for verifier 1, shared by the tests that tamper with it.
fn proof() -> &'static NymAuthProof {
    static PR: OnceLock<NymAuthProof> = OnceLock::new();
    PR.get_or_init(|| {
        let fx = Fx::load(0);
        prover().prove(&fx.request(), &fx.witness()).unwrap()
    })
}

// ---------------------------------------------------------------------------------------------
// The witness against the archive's complete input vectors
// ---------------------------------------------------------------------------------------------

#[test]
fn witness_matches_the_archive_input_vectors() {
    let fx = Fx::load(0);
    let pr = prover();
    let p = &pr.l.profile;
    let c = check(&fx.request()).unwrap();
    let Built {
        mut h,
        mut s,
        msgs,
        pseudonym,
    } = pr.build_inputs(&c, &fx.witness()).unwrap();
    assert_eq!(pseudonym, fx.pseudonym);

    let hw = zstd::decode_all(HASH_WITNESS_ZST).unwrap();
    let sw = zstd::decode_all(SIG_WITNESS_ZST).unwrap();
    assert_eq!(hw.len(), 16 * p.hash_ninputs);
    assert_eq!(sw.len(), 32 * p.sig_ninputs);

    // The archive's vectors use a_p,k = k + 1 and its a_v; the tags follow.
    let a_p: [Field2_128; 6] = std::array::from_fn(|k| Field2_128::from_u128(k as u128 + 1));
    let a_v = Field2_128::try_from(&hw[16 * (p.hash_npub - 3)..16 * (p.hash_npub - 2)]).unwrap();
    set_prover_key_shares(p, &mut h, &mut s, &a_p).unwrap();
    let tags: [Field2_128; 6] = std::array::from_fn(|k| (a_p[k] + a_v) * msgs[k]);
    set_mac_public(p, &mut h, &mut s, &a_v, &tags).unwrap();

    let enc = |e: &Field2_128| {
        let mut b = [0u8; 16];
        crate::Codec::encode(e, &mut &mut b[..]).unwrap();
        b
    };
    let bad_h = h
        .iter()
        .enumerate()
        .filter(|(i, e)| enc(e)[..] != hw[16 * i..16 * i + 16])
        .count();
    let bad_s = s
        .iter()
        .enumerate()
        .filter(|(i, e)| ecdsa::fe_le(e)[..] != sw[32 * i..32 * i + 32])
        .count();
    assert_eq!((bad_h, bad_s), (0, 0));
}

#[test]
fn archive_vectors_satisfy_both_circuits() {
    let pr = prover();
    let hw = zstd::decode_all(HASH_WITNESS_ZST).unwrap();
    let sw = zstd::decode_all(SIG_WITNESS_ZST).unwrap();
    let h: Vec<Field2_128> = hw
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| Field2_128::try_from(&c[..]).unwrap())
        .collect();
    let s: Vec<FieldP256> = sw
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| FieldP256::try_from(c).unwrap())
        .collect();
    pr.evaluate_satisfied(&h, &s).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Cross-implementation: the archive's proof, made by Google's runtime
// ---------------------------------------------------------------------------------------------

#[test]
fn the_archive_proof_verifies() {
    let fx = Fx::load(0);
    verifier()
        .verify(&fx.request(), &fx.pseudonym, REFERENCE_PROOF)
        .unwrap();
}

#[test]
fn the_archive_proof_is_refused_for_another_verifier_or_pseudonym() {
    let fx = Fx::load(0);
    let other = Fx::load(1);
    // Another verifier's request, with that verifier's own pseudonym.
    assert!(
        verifier()
            .verify(&other.request(), &other.pseudonym, REFERENCE_PROOF)
            .is_err()
    );
    // The right request with another verifier's pseudonym.
    assert!(
        verifier()
            .verify(&fx.request(), &other.pseudonym, REFERENCE_PROOF)
            .is_err()
    );
}

// ---------------------------------------------------------------------------------------------
// Our own proofs
// ---------------------------------------------------------------------------------------------

#[test]
fn a_real_proof_verifies_and_reports_the_fixture_pseudonym() {
    let fx = Fx::load(0);
    let pf = proof();
    assert_eq!(pf.pseudonym, fx.pseudonym);
    // The reference proof is 343,748 bytes; ours is larger (see docs/NYMAUTH.md) but bounded.
    assert!(
        pf.proof.len() < 2 * REFERENCE_PROOF.len(),
        "proof of {} bytes",
        pf.proof.len()
    );
    verifier()
        .verify(&fx.request(), &pf.pseudonym, &pf.proof)
        .unwrap();
}

#[test]
fn the_second_verifier_gets_the_second_pseudonym() {
    let fx = Fx::load(1);
    let pf = prover().prove(&fx.request(), &fx.witness()).unwrap();
    assert_eq!(pf.pseudonym, fx.pseudonym);
    verifier()
        .verify(&fx.request(), &pf.pseudonym, &pf.proof)
        .unwrap();
}

#[test]
fn proofs_are_randomized() {
    let fx = Fx::load(0);
    let a = proof();
    let b = prover().prove(&fx.request(), &fx.witness()).unwrap();
    assert_ne!(a.proof, b.proof);
    assert_eq!(a.pseudonym, b.pseudonym);
}

#[test]
fn verification_refuses_tampered_proofs_and_requests() {
    let fx = Fx::load(0);
    let pf = proof();
    let ok =
        |req: &NymAuthRequest<'_>, nym: &[u8], proof: &[u8]| verifier().verify(req, nym, proof);

    // One flipped bit anywhere in the proof, including the tags at the front.
    for at in [0usize, 100, pf.proof.len() / 2, pf.proof.len() - 1] {
        let mut bad = pf.proof.clone();
        bad[at] ^= 1;
        assert!(
            ok(&fx.request(), &pf.pseudonym, &bad).is_err(),
            "flip at {at}"
        );
    }
    // Truncated or extended.
    assert!(
        ok(
            &fx.request(),
            &pf.pseudonym,
            &pf.proof[..pf.proof.len() - 1]
        )
        .is_err()
    );
    assert!(
        ok(
            &fx.request(),
            &pf.pseudonym,
            &[&pf.proof[..], &[0u8][..]].concat()
        )
        .is_err()
    );

    // A different pseudonym.
    let mut nym = pf.pseudonym;
    nym[0] ^= 1;
    assert!(ok(&fx.request(), &nym, &pf.proof).is_err());

    // A different verifier input.
    let mut vi = fx.vi;
    vi[0] ^= 1;
    assert!(
        ok(
            &NymAuthRequest {
                verifier_input: &vi,
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );

    // A different issuer key (the generator, which is on the curve).
    let gx = unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let gy = unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    assert!(
        ok(
            &NymAuthRequest {
                issuer_key_x: &gx,
                issuer_key_y: &gy,
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );

    // A different challenge digest, time, bounds and transcript.
    let mut e2 = fx.e2;
    e2[31] ^= 1;
    assert!(
        ok(
            &NymAuthRequest {
                challenge_digest: &e2,
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );
    assert!(
        ok(
            &NymAuthRequest {
                time: "2026-10-08T12:00:00Z",
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );
    assert!(
        ok(
            &NymAuthRequest {
                cutoff: "2008-10-08",
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );
    assert!(
        ok(
            &NymAuthRequest {
                earliest: "1900-01-01",
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );
    assert!(
        ok(
            &NymAuthRequest {
                transcript_seed: b"another transcript, long enough to pass the floor",
                ..fx.request()
            },
            &pf.pseudonym,
            &pf.proof
        )
        .is_err()
    );

    // And the untampered inputs still verify.
    ok(&fx.request(), &pf.pseudonym, &pf.proof).unwrap();
}

// ---------------------------------------------------------------------------------------------
// The prover refuses false statements, before it commits to anything
// ---------------------------------------------------------------------------------------------

fn unsatisfied(r: Result<NymAuthProof, NymAuthError>) {
    match r {
        Err(NymAuthError::Unsatisfied(_)) => {}
        other => panic!(
            "expected Unsatisfied, got {:?}",
            other.map(|p| p.proof.len())
        ),
    }
}

#[test]
fn prover_refuses_a_wrong_seed() {
    let fx = Fx::load(0);
    let mut seed = fx.seed;
    seed[0] ^= 1;
    unsatisfied(prover().prove(
        &fx.request(),
        &NymAuthWitnessInput {
            secret_seed: &seed,
            ..fx.witness()
        },
    ));
}

#[test]
fn prover_refuses_a_wrong_issuer_key() {
    let fx = Fx::load(0);
    let gx = unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let gy = unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    unsatisfied(prover().prove(
        &NymAuthRequest {
            issuer_key_x: &gx,
            issuer_key_y: &gy,
            ..fx.request()
        },
        &fx.witness(),
    ));
}

#[test]
fn prover_refuses_a_wrong_device_signature_or_challenge() {
    let fx = Fx::load(0);
    let mut sig = fx.dev_sig;
    sig[40] ^= 1;
    unsatisfied(prover().prove(
        &fx.request(),
        &NymAuthWitnessInput {
            device_signature: &sig,
            ..fx.witness()
        },
    ));
    let mut e2 = fx.e2;
    e2[0] ^= 1;
    unsatisfied(prover().prove(
        &NymAuthRequest {
            challenge_digest: &e2,
            ..fx.request()
        },
        &fx.witness(),
    ));
}

#[test]
fn prover_refuses_a_tampered_credential() {
    let fx = Fx::load(0);
    // Flip a byte inside the signed MSO: the issuer signature no longer verifies.
    let mut cred = fx.credential.clone();
    let at = cred.windows(9).position(|w| w == b"validFrom").unwrap() + 20;
    cred[at] ^= 1;
    let r = prover().prove(
        &fx.request(),
        &NymAuthWitnessInput {
            issuer_signed: &cred,
            ..fx.witness()
        },
    );
    assert!(matches!(
        r,
        Err(NymAuthError::Unsatisfied(_)) | Err(NymAuthError::Credential(_))
    ));
}

#[test]
fn prover_refuses_a_request_the_credential_does_not_meet() {
    let fx = Fx::load(0);
    // Valid until 2036 or so, but not valid yet in 2000.
    unsatisfied(prover().prove(
        &NymAuthRequest {
            time: "2000-01-01T00:00:00Z",
            ..fx.request()
        },
        &fx.witness(),
    ));
    // Born after the cutoff.
    unsatisfied(prover().prove(
        &NymAuthRequest {
            cutoff: "1900-01-01",
            ..fx.request()
        },
        &fx.witness(),
    ));
    // Born before the earliest allowed date.
    unsatisfied(prover().prove(
        &NymAuthRequest {
            earliest: "9000-01-01",
            cutoff: "9999-12-31",
            ..fx.request()
        },
        &fx.witness(),
    ));
}

#[test]
fn malformed_inputs_are_typed_errors_not_panics() {
    let fx = Fx::load(0);
    let pr = prover();
    let bad_len = |r: Result<NymAuthProof, NymAuthError>| {
        assert!(matches!(r, Err(NymAuthError::InvalidInput(_))))
    };
    bad_len(pr.prove(
        &fx.request(),
        &NymAuthWitnessInput {
            secret_seed: &fx.seed[..15],
            ..fx.witness()
        },
    ));
    bad_len(pr.prove(
        &fx.request(),
        &NymAuthWitnessInput {
            device_signature: &fx.dev_sig[..63],
            ..fx.witness()
        },
    ));
    bad_len(pr.prove(
        &NymAuthRequest {
            time: "2026-10-07",
            ..fx.request()
        },
        &fx.witness(),
    ));
    bad_len(pr.prove(
        &NymAuthRequest {
            issuer_key_x: &fx.qx[..31],
            ..fx.request()
        },
        &fx.witness(),
    ));
    bad_len(pr.prove(
        &NymAuthRequest {
            verifier_input: &fx.vi[..31],
            ..fx.request()
        },
        &fx.witness(),
    ));

    // Every prefix and a few mutations of the credential are an error, never a panic.
    for n in [0usize, 1, 5, 100, 500, fx.credential.len() - 1] {
        let r = pr.prove(
            &fx.request(),
            &NymAuthWitnessInput {
                issuer_signed: &fx.credential[..n],
                ..fx.witness()
            },
        );
        assert!(
            matches!(r, Err(NymAuthError::Credential(_))),
            "prefix {n}: {:?}",
            r.err()
        );
    }
    for fill in [0x00u8, 0xff, 0x9f] {
        let r = pr.prove(
            &fx.request(),
            &NymAuthWitnessInput {
                issuer_signed: &[fill; 64],
                ..fx.witness()
            },
        );
        assert!(r.is_err());
    }

    // Garbage proofs.
    for proof in [&[][..], &[0u8; 10][..], &[0xffu8; 4000][..]] {
        assert!(
            verifier()
                .verify(&fx.request(), &fx.pseudonym, proof)
                .is_err()
        );
    }
    assert!(matches!(
        verifier().verify(&fx.request(), &fx.pseudonym[..31], REFERENCE_PROOF),
        Err(NymAuthError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Circuit loading
// ---------------------------------------------------------------------------------------------

#[test]
fn circuit_ids_and_parameters_are_checked() {
    let c = circuit();
    let with = |f: &dyn Fn(&mut NymAuthCircuitParams)| {
        let mut p = params();
        f(&mut p);
        NymAuthVerifier::new(&c, &p).err()
    };
    assert!(matches!(
        with(&|p| p.hash_circuit_id = "00".repeat(32)),
        Some(NymAuthError::UnsupportedCircuit(_))
    ));
    assert!(matches!(
        with(&|p| p.sig_circuit_id = "00".repeat(32)),
        Some(NymAuthError::Circuit(_))
    ));
    assert!(matches!(
        with(&|p| p.block_enc_hash = 10),
        Some(NymAuthError::Circuit(_))
    ));
    assert!(matches!(
        with(&|p| p.block_enc_sig = 0),
        Some(NymAuthError::Circuit(_))
    ));
    // The pair in the wrong order, truncated, or with trailing bytes.
    assert!(NymAuthVerifier::new(&c[..c.len() - 1], &params()).is_err());
    assert!(NymAuthVerifier::new(&[c.clone(), vec![0]].concat(), &params()).is_err());
    assert!(NymAuthVerifier::new(&[], &params()).is_err());
    // The generic mdoc circuits are not nym_auth circuits.
    let other = zstd::decode_all(
        &include_bytes!("../../test-vectors/mdoc_zk/7_1_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121")[..],
    )
    .unwrap();
    assert!(matches!(
        NymAuthVerifier::new(&other, &params()).err(),
        Some(NymAuthError::Circuit(_))
    ));
}

#[test]
fn circuit_id_of_the_artifact_is_the_published_one() {
    let l = load(&circuit(), &params()).unwrap();
    assert_eq!(
        hex::encode(l.hash.circuit_id().unwrap().0),
        MDOC_HASH_CIRCUIT_ID
    );
    assert_eq!(hex::encode(l.sig.circuit_id().unwrap().0), SIG_CIRCUIT_ID);
}

// ---------------------------------------------------------------------------------------------
// The C ABI
// ---------------------------------------------------------------------------------------------

mod c_abi_tests {
    use super::*;
    use crate::nymauth::c_abi::*;
    use std::ffi::{CStr, c_char};

    fn nb(b: &[u8]) -> NymAuthBytes {
        NymAuthBytes {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn creq(fx: &Fx) -> NymAuthCRequest {
        NymAuthCRequest {
            issuer_key_x: nb(&fx.qx),
            issuer_key_y: nb(&fx.qy),
            time: nb(fx.time.as_bytes()),
            earliest: nb(fx.earliest.as_bytes()),
            cutoff: nb(fx.cutoff.as_bytes()),
            challenge_digest: nb(&fx.e2),
            verifier_input: nb(&fx.vi),
            transcript_seed: nb(&fx.transcript),
        }
    }

    fn cparams(hash_id: &str) -> NymAuthCParams {
        NymAuthCParams {
            block_enc_hash: 6983,
            block_enc_sig: 4679,
            hash_circuit_id: nb(hash_id.as_bytes()),
            sig_circuit_id: nb(SIG_CIRCUIT_ID.as_bytes()),
        }
    }

    unsafe fn take_error(e: *mut c_char) -> Option<String> {
        if e.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned();
        unsafe { nymauth_free_error_string(e) };
        Some(s)
    }

    #[test]
    fn prove_and_verify_through_the_c_abi() {
        let fx = Fx::load(0);
        let circuit = circuit();
        let mut err: *mut c_char = std::ptr::null_mut();
        unsafe {
            let p = nymauth_prover_new(nb(&circuit), &cparams(MDOC_HASH_CIRCUIT_ID), &mut err);
            assert!(!p.is_null(), "{:?}", take_error(err));
            let v = nymauth_verifier_new(nb(&circuit), &cparams(MDOC_HASH_CIRCUIT_ID), &mut err);
            assert!(!v.is_null());

            let wit = |seed: &[u8]| NymAuthCWitness {
                issuer_signed: nb(&fx.credential),
                secret_seed: nb(seed),
                device_signature: nb(&fx.dev_sig),
            };
            let (mut proof, mut len, mut nym) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
            let rc = nymauth_prove(
                p,
                &creq(&fx),
                &wit(&fx.seed),
                &mut proof,
                &mut len,
                nym.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, 0, "{:?}", take_error(err));
            assert_eq!(nym, fx.pseudonym);
            let pbytes = std::slice::from_raw_parts(proof, len).to_vec();
            nymauth_free_buffer(proof, len);

            assert_eq!(
                nymauth_verify(v, &creq(&fx), nb(&nym), nb(&pbytes), &mut err),
                0
            );
            let mut bad = pbytes.clone();
            let n = bad.len() / 2;
            bad[n] ^= 1;
            assert_eq!(
                nymauth_verify(v, &creq(&fx), nb(&nym), nb(&bad), &mut err),
                -7
            );
            assert!(take_error(err).is_some());
            err = std::ptr::null_mut();

            // A wrong seed is refused with the "not satisfied" status and writes no output.
            let mut wrong = fx.seed;
            wrong[3] ^= 0x80;
            let (mut proof2, mut len2, mut nym2) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
            let rc = nymauth_prove(
                p,
                &creq(&fx),
                &wit(&wrong),
                &mut proof2,
                &mut len2,
                nym2.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, -5);
            assert!(proof2.is_null() && len2 == 0 && nym2 == [0u8; 32]);
            assert!(take_error(err).unwrap().contains("not satisfied"));
            err = std::ptr::null_mut();

            // Null arguments and bad lengths are statuses, not crashes.
            let rc = nymauth_prove(
                std::ptr::null(),
                &creq(&fx),
                &wit(&fx.seed),
                &mut proof2,
                &mut len2,
                nym2.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, -1);
            take_error(err);
            err = std::ptr::null_mut();
            let rc = nymauth_prove(
                p,
                &creq(&fx),
                &wit(&fx.seed[..4]),
                &mut proof2,
                &mut len2,
                nym2.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, -1);
            take_error(err);
            err = std::ptr::null_mut();
            // A transcript seed under the floor is refused by both entry points.
            let short = NymAuthCRequest {
                transcript_seed: nb(b"short"),
                ..creq(&fx)
            };
            assert_eq!(
                nymauth_verify(v, &short, nb(&nym), nb(&pbytes), std::ptr::null_mut()),
                -1
            );
            assert_eq!(
                nymauth_prove(
                    p,
                    &short,
                    &wit(&fx.seed),
                    &mut proof2,
                    &mut len2,
                    nym2.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            let nullbytes = NymAuthBytes {
                ptr: std::ptr::null(),
                len: 5,
            };
            let rc = nymauth_verify(v, &creq(&fx), nullbytes, nb(&pbytes), &mut err);
            assert_eq!(rc, -1);
            take_error(err);
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_verify(
                    std::ptr::null(),
                    &creq(&fx),
                    nb(&nym),
                    nb(&pbytes),
                    std::ptr::null_mut()
                ),
                -1
            );

            // An unknown circuit id: null handle and a message.
            let bad_id = "00".repeat(32);
            let p2 = nymauth_prover_new(nb(&circuit), &cparams(&bad_id), &mut err);
            assert!(p2.is_null());
            assert!(take_error(err).unwrap().contains("unsupported circuit"));
            assert!(
                nymauth_prover_new(
                    nb(&[]),
                    &cparams(MDOC_HASH_CIRCUIT_ID),
                    std::ptr::null_mut()
                )
                .is_null()
            );

            assert_eq!(
                nymauth_prove(
                    p,
                    std::ptr::null(),
                    &wit(&fx.seed),
                    &mut proof2,
                    &mut len2,
                    nym2.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_verify(
                    v,
                    std::ptr::null(),
                    nb(&nym),
                    nb(&pbytes),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert!(
                nymauth_verifier_new(nb(&circuit), std::ptr::null(), std::ptr::null_mut())
                    .is_null()
            );

            nymauth_prover_free(p);
            nymauth_verifier_free(v);
            nymauth_prover_free(std::ptr::null_mut());
            nymauth_free_buffer(std::ptr::null_mut(), 0);
        }
    }
}

#[cfg(feature = "uniffi")]
mod uniffi_tests {
    use super::*;
    use crate::nymauth::ffi_uniffi::{
        NymAuthCircuitParams as FfiParams, NymAuthProveRequest, NymAuthVerifyRequest,
        nymauth_initialize_prover, nymauth_initialize_verifier, nymauth_prove, nymauth_verify,
    };

    #[test]
    fn prove_and_verify_through_the_uniffi_surface() {
        let fx = Fx::load(0);
        let params = || FfiParams {
            block_enc_hash: 6983,
            block_enc_sig: 4679,
            hash_circuit_id: MDOC_HASH_CIRCUIT_ID.into(),
            sig_circuit_id: SIG_CIRCUIT_ID.into(),
        };
        let p = nymauth_initialize_prover(&circuit(), params()).unwrap();
        let v = nymauth_initialize_verifier(&circuit(), params()).unwrap();
        let req = |seed: Vec<u8>| NymAuthProveRequest {
            issuer_signed: fx.credential.clone(),
            secret_seed: seed,
            issuer_key_x: fx.qx.clone(),
            issuer_key_y: fx.qy.clone(),
            time: fx.time.clone(),
            earliest: fx.earliest.clone(),
            cutoff: fx.cutoff.clone(),
            challenge_digest: fx.e2.to_vec(),
            device_signature: fx.dev_sig.to_vec(),
            verifier_input: fx.vi.to_vec(),
            transcript_seed: fx.transcript.clone(),
        };
        let r = nymauth_prove(&p, req(fx.seed.to_vec())).unwrap();
        assert_eq!(r.pseudonym, fx.pseudonym);
        let vreq = |proof: Vec<u8>, pseudonym: Vec<u8>| NymAuthVerifyRequest {
            issuer_key_x: fx.qx.clone(),
            issuer_key_y: fx.qy.clone(),
            time: fx.time.clone(),
            earliest: fx.earliest.clone(),
            cutoff: fx.cutoff.clone(),
            challenge_digest: fx.e2.to_vec(),
            verifier_input: fx.vi.to_vec(),
            transcript_seed: fx.transcript.clone(),
            pseudonym,
            proof,
        };
        nymauth_verify(&v, vreq(r.proof.clone(), r.pseudonym.clone())).unwrap();
        let mut bad = r.proof.clone();
        bad[1000] ^= 1;
        assert!(nymauth_verify(&v, vreq(bad, r.pseudonym.clone())).is_err());
        let mut seed = fx.seed.to_vec();
        seed[0] ^= 1;
        assert!(matches!(
            nymauth_prove(&p, req(seed)),
            Err(NymAuthError::Unsatisfied(_))
        ));
    }
}

#[test]
fn wiped_buffers_are_zeroed_on_drop() {
    use std::mem::ManuallyDrop;
    let mut s = ManuallyDrop::new(wipe::SecretArray([0xa5u8; 16]));
    // SAFETY: dropped once; the storage is owned by the ManuallyDrop and still valid to read.
    unsafe { ManuallyDrop::drop(&mut s) };
    assert_eq!(s.0, [0u8; 16]);
}

/// `cargo test --release --lib nymauth::tests::measure -- --ignored --nocapture`
#[test]
#[ignore = "timing only"]
fn measure_load_prove_verify() {
    use std::time::Instant;
    let fx = Fx::load(0);
    let c = circuit();
    let t = Instant::now();
    let p = NymAuthProver::new(&c, &params()).unwrap();
    println!("prover load   {:?}", t.elapsed());
    let t = Instant::now();
    let v = NymAuthVerifier::new(&c, &params()).unwrap();
    println!("verifier load {:?}", t.elapsed());
    for i in 0..3 {
        let t = Instant::now();
        let pf = p.prove(&fx.request(), &fx.witness()).unwrap();
        let prove = t.elapsed();
        let t = Instant::now();
        v.verify(&fx.request(), &pf.pseudonym, &pf.proof).unwrap();
        println!(
            "run {i}: prove {prove:?}  verify {:?}  proof {} bytes",
            t.elapsed(),
            pf.proof.len()
        );
    }
}

/// Writes a real proof for the reference verifier: `NYMAUTH_DUMP=/path cargo test --release
/// --lib nymauth::tests::dump -- --ignored`.
#[test]
#[ignore = "writes a file"]
fn dump_proof_for_the_reference_verifier() {
    let fx = Fx::load(0);
    let pf = prover().prove(&fx.request(), &fx.witness()).unwrap();
    let path = std::env::var("NYMAUTH_DUMP").unwrap();
    std::fs::write(&path, &pf.proof).unwrap();
    println!("{}", hex::encode(pf.pseudonym));
}

#[cfg(test)]
mod adversarial;

#[cfg(test)]
mod hardening;

#[cfg(test)]
mod challenge;

/// Fixtures for the Go cgo smoke test (`go-cabi-smoketest/nymauth`):
/// `cargo test --release --lib nymauth::tests::dump_go -- --ignored` (or `make go-cabi-nymauth-fixture`).
#[test]
#[ignore = "writes files for the Go smoke test"]
fn dump_go_smoke_fixture() {
    let fx = Fx::load(0);
    let pf = prover().prove(&fx.request(), &fx.witness()).unwrap();
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/go-cabi/testdata-nymauth");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("circuit.bin"), circuit()).unwrap();
    std::fs::write(dir.join("proof.bin"), &pf.proof).unwrap();
    let p = params();
    let json = serde_json::json!({
        "hash_circuit_id": p.hash_circuit_id,
        "sig_circuit_id": p.sig_circuit_id,
        "block_enc_hash": p.block_enc_hash,
        "block_enc_sig": p.block_enc_sig,
        "issuer_key_x": hex::encode(&fx.qx),
        "issuer_key_y": hex::encode(&fx.qy),
        "time": fx.time,
        "earliest": fx.earliest,
        "cutoff": fx.cutoff,
        "origin": "https://verifier.example",
        "nonce": "pOA0oqEAhLnqug2r7Ve4tQ",
        "doc_type": "eu.europa.ec.eudi.nym_auth.1",
        "client_id": "x509_san_dns:verifier.example",
        "pseudonym": hex::encode(pf.pseudonym),
        "challenge_digest": hex::encode(fx.e2),
        "session_transcript": hex::encode(&fx.transcript),
        "verifier_input": hex::encode(fx.vi),
    });
    std::fs::write(
        dir.join("fixture.json"),
        serde_json::to_vec_pretty(&json).unwrap(),
    )
    .unwrap();
    println!("wrote {}", dir.display());
}
