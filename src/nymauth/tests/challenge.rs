//! The shared challenge vectors (`test-vectors/nymauth/challenge-vectors.json`, byte-identical in
//! zk-cred-vega and zk-cred-longfellow): e2 and the transcript seed per `SPEC.md` section 3.

use super::*;
use crate::nymauth::{challenge_digest, derive_challenge, verifier_input};
use serde_json::Value as Json;

fn vectors() -> Json {
    serde_json::from_str(include_str!(
        "../../../test-vectors/nymauth/challenge-vectors.json"
    ))
    .unwrap()
}

fn s(j: &Json, k: &str) -> String {
    j[k].as_str().unwrap().to_string()
}

fn thumb(j: &Json) -> Option<Vec<u8>> {
    j["jwk_thumbprint_hex"]
        .as_str()
        .map(|h| hex::decode(h).unwrap())
}

#[test]
fn derive_matches_every_shared_vector() {
    let v = vectors();
    let all = v["derive"].as_array().unwrap();
    assert!(all.len() >= 4);
    for case in all {
        let t = thumb(case);
        let c = derive_challenge(
            &s(case, "origin"),
            &s(case, "nonce"),
            &s(case, "doc_type"),
            t.as_deref(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&c.session_transcript),
            s(case, "session_transcript_hex"),
            "{}",
            s(case, "name")
        );
        assert_eq!(
            hex::encode(&c.challenge_digest),
            s(case, "challenge_digest_hex"),
            "{}",
            s(case, "name")
        );
        // the digest of the transcript alone agrees
        let d = challenge_digest(&c.session_transcript, &s(case, "doc_type")).unwrap();
        assert_eq!(hex::encode(d), s(case, "challenge_digest_hex"));
    }
}

#[test]
fn the_archive_fixture_challenge_is_what_the_fixture_signature_is_over() {
    // Verifier 1 and 2 of the fixtures: e2 and the transcript equal the ones the tests use.
    for (i, v) in [0usize, 1].into_iter().enumerate() {
        let fx = Fx::load(v);
        let case = &vectors()["derive"][i];
        let c = derive_challenge(
            &s(case, "origin"),
            &s(case, "nonce"),
            &s(case, "doc_type"),
            None,
        )
        .unwrap();
        assert_eq!(c.challenge_digest, fx.e2);
        assert_eq!(c.session_transcript, fx.transcript);
        // and verifier_input is SHA-256 of the client id in pseudonym.json
        let nym: Json = serde_json::from_str(PSEUDONYM_JSON).unwrap();
        let client_id = nym["verifiers"][v]["client_id"].as_str().unwrap();
        assert_eq!(verifier_input(client_id).unwrap(), fx.vi);
    }
}

#[test]
fn the_kotlin_fixture_transcript_gives_the_review_e2() {
    let v = vectors();
    let case = &v["digest"][0];
    let st = hex::decode(s(case, "session_transcript_hex")).unwrap();
    let d = hex::encode(challenge_digest(&st, &s(case, "doc_type")).unwrap());
    assert_eq!(d, s(case, "challenge_digest_hex"));
    assert!(d.starts_with("205f2280") && d.ends_with("d1a0"));
}

#[test]
fn every_shared_reject_vector_is_refused() {
    let v = vectors();
    let rejects = v["rejects"].as_array().unwrap();
    assert!(rejects.len() >= 8);
    for case in rejects {
        let r = match s(case, "op").as_str() {
            "derive" => {
                let t = thumb(case);
                derive_challenge(
                    &s(case, "origin"),
                    &s(case, "nonce"),
                    &s(case, "doc_type"),
                    t.as_deref(),
                )
                .map(|_| ())
            }
            "digest" => challenge_digest(
                &hex::decode(s(case, "session_transcript_hex")).unwrap(),
                &s(case, "doc_type"),
            )
            .map(|_| ()),
            other => panic!("unknown op {other}"),
        };
        assert!(
            matches!(r, Err(NymAuthError::InvalidInput(_))),
            "{} was not refused: {r:?}",
            s(case, "name")
        );
    }
    // The shortest accepted nonce is exactly min_nonce_chars.
    let min = v["min_nonce_chars"].as_u64().unwrap() as usize;
    assert_eq!(min, crate::nymauth::MIN_NONCE_CHARS);
    derive_challenge("https://verifier.example", &"a".repeat(min), "x", None).unwrap();
    assert!(verifier_input("").is_err());
}

#[test]
fn a_derived_challenge_proves_and_verifies() {
    // End to end: a verifier derives e2 and the seed itself from origin and nonce; the proof made
    // by the holder with those values verifies, and a different nonce does not.
    let fx = Fx::load(0);
    let c = derive_challenge(
        "https://verifier.example",
        "pOA0oqEAhLnqug2r7Ve4tQ",
        "eu.europa.ec.eudi.nym_auth.1",
        None,
    )
    .unwrap();
    let rq = NymAuthRequest {
        challenge_digest: &c.challenge_digest,
        transcript_seed: &c.session_transcript,
        ..fx.request()
    };
    verifier()
        .verify(&rq, &fx.pseudonym, REFERENCE_PROOF)
        .unwrap();
    let other = derive_challenge(
        "https://verifier.example",
        "pOA0oqEAhLnqug2r7Ve4tR",
        "eu.europa.ec.eudi.nym_auth.1",
        None,
    )
    .unwrap();
    let rq = NymAuthRequest {
        challenge_digest: &other.challenge_digest,
        transcript_seed: &other.session_transcript,
        ..fx.request()
    };
    assert!(
        verifier()
            .verify(&rq, &fx.pseudonym, REFERENCE_PROOF)
            .is_err()
    );
}

mod c_abi {
    use super::*;
    use crate::nymauth::c_abi::*;
    use std::ffi::{CStr, c_char};

    fn nb(b: &[u8]) -> NymAuthBytes {
        NymAuthBytes {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    #[test]
    fn challenge_helpers_through_the_c_abi() {
        let v = vectors();
        let case = &v["derive"][2]; // with a JWK thumbprint
        let (origin, nonce, doc_type) = (s(case, "origin"), s(case, "nonce"), s(case, "doc_type"));
        let t = thumb(case).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let (mut out, mut len, mut digest) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
        unsafe {
            let rc = nymauth_derive_challenge(
                nb(origin.as_bytes()),
                nb(nonce.as_bytes()),
                nb(doc_type.as_bytes()),
                nb(&t),
                &mut out,
                &mut len,
                digest.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, 0);
            let st = std::slice::from_raw_parts(out, len).to_vec();
            nymauth_free_buffer(out, len);
            assert_eq!(hex::encode(&st), s(case, "session_transcript_hex"));
            assert_eq!(hex::encode(digest), s(case, "challenge_digest_hex"));

            let mut d2 = [0u8; 32];
            assert_eq!(
                nymauth_challenge_digest(
                    nb(&st),
                    nb(doc_type.as_bytes()),
                    d2.as_mut_ptr(),
                    &mut err
                ),
                0
            );
            assert_eq!(d2, digest);

            // Refusals are statuses with a message; outputs stay untouched.
            let (mut o2, mut l2, mut d3) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
            let rc = nymauth_derive_challenge(
                nb(origin.as_bytes()),
                nb(b"short"),
                nb(doc_type.as_bytes()),
                nb(&[]),
                &mut o2,
                &mut l2,
                d3.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, -1);
            assert!(o2.is_null() && l2 == 0 && d3 == [0u8; 32]);
            assert!(
                CStr::from_ptr(err)
                    .to_string_lossy()
                    .contains("at least 16")
            );
            nymauth_free_error_string(err);
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_challenge_digest(
                    nb(&[0x83]),
                    nb(doc_type.as_bytes()),
                    d3.as_mut_ptr(),
                    &mut err
                ),
                -1
            );
            nymauth_free_error_string(err);
            assert_eq!(
                nymauth_derive_challenge(
                    nb(b"o"),
                    nb(b"n"),
                    nb(b"d"),
                    nb(&[]),
                    std::ptr::null_mut(),
                    &mut l2,
                    d3.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            let mut vi = [0u8; 32];
            assert_eq!(
                nymauth_verifier_input(
                    nb(b"x509_san_dns:verifier.example"),
                    vi.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(vi, Fx::load(0).vi);
            assert_eq!(
                nymauth_verifier_input(nb(b""), vi.as_mut_ptr(), std::ptr::null_mut()),
                -1
            );
        }
    }
}
