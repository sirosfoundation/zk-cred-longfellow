//! Tests for the failure modes and validation paths of the nymauth module that the end-to-end
//! tests do not reach: malformed LFC2 circuits, malformed CBOR credentials, circuit loading
//! checks, curve-point validation, error text, and the unsatisfied-output gates. Every test
//! asserts the specific refusal.

use super::*;
use crate::nymauth::{cbor, ecdsa, lfc2, mdoc, profile};
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------------------------
// LFC2 reader
// ---------------------------------------------------------------------------------------------

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

/// (logw, nw, deltas (g, h0, h1, k), segments, tokens)
type LfcLayer = (u32, u32, Vec<[u32; 4]>, Vec<Vec<u32>>, Vec<u32>);

struct Lc {
    fid: u32,
    nv: u32,
    nc: u32,
    npub: u32,
    nin: u32,
    nconst: u32,
    layer: Option<LfcLayer>,
}

impl Lc {
    fn ok() -> Self {
        Lc {
            fid: 1,
            nv: 1,
            nc: 1,
            npub: 1,
            nin: 2,
            nconst: 1,
            layer: Some((1, 2, vec![[0, 0, 0, 0]], vec![vec![0]], vec![0])),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut o = b"LFC2".to_vec();
        let nl = u32::from(self.layer.is_some());
        for v in [
            self.fid,
            self.nv,
            self.nc,
            self.npub,
            self.nin,
            self.nin,
            nl,
            self.nconst,
        ] {
            uleb(v, &mut o);
        }
        let elt = if self.fid == 4 { 16 } else { 32 };
        o.extend(std::iter::repeat_n(1u8, elt * self.nconst as usize));
        if let Some((logw, nw, deltas, segs, toks)) = &self.layer {
            uleb(*logw, &mut o);
            uleb(*nw, &mut o);
            uleb(deltas.len() as u32, &mut o);
            for d in deltas {
                d.iter().for_each(|v| uleb(*v, &mut o));
            }
            uleb(segs.len() as u32, &mut o);
            for s in segs {
                uleb(s.len() as u32, &mut o);
                s.iter().for_each(|v| uleb(*v, &mut o));
            }
            uleb(toks.len() as u32, &mut o);
            toks.iter().for_each(|v| uleb(*v, &mut o));
        }
        o.extend_from_slice(&[0u8; 32]);
        o
    }
}

fn lfc2_err(bytes: &[u8]) -> String {
    match lfc2::one(bytes) {
        Err(NymAuthError::Circuit(m)) => m,
        other => panic!(
            "expected a Circuit error, got {:?}",
            other.map(|(v, n)| (v.len(), n))
        ),
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn lfc2_minimal_circuit_converts() {
    let b = Lc::ok().bytes();
    let (legacy, used) = lfc2::one(&b).unwrap();
    assert_eq!(used, b.len());
    // version byte, three-byte sizes, one term: 1 + 3*8 header, 32 constant, 3*4 + 12 term, 32 id
    assert_eq!(legacy[0], 1);
    assert_eq!(legacy.len(), 1 + 24 + 32 + 9 + 12 + 32);
    // GF(2^128) circuits use 16-byte constants
    let g = Lc { fid: 4, ..Lc::ok() }.bytes();
    assert_eq!(lfc2::one(&g).unwrap().0.len(), legacy.len() - 16);
}

#[wasm_bindgen_test(unsupported = test)]
fn lfc2_malformed_circuits_are_refused_with_the_right_reason() {
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("no header", b"LFC1....".to_vec(), "missing LFC2 header"),
        (
            "unsupported field",
            Lc { fid: 7, ..Lc::ok() }.bytes(),
            "unsupported field id 7",
        ),
        (
            "two copies",
            Lc { nc: 2, ..Lc::ok() }.bytes(),
            "only one copy",
        ),
        (
            "more public than inputs",
            Lc {
                npub: 3,
                ..Lc::ok()
            }
            .bytes(),
            "more public inputs",
        ),
        (
            "excessive outputs",
            Lc {
                nv: 6_000_000,
                ..Lc::ok()
            }
            .bytes(),
            "excessive output count",
        ),
        (
            "constant index out of range",
            Lc {
                layer: Some((1, 2, vec![[0, 0, 0, 5]], vec![vec![0]], vec![0])),
                ..Lc::ok()
            }
            .bytes(),
            "constant index",
        ),
        (
            "delta index out of range",
            Lc {
                layer: Some((1, 2, vec![[0, 0, 0, 0]], vec![vec![3]], vec![0])),
                ..Lc::ok()
            }
            .bytes(),
            "delta index",
        ),
        (
            "token out of range",
            Lc {
                layer: Some((1, 2, vec![[0, 0, 0, 0]], vec![vec![0]], vec![4])),
                ..Lc::ok()
            }
            .bytes(),
            "token out of range",
        ),
        (
            "wire index too large for the legacy layout",
            Lc {
                layer: Some((1, 2, vec![[1 << 25, 0, 0, 0]], vec![vec![0]], vec![0])),
                ..Lc::ok()
            }
            .bytes(),
            "three-byte",
        ),
    ];
    for (name, bytes, want) in cases {
        let m = lfc2_err(&bytes);
        assert!(m.contains(want), "{name}: {m}");
    }
    // A ULEB128 of five bytes, and truncation anywhere in a good circuit.
    let mut long = b"LFC2".to_vec();
    long.extend_from_slice(&[0x81, 0x80, 0x80, 0x80, 0x01]);
    assert!(lfc2_err(&long).contains("longer than four bytes"));
    let good = Lc::ok().bytes();
    for n in 0..good.len() {
        assert!(lfc2::one(&good[..n]).is_err(), "prefix {n}");
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn lfc2_term_and_output_budgets() {
    // 30,000 tokens of a 1,000-term segment: 30 M terms, over the term limit.
    let big = |ntok: usize| Lc {
        layer: Some((1, 2, vec![[0, 0, 0, 0]], vec![vec![0; 1000]], vec![0; ntok])),
        ..Lc::ok()
    };
    assert!(lfc2_err(&big(30_000).bytes()).contains("too many terms"));
    // Two circuits that are each within the budget (about 20 MB) but over it together.
    let two = [
        big(1700).bytes(),
        Lc {
            fid: 4,
            ..big(1700)
        }
        .bytes(),
    ]
    .concat();
    let e = lfc2::to_legacy_pair(&two).unwrap_err();
    assert!(e.to_string().contains("size limit"), "{e}");
    // A single circuit over the budget by itself.
    let e = lfc2::to_legacy_pair(&big(4000).bytes()).unwrap_err();
    assert!(e.to_string().contains("size limit"), "{e}");
}

// ---------------------------------------------------------------------------------------------
// Circuit loading checks that the pin normally makes unreachable (decode_pair is the second line)
// ---------------------------------------------------------------------------------------------

fn profile_of_fixture() -> profile::Profile {
    profile::for_hash_circuit(MDOC_HASH_CIRCUIT_ID).unwrap()
}

#[wasm_bindgen_test(unsupported = test)]
fn decode_pair_checks_everything_itself() {
    let legacy = lfc2::to_legacy_pair(&circuit()).unwrap();
    decode_pair(&legacy, &params(), profile_of_fixture()).unwrap();
    // trailing bytes, truncation, garbage
    let with = |l: &[u8], p: NymAuthCircuitParams, pr: profile::Profile| {
        decode_pair(l, &p, pr)
            .err()
            .expect("must be refused")
            .to_string()
    };
    let e = with(
        &[&legacy[..], &[0u8][..]].concat(),
        params(),
        profile_of_fixture(),
    );
    assert!(e.contains("left over"), "{e}");
    assert!(with(&legacy[..legacy.len() / 2], params(), profile_of_fixture()).contains("circuit"));
    assert!(with(&[1u8; 40], params(), profile_of_fixture()).contains("signature circuit"));
    // the descriptor's ids must be the recomputed ids
    let p = NymAuthCircuitParams {
        sig_circuit_id: "00".repeat(32),
        ..params()
    };
    assert!(with(&legacy, p, profile_of_fixture()).contains("descriptor's circuit ids"));
    let p = NymAuthCircuitParams {
        hash_circuit_id: "00".repeat(32),
        ..params()
    };
    assert!(with(&legacy, p, profile_of_fixture()).contains("descriptor's circuit ids"));
    // the input counts must be the profile's
    for tweak in [
        |p: &mut profile::Profile| p.hash_ninputs += 1,
        |p: &mut profile::Profile| p.hash_npub += 1,
        |p: &mut profile::Profile| p.sig_ninputs += 1,
        |p: &mut profile::Profile| p.sig_npub += 1,
    ] {
        let mut pr = profile_of_fixture();
        tweak(&mut pr);
        assert!(with(&legacy, params(), pr).contains("input counts"));
    }
    // and the Ligero widths must be usable
    let mut pr = profile_of_fixture();
    pr.block_enc_hash = 10;
    assert!(with(&legacy, params(), pr).contains("Ligero width"));
}

#[wasm_bindgen_test(unsupported = test)]
fn ligero_widths_are_bounded() {
    for bad in [0usize, 1, 9 * 132 + 7, (1 << 22) + 1] {
        assert!(
            matches!(ligero_parameters(bad), Err(NymAuthError::Circuit(_))),
            "{bad}"
        );
    }
    let p = ligero_parameters(6983).unwrap();
    assert_eq!(
        (p.block_size, p.witnesses_per_row, p.num_columns),
        (776, 644, 6983)
    );
}

// ---------------------------------------------------------------------------------------------
// Request validation: calendar edge cases
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn calendar_validation_edge_cases() {
    let fx = Fx::load(0);
    let ok_time = |t: &str| {
        check(&NymAuthRequest {
            time: t,
            ..fx.request()
        })
        .is_ok()
    };
    let ok_cutoff = |c: &str| {
        check(&NymAuthRequest {
            cutoff: c,
            ..fx.request()
        })
        .is_ok()
    };
    // thirty-day months
    for (m, last) in [(4, 30), (6, 30), (9, 30), (11, 30), (1, 31), (12, 31)] {
        assert!(ok_cutoff(&format!("2020-{m:02}-{last:02}")), "{m}-{last}");
    }
    for m in [4, 6, 9, 11] {
        assert!(!ok_cutoff(&format!("2020-{m:02}-31")), "{m}-31");
    }
    assert!(ok_cutoff("2000-02-29") && ok_cutoff("2024-02-29"));
    assert!(!ok_cutoff("1900-02-29") && !ok_cutoff("2023-02-29") && !ok_cutoff("2023-02-30"));
    // digits only, in every position
    assert!(!ok_cutoff("2o20-01-01") && !ok_cutoff("2020-0a-01") && !ok_cutoff("2020-01-0b"));
    assert!(!ok_time("2026-10-07T1a:00:00Z") && !ok_time("2026-10-07T12:0b:00Z"));
    assert!(!ok_time("2026-10-07T12:00:0cZ") && !ok_time("2026-10-07T12-00:00Z"));
    assert!(ok_time("2026-10-07T23:59:59Z") && ok_time("2026-10-07T00:00:00Z"));
}

// ---------------------------------------------------------------------------------------------
// The issuer key must be a point of P-256, at prove and at verify (review finding)
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn issuer_key_must_be_on_the_curve_at_prove_and_verify() {
    let fx = Fx::load(0);
    let be = |hex: &str| hex::decode(hex).unwrap();
    let p = be("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    let mut y_off = fx.qy.clone();
    y_off[31] ^= 1;
    let mut p_plus_x = p.clone();
    p_plus_x[31] = 0x00; // p - 255: below p, but an arbitrary x
    let zero = vec![0u8; 32];
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("(0, 0)", zero.clone(), zero.clone()),
        ("y off by one", fx.qx.clone(), y_off),
        ("x = p", p.clone(), fx.qy.clone()),
        ("y = p", fx.qx.clone(), p.clone()),
        ("both above p", vec![0xff; 32], vec![0xff; 32]),
        ("arbitrary pair", p_plus_x, fx.qy.clone()),
    ];
    for (name, x, y) in cases {
        let rq = NymAuthRequest {
            issuer_key_x: &x,
            issuer_key_y: &y,
            ..fx.request()
        };
        assert!(
            matches!(
                verifier().verify(&rq, &fx.pseudonym, REFERENCE_PROOF),
                Err(NymAuthError::InvalidInput(_))
            ),
            "verify {name}"
        );
        assert!(
            matches!(
                prover().prove(&rq, &fx.witness()),
                Err(NymAuthError::InvalidInput(_))
            ),
            "prove {name}"
        );
    }
    // the genuine key is accepted by validation
    ecdsa::validate_public_key(
        &fx.qx.clone().try_into().unwrap(),
        &fx.qy.clone().try_into().unwrap(),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------------------------
// ECDSA trace failure modes
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn ecdsa_trace_refuses_bad_signatures() {
    let fx = Fx::load(0);
    let (qx, qy): ([u8; 32], [u8; 32]) = (
        fx.qx.clone().try_into().unwrap(),
        fx.qy.clone().try_into().unwrap(),
    );
    let d = [7u8; 32];
    let n =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
    let one = {
        let mut o = [0u8; 32];
        o[31] = 1;
        o
    };
    let n: [u8; 32] = n.try_into().unwrap();
    let unsat = |r: Result<Vec<_>, NymAuthError>| match r {
        Err(NymAuthError::Unsatisfied(m)) => m,
        other => panic!("expected Unsatisfied, got {:?}", other.map(|v| v.len())),
    };
    assert!(unsat(ecdsa::verification(&qx, &qy, &d, &[0; 32], &one)).contains("out of range"));
    assert!(unsat(ecdsa::verification(&qx, &qy, &d, &one, &[0; 32])).contains("out of range"));
    assert!(unsat(ecdsa::verification(&qx, &qy, &d, &n, &one)).contains("out of range"));
    assert!(unsat(ecdsa::verification(&qx, &qy, &d, &one, &n)).contains("out of range"));
    let mut off = qy;
    off[0] ^= 1;
    assert!(unsat(ecdsa::verification(&qx, &off, &d, &one, &one)).contains("not on the curve"));
    // a random (r, s) does not verify
    assert!(unsat(ecdsa::verification(&qx, &qy, &d, &one, &one)).contains("does not verify"));
    // R is the identity when the key is -G and e = r: u1 G + u2 (-G) = 0
    let gx =
        hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").unwrap();
    let gy =
        hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
    let p = num_bigint::BigUint::from_bytes_be(
        &hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff").unwrap(),
    );
    let neg_gy = &p - num_bigint::BigUint::from_bytes_be(&gy);
    let mut ngy = [0u8; 32];
    let b = neg_gy.to_bytes_be();
    ngy[32 - b.len()..].copy_from_slice(&b);
    let (gx, _): ([u8; 32], ()) = (gx.try_into().unwrap(), ());
    let mut r = [0u8; 32];
    r[31] = 5;
    assert!(unsat(ecdsa::verification(&gx, &ngy, &r, &r, &one)).contains("identity"));
}

// ---------------------------------------------------------------------------------------------
// CBOR walker and credential parsing
// ---------------------------------------------------------------------------------------------

fn head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=255 => vec![m | 24, n as u8],
        _ => vec![m | 25, (n >> 8) as u8, n as u8],
    }
}
fn tstr(s: &str) -> Vec<u8> {
    [head(3, s.len()), s.as_bytes().to_vec()].concat()
}
fn bstr(b: &[u8]) -> Vec<u8> {
    [head(2, b.len()), b.to_vec()].concat()
}
fn arr(items: &[Vec<u8>]) -> Vec<u8> {
    [head(4, items.len()), items.concat()].concat()
}
fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut o = head(5, pairs.len());
    for (k, v) in pairs {
        o.extend_from_slice(k);
        o.extend_from_slice(v);
    }
    o
}
fn item(id: &str) -> Vec<u8> {
    let inner = map(&[
        (tstr("elementIdentifier"), tstr(id)),
        (tstr("elementValue"), tstr("x")),
    ]);
    [head(6, 24), bstr(&inner)].concat()
}

/// An IssuerSigned-shaped document with the given payload and namespace value.
fn doc(payload: &[u8], sig: &[u8], ns_value: Vec<u8>) -> Vec<u8> {
    map(&[
        (tstr("nameSpaces"), map(&[(tstr(mdoc::DOC_TYPE), ns_value)])),
        (
            tstr("issuerAuth"),
            arr(&[
                bstr(&[0xa1, 0x01, 0x26]),
                map(&[]),
                bstr(payload),
                bstr(sig),
            ]),
        ),
    ])
}

fn semantic_err(d: &[u8]) -> String {
    let fx = Fx::load(0);
    match mdoc::semantic(d, &fx.seed, &fx.vi, &profile_of_fixture()) {
        Err(NymAuthError::Credential(m)) => m,
        Err(e) => panic!("expected Credential, got {e}"),
        Ok(_) => panic!("expected a refusal"),
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn credential_structure_errors_are_specific() {
    let sig = [0u8; 64];
    let two = arr(&[item("birth_date"), item("ssc")]);
    // namespace is a map, not an array
    assert!(semantic_err(&doc(b"p", &sig, map(&[]))).contains("not an array"));
    // an unrelated attribute is skipped, then the wanted ones are missing
    let m = semantic_err(&doc(b"p", &sig, arr(&[item("family_name")])));
    assert!(m.contains("birth_date attribute is missing"), "{m}");
    let m = semantic_err(&doc(
        b"p",
        &sig,
        arr(&[item("birth_date"), item("family_name")]),
    ));
    assert!(m.contains("ssc attribute is missing"), "{m}");
    // signature of the wrong size
    assert!(semantic_err(&doc(b"p", &sig[..63], two.clone())).contains("not 64 bytes"));
    // a signed message that does not fit its seven blocks
    let m = semantic_err(&doc(&[7u8; 600], &sig, two.clone()));
    assert!(m.contains("does not fit 7 blocks"), "{m}");
    // an attribute item that does not fit its two blocks
    let big = [
        head(6, 24),
        bstr(&map(&[
            (tstr("elementIdentifier"), tstr("birth_date")),
            (tstr("elementValue"), tstr(&"v".repeat(200))),
        ])),
    ]
    .concat();
    let m = semantic_err(&doc(b"p", &sig, arr(&[big, item("ssc")])));
    assert!(
        m.contains("birth_date item") && m.contains("does not fit"),
        "{m}"
    );
    // all present and sized, but the signed message has none of the fields: a window is missing
    let m = semantic_err(&doc(b"p", &sig, two));
    assert!(m.contains("not found"), "{m}");
    // missing top-level keys
    assert!(semantic_err(&map(&[])).contains("issuerAuth is missing"));
    assert!(
        semantic_err(&map(&[(tstr("issuerAuth"), arr(&[]))])).contains("nameSpaces is missing")
    );
}

#[wasm_bindgen_test(unsupported = test)]
fn cbor_walker_refuses_malformed_items() {
    // depth
    let mut deep = vec![0x81u8; 20];
    deep.push(0x00);
    assert!(
        cbor::end(&deep, 0)
            .unwrap_err()
            .to_string()
            .contains("too deeply")
    );
    assert_eq!(cbor::end(&[0x81, 0x00], 0).unwrap(), 2);
    // wrong major types for the accessors
    assert!(
        cbor::content(&[0x01], 0)
            .unwrap_err()
            .to_string()
            .contains("expected a CBOR string")
    );
    assert!(
        cbor::array_item(&[0xa0], 0, 0)
            .unwrap_err()
            .to_string()
            .contains("expected a CBOR array")
    );
    assert!(
        cbor::array_item(&[0x80], 0, 0)
            .unwrap_err()
            .to_string()
            .contains("too short")
    );
    assert!(
        cbor::array_item(&[0x81, 0x00], 0, 1)
            .unwrap_err()
            .to_string()
            .contains("too short")
    );
    assert_eq!(cbor::array_item(&[0x82, 0x00, 0x01], 0, 1).unwrap(), 2);
    assert!(
        cbor::map_get(&[0x80], 0, b"k")
            .unwrap_err()
            .to_string()
            .contains("expected a CBOR map")
    );
    // keys: found, not found, non-string key skipped
    let m = [0xa2, 0x00, 0x01, 0x61, b'k', 0x02];
    assert_eq!(cbor::map_get(&m, 0, b"k").unwrap(), Some(5));
    assert_eq!(cbor::map_get(&m, 0, b"z").unwrap(), None);
    assert!(
        cbor::map_require(&m, 0, b"z", "z")
            .unwrap_err()
            .to_string()
            .contains("z is missing")
    );
    // text strings must be UTF-8; the long form of a simple value below 32 is not well-formed
    assert!(
        cbor::end(&[0x61, 0xff], 0)
            .unwrap_err()
            .to_string()
            .contains("UTF-8")
    );
    assert_eq!(cbor::end(&[0x62, 0xc3, 0xa9], 0).unwrap(), 3);
    for bad in [[0xf8u8, 0x00], [0xf8, 0x18], [0xf8, 0x1f]] {
        let e = cbor::end(&bad, 0).unwrap_err().to_string();
        assert!(e.contains("non-canonical"), "{bad:?}: {e}");
    }
    assert_eq!(cbor::end(&[0xf8, 0x20], 0).unwrap(), 2);
    assert_eq!(cbor::end(&[0xf6], 0).unwrap(), 1);
    // truncation and indefinite lengths
    assert!(cbor::head(&[], 0).is_err());
    assert!(cbor::head(&[0x19, 0x01], 0).is_err());
    assert!(
        cbor::head(&[0x5f], 0)
            .unwrap_err()
            .to_string()
            .contains("indefinite")
    );
    assert!(cbor::end(&[0x62, b'a'], 0).is_err());
    assert!(cbor::end(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0).is_err());
    assert!(cbor::end(&[0x84, 0x00], 0).is_err());
    // search helpers
    assert_eq!(cbor::find(b"abcabc", b"ca"), Some(2));
    assert_eq!(cbor::find(b"abc", b""), None);
    assert_eq!(cbor::find(b"ab", b"abc"), None);
    assert!(
        cbor::found(b"abc", b"z", "thing")
            .unwrap_err()
            .to_string()
            .contains("thing not found")
    );
}

// ---------------------------------------------------------------------------------------------
// The unsatisfied-output gates and the slot-map length check of the prover
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn prover_refuses_a_slot_map_that_does_not_match_its_bits() {
    let fx = Fx::load(0);
    let mut pr = NymAuthProver::new(&circuit(), &params()).unwrap();
    pr.l.profile.semantic_len += 1;
    let e = pr.prove(&fx.request(), &fx.witness()).unwrap_err();
    assert!(
        matches!(&e, NymAuthError::Credential(m) if m.contains("slot map")),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// Error text, challenge helper limits
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen_test(unsupported = test)]
fn every_error_variant_has_its_own_prefix() {
    let all = [
        (
            NymAuthError::InvalidInput("a".into()),
            "nymauth invalid input: a",
        ),
        (NymAuthError::Circuit("a".into()), "nymauth circuit: a"),
        (
            NymAuthError::UnsupportedCircuit("a".into()),
            "nymauth unsupported circuit: a",
        ),
        (
            NymAuthError::Credential("a".into()),
            "nymauth credential: a",
        ),
        (
            NymAuthError::Unsatisfied("a".into()),
            "nymauth statement not satisfied: a",
        ),
        (NymAuthError::Prover("a".into()), "nymauth prover: a"),
        (
            NymAuthError::Verification("a".into()),
            "nymauth verification failed: a",
        ),
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
    }
}

#[wasm_bindgen_test(unsupported = test)]
fn challenge_helper_limits_and_long_fields() {
    use crate::nymauth::derive_challenge;
    let nonce = "n".repeat(16);
    // a field over the 4096-byte limit
    for (o, n, d) in [
        ("o".repeat(4097), nonce.clone(), "d".to_string()),
        ("o".to_string(), "n".repeat(4097), "d".to_string()),
        ("o".to_string(), nonce.clone(), "d".repeat(4097)),
    ] {
        let e = derive_challenge(&o, &n, &d, None).unwrap_err();
        assert!(e.to_string().contains("longer than 4096"), "{e}");
    }
    // lengths of 24, 256 and 4096 bytes use the one-, two- and the two-byte CBOR length heads,
    // and give distinct, stable transcripts
    let mut seen = std::collections::HashSet::new();
    for len in [23usize, 24, 255, 256, 4096] {
        let c = derive_challenge(&"o".repeat(len), &nonce, "d", None).unwrap();
        assert!(seen.insert(c.session_transcript.clone()));
        assert_eq!(c.challenge_digest.len(), 32);
        // the digest of the transcript alone agrees
        let d = crate::nymauth::challenge_digest(&c.session_transcript, "d").unwrap();
        assert_eq!(d.to_vec(), c.challenge_digest);
    }
    // 16 multi-byte characters satisfy the character floor, 15 do not
    assert!(derive_challenge("o", &"é".repeat(16), "d", None).is_ok());
    assert!(derive_challenge("o", &"é".repeat(15), "d", None).is_err());
}

// ---------------------------------------------------------------------------------------------
// C ABI: statuses and argument validation not reached by the round-trip test
// ---------------------------------------------------------------------------------------------

mod c_abi_validation {
    use super::*;
    use crate::nymauth::c_abi::*;
    use std::ffi::{CStr, c_char};

    fn nb(b: &[u8]) -> NymAuthBytes {
        NymAuthBytes {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    unsafe fn message(e: *mut c_char) -> String {
        assert!(!e.is_null(), "an error message was expected");
        let s = unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned();
        unsafe { nymauth_free_error_string(e) };
        s
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn a_malformed_credential_has_status_minus_4() {
        let fx = Fx::load(0);
        let circuit = circuit();
        let id = |s: &str| nb(s.as_bytes());
        let params = NymAuthCParams {
            block_enc_hash: 6983,
            block_enc_sig: 4679,
            hash_circuit_id: id(MDOC_HASH_CIRCUIT_ID),
            sig_circuit_id: id(SIG_CIRCUIT_ID),
        };
        let rq = NymAuthCRequest {
            issuer_key_x: nb(&fx.qx),
            issuer_key_y: nb(&fx.qy),
            time: nb(fx.time.as_bytes()),
            earliest: nb(fx.earliest.as_bytes()),
            cutoff: nb(fx.cutoff.as_bytes()),
            challenge_digest: nb(&fx.e2),
            verifier_input: nb(&fx.vi),
            transcript_seed: nb(&fx.transcript),
        };
        let garbage = [0xffu8; 40];
        let w = NymAuthCWitness {
            issuer_signed: nb(&garbage),
            secret_seed: nb(&fx.seed),
            device_signature: nb(&fx.dev_sig),
        };
        unsafe {
            let mut err: *mut c_char = std::ptr::null_mut();
            let p = nymauth_prover_new(nb(&circuit), &params, &mut err);
            assert!(!p.is_null());
            let (mut out, mut len, mut nym) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
            let rc = nymauth_prove(p, &rq, &w, &mut out, &mut len, nym.as_mut_ptr(), &mut err);
            assert_eq!(rc, -4);
            assert!(message(err).starts_with("nymauth credential"));
            assert!(out.is_null() && len == 0 && nym == [0u8; 32]);
            // a pointer that is null with a length is an input error, not a crash
            let bad = NymAuthCWitness {
                issuer_signed: NymAuthBytes {
                    ptr: std::ptr::null(),
                    len: 3,
                },
                ..w
            };
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_prove(p, &rq, &bad, &mut out, &mut len, nym.as_mut_ptr(), &mut err),
                -1
            );
            assert!(message(err).contains("null pointer"));
            // text that is not UTF-8
            let bad_time = NymAuthCRequest {
                time: nb(&[0xff; 20]),
                ..rq
            };
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_prove(
                    p,
                    &bad_time,
                    &w,
                    &mut out,
                    &mut len,
                    nym.as_mut_ptr(),
                    &mut err
                ),
                -1
            );
            assert!(message(err).contains("not UTF-8"));
            // null output pointers
            assert_eq!(
                nymauth_prove(
                    p,
                    &rq,
                    &w,
                    std::ptr::null_mut(),
                    &mut len,
                    nym.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_prove(
                    p,
                    &rq,
                    &w,
                    &mut out,
                    std::ptr::null_mut(),
                    nym.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_prove(
                    p,
                    &rq,
                    &w,
                    &mut out,
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_prove(
                    p,
                    std::ptr::null(),
                    &w,
                    &mut out,
                    &mut len,
                    nym.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_prove(
                    p,
                    &rq,
                    std::ptr::null(),
                    &mut out,
                    &mut len,
                    nym.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                -1
            );
            nymauth_prover_free(p);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn the_c_verifier_refuses_an_issuer_key_off_the_curve() {
        let fx = Fx::load(0);
        let circuit = circuit();
        let params = NymAuthCParams {
            block_enc_hash: 6983,
            block_enc_sig: 4679,
            hash_circuit_id: nb(MDOC_HASH_CIRCUIT_ID.as_bytes()),
            sig_circuit_id: nb(SIG_CIRCUIT_ID.as_bytes()),
        };
        let request = |x: &[u8], y: &[u8]| NymAuthCRequest {
            issuer_key_x: nb(x),
            issuer_key_y: nb(y),
            time: nb(fx.time.as_bytes()),
            earliest: nb(fx.earliest.as_bytes()),
            cutoff: nb(fx.cutoff.as_bytes()),
            challenge_digest: nb(&fx.e2),
            verifier_input: nb(&fx.vi),
            transcript_seed: nb(&fx.transcript),
        };
        let mut y_off = fx.qy.clone();
        y_off[31] ^= 1;
        let p_mod = hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
            .unwrap();
        unsafe {
            let mut err: *mut c_char = std::ptr::null_mut();
            let v = nymauth_verifier_new(nb(&circuit), &params, &mut err);
            assert!(!v.is_null());
            // positive control: the genuine key and the archive's proof are accepted
            let ok = request(&fx.qx, &fx.qy);
            assert_eq!(
                nymauth_verify(v, &ok, nb(&fx.pseudonym), nb(REFERENCE_PROOF), &mut err),
                0
            );
            for (name, x, y) in [
                ("off the curve", fx.qx.clone(), y_off),
                ("(0, 0)", vec![0; 32], vec![0; 32]),
                ("x = p", p_mod.clone(), fx.qy.clone()),
                ("y = p", fx.qx.clone(), p_mod.clone()),
            ] {
                let bad = request(&x, &y);
                err = std::ptr::null_mut();
                let rc = nymauth_verify(v, &bad, nb(&fx.pseudonym), nb(REFERENCE_PROOF), &mut err);
                assert_eq!(rc, -1, "{name}");
                assert!(message(err).starts_with("nymauth invalid input"), "{name}");
            }
            nymauth_verifier_free(v);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn challenge_entry_points_validate_their_arguments() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let (mut out, mut len, mut digest) = (std::ptr::null_mut(), 0usize, [0u8; 32]);
        let (o, n, d) = (
            b"https://verifier.example",
            b"pOA0oqEAhLnqug2r7Ve4tQ",
            b"doc",
        );
        let nullp = NymAuthBytes {
            ptr: std::ptr::null(),
            len: 4,
        };
        unsafe {
            // null output pointers
            let args = |out: *mut *mut u8, len: *mut usize, dg: *mut u8| {
                nymauth_derive_challenge(
                    nb(o),
                    nb(n),
                    nb(d),
                    nb(&[]),
                    out,
                    len,
                    dg,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(
                args(std::ptr::null_mut(), &mut len, digest.as_mut_ptr()),
                -1
            );
            assert_eq!(
                args(&mut out, std::ptr::null_mut(), digest.as_mut_ptr()),
                -1
            );
            assert_eq!(args(&mut out, &mut len, std::ptr::null_mut()), -1);
            // null pointer with a length, for each input; and non-UTF-8 text
            for (i, bad) in [nullp, nullp, nullp, nullp].into_iter().enumerate() {
                let mut a = [nb(o), nb(n), nb(d), nb(&[])];
                a[i] = bad;
                let rc = nymauth_derive_challenge(
                    a[0],
                    a[1],
                    a[2],
                    a[3],
                    &mut out,
                    &mut len,
                    digest.as_mut_ptr(),
                    &mut err,
                );
                assert_eq!(rc, -1, "argument {i}");
                assert!(message(err).contains("null pointer"));
                err = std::ptr::null_mut();
            }
            let rc = nymauth_derive_challenge(
                nb(&[0xff]),
                nb(n),
                nb(d),
                nb(&[]),
                &mut out,
                &mut len,
                digest.as_mut_ptr(),
                &mut err,
            );
            assert_eq!(rc, -1);
            assert!(message(err).contains("not UTF-8"));
            err = std::ptr::null_mut();
            // challenge_digest and verifier_input
            assert_eq!(
                nymauth_challenge_digest(
                    nb(&[0x83, 0xf6, 0xf6, 0xf6]),
                    nb(d),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(
                nymauth_challenge_digest(nullp, nb(d), digest.as_mut_ptr(), &mut err),
                -1
            );
            assert!(message(err).contains("null pointer"));
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_challenge_digest(
                    nb(&[0x83, 0xf6, 0xf6, 0xf6]),
                    nb(&[0xff]),
                    digest.as_mut_ptr(),
                    &mut err
                ),
                -1
            );
            assert!(message(err).contains("not UTF-8"));
            err = std::ptr::null_mut();
            assert_eq!(
                nymauth_verifier_input(nb(b"x"), std::ptr::null_mut(), std::ptr::null_mut()),
                -1
            );
            assert_eq!(
                nymauth_verifier_input(nullp, digest.as_mut_ptr(), &mut err),
                -1
            );
            assert!(message(err).contains("null pointer"));
            // a valid call still works after all of that
            let mut ok = [0u8; 32];
            assert_eq!(
                nymauth_verifier_input(
                    nb(b"x509_san_dns:verifier.example"),
                    ok.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(ok, Fx::load(0).vi);
        }
    }
}

#[cfg(feature = "uniffi")]
mod uniffi_challenge {
    use super::*;
    use crate::nymauth::ffi_uniffi::{
        nymauth_challenge_digest, nymauth_derive_challenge, nymauth_verifier_input,
    };

    #[wasm_bindgen_test(unsupported = test)]
    fn the_uniffi_challenge_exports_match_the_core() {
        let c = nymauth_derive_challenge(
            "https://verifier.example".into(),
            "pOA0oqEAhLnqug2r7Ve4tQ".into(),
            "eu.europa.ec.eudi.nym_auth.1".into(),
            None,
        )
        .unwrap();
        let fx = Fx::load(0);
        assert_eq!(c.session_transcript, fx.transcript);
        assert_eq!(c.challenge_digest, fx.e2.to_vec());
        let d = nymauth_challenge_digest(
            c.session_transcript.clone(),
            "eu.europa.ec.eudi.nym_auth.1".into(),
        )
        .unwrap();
        assert_eq!(d, c.challenge_digest);
        assert_eq!(
            nymauth_verifier_input("x509_san_dns:verifier.example".into()).unwrap(),
            fx.vi.to_vec()
        );
        // thumbprint accepted at 32 bytes only; refusals are typed errors
        assert!(
            nymauth_derive_challenge("o".into(), "n".repeat(16), "d".into(), Some(vec![1; 32]))
                .is_ok()
        );
        assert!(matches!(
            nymauth_derive_challenge("o".into(), "n".repeat(16), "d".into(), Some(vec![1; 31])),
            Err(NymAuthError::InvalidInput(_))
        ));
        assert!(matches!(
            nymauth_challenge_digest(vec![], "d".into()),
            Err(NymAuthError::InvalidInput(_))
        ));
        assert!(matches!(
            nymauth_verifier_input(String::new()),
            Err(NymAuthError::InvalidInput(_))
        ));
    }
}
