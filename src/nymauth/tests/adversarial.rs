//! Adversarial tests from the independent review of PR #13 (harness by the reviewer): a cheating
//! prover that skips the satisfiability gates, pseudonym/seed binding in the hash circuit, and
//! proof splicing. The harness issues credentials under its own issuer and device keys with a
//! small affine P-256 implementation.
//!
//! The cheating prover evaluates circuits through a test-only switch in `circuit.rs`
//! (`cfg(test)`, thread-local, off by default); it is not compiled into production builds.

use super::*;
use crate::circuit::Evaluation;
use crate::nymauth::{cbor, mdoc, sha};
use num_bigint::BigUint;
use std::time::Instant;

// ------------------------------------------------------------------------------------------
// mini P-256 (affine, BigUint) so the harness can issue credentials under its own keys
// ------------------------------------------------------------------------------------------
struct Ec {
    p: BigUint,
    n: BigUint,
    a: BigUint,
    g: (BigUint, BigUint),
}
type Pt = Option<(BigUint, BigUint)>;
fn bu(h: &str) -> BigUint {
    BigUint::parse_bytes(h.as_bytes(), 16).unwrap()
}
fn ec() -> Ec {
    let p = bu("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    Ec {
        a: &p - 3u8,
        n: bu("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        g: (
            bu("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            bu("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        ),
        p,
    }
}
fn inv(x: &BigUint, m: &BigUint) -> BigUint {
    x.modpow(&(m - 2u8), m)
}
fn padd(ec: &Ec, p: &Pt, q: &Pt) -> Pt {
    let pp = &ec.p;
    match (p, q) {
        (None, x) | (x, None) => x.clone(),
        (Some((x1, y1)), Some((x2, y2))) => {
            let l = if x1 == x2 {
                if (y1 + y2) % pp == BigUint::from(0u8) {
                    return None;
                }
                (BigUint::from(3u8) * x1 * x1 + &ec.a) % pp
                    * inv(&(BigUint::from(2u8) * y1 % pp), pp)
                    % pp
            } else {
                ((y2 + pp - y1) % pp) * inv(&((x2 + pp - x1) % pp), pp) % pp
            };
            let x3 = (&l * &l + pp + pp - x1 - x2) % pp;
            let y3 = (&l * ((x1 + pp - &x3) % pp) + pp - y1) % pp;
            Some((x3, y3))
        }
    }
}
fn pmul(ec: &Ec, p: &Pt, k: &BigUint) -> Pt {
    let mut acc: Pt = None;
    for i in (0..k.bits()).rev() {
        acc = padd(ec, &acc, &acc.clone());
        if k.bit(i) {
            acc = padd(ec, &acc, p);
        }
    }
    acc
}
fn be32(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(&b);
    o
}
fn pubkey(d: &BigUint) -> ([u8; 32], [u8; 32]) {
    let e = ec();
    let (x, y) = pmul(&e, &Some(e.g.clone()), d).unwrap();
    (be32(&x), be32(&y))
}
fn sign(d: &BigUint, digest: &[u8; 32]) -> [u8; 64] {
    let e = ec();
    let k = BigUint::from_bytes_be(&sha256(&[&be32(d)[..], &digest[..], b"k"].concat())) % &e.n;
    let (rx, _) = pmul(&e, &Some(e.g.clone()), &k).unwrap();
    let r = rx % &e.n;
    let z = BigUint::from_bytes_be(digest) % &e.n;
    let s = inv(&k, &e.n) * ((z + &r * d) % &e.n) % &e.n;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&be32(&r));
    out[32..].copy_from_slice(&be32(&s));
    out
}

// ------------------------------------------------------------------------------------------
// credential re-issuing under the harness's own issuer and device keys (same-length edits only)
// ------------------------------------------------------------------------------------------
struct Env {
    iss_d: BigUint,
    qx: [u8; 32],
    qy: [u8; 32],
    dev_d: BigUint,
    dx: [u8; 32],
    dy: [u8; 32],
}
fn env() -> Env {
    let iss_d = BigUint::from_bytes_be(&sha256(b"rt issuer")) % ec().n;
    let dev_d = BigUint::from_bytes_be(&sha256(b"rt device")) % ec().n;
    let (qx, qy) = pubkey(&iss_d);
    let (dx, dy) = pubkey(&dev_d);
    Env {
        iss_d,
        qx,
        qy,
        dev_d,
        dx,
        dy,
    }
}
struct Loc {
    prot: usize,
    prot_end: usize,
    pay: usize,
    pay_end: usize,
    sigc: usize,
    item: (usize, usize),
    ssc: (usize, usize),
}
fn locate(d: &[u8]) -> Loc {
    let auth = cbor::map_require(d, 0, b"issuerAuth", "a").unwrap();
    let spaces = cbor::map_require(d, 0, b"nameSpaces", "n").unwrap();
    let prot = cbor::array_item(d, auth, 0).unwrap();
    let pay = cbor::array_item(d, auth, 2).unwrap();
    let sigp = cbor::array_item(d, auth, 3).unwrap();
    let (_, _, hl) = cbor::head(d, sigp).unwrap();
    let ns = cbor::map_get(d, spaces, mdoc::DOC_TYPE.as_bytes())
        .unwrap()
        .unwrap();
    let (_, n, hl2) = cbor::head(d, ns).unwrap();
    let (mut item, mut ssc) = ((0, 0), (0, 0));
    let mut q = ns + hl2;
    for _ in 0..n {
        let e = cbor::end(d, q).unwrap();
        let (_, _, thl) = cbor::head(d, q).unwrap();
        let c = cbor::content(d, q + thl).unwrap();
        let id = cbor::map_require(c, 0, b"elementIdentifier", "e").unwrap();
        match cbor::content(c, id).unwrap() {
            b"birth_date" => item = (q, e),
            b"ssc" => ssc = (q, e),
            _ => {}
        }
        q = e;
    }
    Loc {
        prot,
        prot_end: cbor::end(d, prot).unwrap(),
        pay,
        pay_end: cbor::end(d, pay).unwrap(),
        sigc: sigp + hl,
        item,
        ssc,
    }
}
fn find(d: &[u8], pat: &[u8]) -> usize {
    let mut it = d
        .windows(pat.len())
        .enumerate()
        .filter(|(_, w)| *w == pat)
        .map(|(i, _)| i);
    let first = it.next().expect("pattern");
    assert!(it.next().is_none(), "pattern occurs twice");
    first
}
fn resign(d: &mut [u8], env: &Env) {
    let l = locate(d);
    let sig = [
        &b"\x84\x6aSignature1"[..],
        &d[l.prot..l.prot_end],
        b"\x40",
        &d[l.pay..l.pay_end],
    ]
    .concat();
    let s = sign(&env.iss_d, &sha256(&sig));
    d[l.sigc..l.sigc + 64].copy_from_slice(&s);
}
fn set_devkey(d: &mut [u8], x: &[u8; 32], y: &[u8; 32]) {
    let o = find(d, b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20");
    d[o + 18..o + 50].copy_from_slice(x);
    d[o + 53..o + 85].copy_from_slice(y);
}
/// Replaces `d[range]` content of an attribute item and fixes its digest in the MSO.
fn edit_item(d: &mut [u8], which_ssc: bool, f: &dyn Fn(&mut [u8])) {
    let l = locate(d);
    let (s, e) = if which_ssc { l.ssc } else { l.item };
    let old = [&b"\x58\x20"[..], &sha256(&d[s..e])].concat();
    f(&mut d[s..e]);
    let new = [&b"\x58\x20"[..], &sha256(&d[s..e])].concat();
    let o = find(d, &old);
    d[o..o + 34].copy_from_slice(&new);
}
fn set_date(d: &mut [u8], date: &[u8; 10]) {
    edit_item(d, false, &|it| {
        let o = find(it, b"\x6celementValue\xd9\x03\xec\x6a");
        it[o + 17..o + 27].copy_from_slice(date);
    });
}
struct Var {
    cred: Vec<u8>,
    dev_sig: [u8; 64],
}
fn variant(fx: &Fx, env: &Env, edit: &dyn Fn(&mut Vec<u8>)) -> Var {
    let mut d = fx.credential.clone();
    set_devkey(&mut d, &env.dx, &env.dy);
    edit(&mut d);
    resign(&mut d, env);
    Var {
        cred: d,
        dev_sig: sign(&env.dev_d, &fx.e2),
    }
}
fn req<'a>(fx: &'a Fx, env: &'a Env) -> NymAuthRequest<'a> {
    NymAuthRequest {
        issuer_key_x: &env.qx,
        issuer_key_y: &env.qy,
        ..fx.request()
    }
}
fn wit<'a>(fx: &'a Fx, v: &'a Var) -> NymAuthWitnessInput<'a> {
    NymAuthWitnessInput {
        issuer_signed: &v.cred,
        secret_seed: &fx.seed,
        device_signature: &v.dev_sig,
    }
}

// ------------------------------------------------------------------------------------------
// witness assembly
// ------------------------------------------------------------------------------------------
struct Base {
    h: Wiped<G>,
    s: Wiped<P>,
    msgs: [G; 6],
    a_p: [G; 6],
    pseudonym: [u8; 32],
}
fn base(
    pr: &NymAuthProver,
    rq: &NymAuthRequest,
    w: &NymAuthWitnessInput,
) -> Result<Base, NymAuthError> {
    let p = &pr.l.profile;
    let c = check(rq)?;
    let Built {
        mut h,
        mut s,
        msgs,
        pseudonym,
    } = pr.build_inputs(&c, w)?;
    let mut a_p = [G::ZERO; 6];
    for a in a_p.iter_mut() {
        *a = G::sample();
    }
    set_prover_key_shares(p, &mut h, &mut s, &a_p)?;
    let mut tags0 = [G::ZERO; 6];
    for k in 0..6 {
        tags0[k] = a_p[k] * msgs[k];
    }
    set_mac_public(p, &mut h, &mut s, &G::ZERO, &tags0)?;
    Ok(Base {
        h,
        s,
        msgs,
        a_p,
        pseudonym,
    })
}
fn zero_out<F: crate::fields::FieldElement>(r: Result<Evaluation<F>, anyhow::Error>) -> bool {
    r.map(|e| e.outputs().iter().all(|o| bool::from(o.is_zero())))
        .unwrap_or(false)
}
fn hsat(pr: &NymAuthProver, h: &[G]) -> bool {
    zero_out(pr.l.hash.evaluate(h))
}
fn sem_map(p: &Profile) -> Vec<usize> {
    let mut m = vec![usize::MAX; p.semantic_len];
    for &(slot, from, len) in &p.runs {
        for k in 0..len {
            m[from + k] = slot + k;
        }
    }
    m
}
fn msg_nym(dst: &[u8], seed: &[u8], z: &[u8], vi: &[u8]) -> Vec<u8> {
    [dst, seed, z, vi].concat()
}

// ------------------------------------------------------------------------------------------
// T0 control: own-issuer credential proves and verifies (validates harness signing + trace)
// ------------------------------------------------------------------------------------------
#[test]
fn own_issuer_credential_end_to_end() {
    let fx = Fx::load(0);
    let env = env();
    let v = variant(&fx, &env, &|_| {});
    let t = Instant::now();
    let pf = prover().prove(&req(&fx, &env), &wit(&fx, &v)).unwrap();
    verifier()
        .verify(&req(&fx, &env), &pf.pseudonym, &pf.proof)
        .unwrap();
    // and the production request with the fixture issuer key must refuse this proof
    assert!(
        verifier()
            .verify(&fx.request(), &pf.pseudonym, &pf.proof)
            .is_err()
    );
    println!(
        "RT00 ok in {:?}; proof {} bytes",
        t.elapsed(),
        pf.proof.len()
    );
}

// ------------------------------------------------------------------------------------------
// T2 pseudonym / seed binding in the hash circuit (the sybil-resistance property): patch ONLY the
// nym faces + public pseudonym; everything else (ssc commitment, credential) stays honest.
// ------------------------------------------------------------------------------------------
#[test]
fn pseudonym_is_bound_to_the_committed_seed() {
    let fx = Fx::load(0);
    let pr = prover();
    let p = &pr.l.profile;
    let b = base(pr, &fx.request(), &fx.witness()).unwrap();
    assert!(hsat(pr, &b.h), "control");
    let map = sem_map(p);
    let off_nym = (p.b_sig + p.b_item + p.b_ssc + 1) * 6656;
    let dst = mdoc::DST;
    let seed = fx.seed;
    let vi = fx.vi;
    let try_msg = |name: &str, msg: &[u8], want_sat: bool| {
        let mut out = Vec::new();
        sha::faces(msg, 2, &mut out).expect("fits 2 blocks");
        let nym = sha256(msg);
        let mut h = b.h.to_vec();
        for (i, bit) in out.iter().enumerate() {
            h[map[off_nym + i]] = hbit(*bit);
        }
        let hv = pseudonym_halves(&nym).unwrap();
        h[p.hash_npub - 2] = hv[0];
        h[p.hash_npub - 1] = hv[1];
        let s = hsat(pr, &h);
        println!(
            "  {name}: hash_sat={s} (pseudonym differs from honest: {})",
            nym != b.pseudonym
        );
        assert_eq!(s, want_sat, "{name}");
    };
    try_msg(
        "control (honest nym message)",
        &msg_nym(dst, &seed, &[0u8; 32], &vi),
        true,
    );
    let mut seed_b = seed;
    seed_b[0] ^= 0x55;
    try_msg(
        "pseudonym from a different seed (ssc commits to the original)",
        &msg_nym(dst, &seed_b, &[0u8; 32], &vi),
        false,
    );
    for i in 0..32 {
        let mut z = [0u8; 32];
        z[i] = 1;
        try_msg(
            &format!("nonzero byte {i} in the 32-byte zero field"),
            &msg_nym(dst, &seed, &z, &vi),
            false,
        );
    }
    let mut vi2 = vi;
    vi2[31] ^= 1;
    try_msg(
        "pseudonym for a different verifier_input",
        &msg_nym(dst, &seed, &[0u8; 32], &vi2),
        false,
    );
    for i in [0usize, 10, 38] {
        let mut d2 = dst.to_vec();
        d2[i] ^= 1;
        try_msg(
            &format!("DST byte {i} altered"),
            &msg_nym(&d2, &seed, &[0u8; 32], &vi),
            false,
        );
    }
    // different message lengths / shifted layout (padding enforcement)
    try_msg(
        "118-byte message (one zero byte dropped)",
        &msg_nym(dst, &seed, &[0u8; 31], &vi),
        false,
    );
    try_msg(
        "seed shifted by one byte",
        &[dst, &[0u8][..], &seed[..], &[0u8; 31][..], &vi[..]].concat(),
        false,
    );
    try_msg(
        "seed preceded by 1 extra byte, DST truncated",
        &[
            &dst[..38],
            &[0u8, 0u8][..],
            &seed[..],
            &[0u8; 32][..],
            &vi[..],
        ]
        .concat()[..119],
        false,
    );
    // whole-seed variants where the seed is a prefix/suffix of 16 zero bytes
    try_msg(
        "all-zero seed in nym only",
        &msg_nym(dst, &[0u8; 16], &[0u8; 32], &vi),
        false,
    );
}

#[test]
fn cheating_prover_with_mismatched_messages_is_refused_by_verifier() {
    let fx = Fx::load(0);
    let env = env();
    let pr = prover();
    let a = variant(&fx, &env, &|_| {});
    let young = variant(&fx, &env, &|d| set_date(d, b"2015-01-01"));
    let ba = base(pr, &req(&fx, &env), &wit(&fx, &a)).unwrap();
    let bb = base(pr, &req(&fx, &env), &wit(&fx, &young)).unwrap();
    let c = check(&req(&fx, &env)).unwrap();
    // control: the same machinery with consistent inputs verifies
    let ok = prove_unchecked(pr, &c, ba.h.to_vec(), ba.s.to_vec(), ba.a_p, ba.msgs).unwrap();
    let nym = ba.pseudonym;
    verifier().verify(&req(&fx, &env), &nym, &ok).unwrap();
    println!("RT03b control through prove_unchecked: accepted");
    // attack 1: hash side credential A, sig side credential B (signed, young); tags from A
    let mut s_b = bb.s.to_vec();
    // key shares: use the same a_p in both circuits (as the honest prover does)
    set_prover_key_shares(&pr.l.profile, &mut ba.h.to_vec(), &mut s_b, &ba.a_p).unwrap();
    for (name, tm) in [("tags from A", ba.msgs), ("tags from B", bb.msgs)] {
        let r = prove_unchecked(pr, &c, ba.h.to_vec(), s_b.clone(), ba.a_p, tm);
        match r {
            Ok(proof) => {
                let v = verifier().verify(&req(&fx, &env), &nym, &proof);
                println!(
                    "RT03b mismatched {name}: proof produced ({} B), verifier says {:?}",
                    proof.len(),
                    v.as_ref().err().map(|e| e.to_string())
                );
                assert!(v.is_err());
            }
            Err(e) => println!("RT03b mismatched {name}: prover failed: {e}"),
        }
    }
    // attack 2: false statement end-to-end: young holder, validly signed, request cutoff 2008-10-07
    let c2 = check(&req(&fx, &env)).unwrap();
    let r = prove_unchecked(pr, &c2, bb.h.to_vec(), bb.s.to_vec(), bb.a_p, bb.msgs);
    match r {
        Ok(proof) => {
            let v = verifier().verify(&req(&fx, &env), &bb.pseudonym, &proof);
            println!(
                "RT03b too-young (false) statement: proof produced ({} B); verifier: {:?}",
                proof.len(),
                v.as_ref().err().map(|e| e.to_string())
            );
            assert!(v.is_err());
        }
        Err(e) => println!("RT03b too-young: prover failed: {e}"),
    }
}

// ------------------------------------------------------------------------------------------
// T4 proof splicing / substitution across instances
// ------------------------------------------------------------------------------------------
#[test]
fn proof_splicing_is_refused() {
    let v = verifier();
    let (f0, f1) = (Fx::load(0), Fx::load(1));
    let p0 = prover().prove(&f0.request(), &f0.witness()).unwrap();
    let p0b = prover().prove(&f0.request(), &f0.witness()).unwrap();
    let p1 = prover().prove(&f1.request(), &f1.witness()).unwrap();
    let ctx = ProofContext {
        hash_circuit: &v.l.hash,
        sig_circuit: &v.l.sig,
        hash_layout: v.hash_verifier.tableau_layout(),
        sig_layout: v.sig_verifier.tableau_layout(),
    };
    let dec = |b: &[u8]| Proof::get_decoded_with_param(&ctx, b).unwrap();
    let (a, b, c) = (dec(&p0.proof), dec(&p0b.proof), dec(&p1.proof));
    // re-encode round trip is byte-identical
    assert_eq!(a.get_encoded_with_param(&ctx).unwrap(), p0.proof);
    let mk = |t: &Proof, h: &Proof, s: &Proof| Proof {
        mac_tags: t.mac_tags,
        hash_commitment: h.hash_commitment,
        hash_sumcheck: h.hash_sumcheck.clone(),
        hash_ligero: h.hash_ligero.clone(),
        sig_commitment: s.sig_commitment,
        sig_sumcheck: s.sig_sumcheck.clone(),
        sig_ligero: s.sig_ligero.clone(),
    };
    let mut n = 0;
    for (name, sp) in [
        (
            "tags0 hash0 sig0b (same request, other randomness)",
            mk(&a, &a, &b),
        ),
        ("tags0 hash0b sig0", mk(&a, &b, &a)),
        ("tags0b hash0 sig0", mk(&b, &a, &a)),
        (
            "tags0 hash0 sig1 (other instance's sig proof)",
            mk(&a, &a, &c),
        ),
        ("tags1 hash0 sig1", mk(&c, &a, &c)),
        ("tags1 hash1 sig0", mk(&c, &c, &a)),
        ("tags0 hash1 sig0", mk(&a, &c, &a)),
    ] {
        let bytes = sp.get_encoded_with_param(&ctx).unwrap();
        for (rn, f, nym) in [("req0", &f0, &p0.pseudonym), ("req1", &f1, &p1.pseudonym)] {
            let r = v.verify(&f.request(), nym, &bytes);
            println!(
                "  splice [{name}] under {rn}: {}",
                if r.is_ok() { "ACCEPTED" } else { "refused" }
            );
            assert!(r.is_err(), "{name} {rn}");
            n += 1;
        }
    }
    // cross-seed: proof for req0 with transcript seed of req1
    let r = v.verify(
        &NymAuthRequest {
            transcript_seed: &f1.transcript,
            ..f0.request()
        },
        &p0.pseudonym,
        &p0.proof,
    );
    assert!(r.is_err());
    // controls
    v.verify(&f0.request(), &p0.pseudonym, &p0.proof).unwrap();
    v.verify(&f1.request(), &p1.pseudonym, &p1.proof).unwrap();
    println!("RT04: {n} splice/verify attempts all refused; controls accepted");
}

/// prove_inner without the satisfiability gates; `tag_msgs` are the MAC messages the tags are
/// computed from after a_v is drawn from the transcript.
fn prove_unchecked(
    pr: &NymAuthProver,
    c: &Checked<'_>,
    mut h: Vec<G>,
    mut s: Vec<P>,
    a_p: [G; 6],
    tag_msgs: [G; 6],
) -> Result<Vec<u8>, String> {
    let p = &pr.l.profile;
    crate::circuit::TEST_LENIENT_EVALUATE.with(|l| l.set(true));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<Vec<u8>, anyhow::Error> {
            let hash_layout = pr.hash_prover.witness_layout().clone();
            let sig_layout = pr.sig_prover.witness_layout().clone();
            let mut rng = rand::rng();
            let mut buf = vec![0u8; G::num_bytes()];
            let hash_witness = Witness::fill_witness(hash_layout, &h[p.hash_npub..], || {
                G::sample_from_source(&mut buf, |b| rng.fill_bytes(b))
            });
            let mut buf = vec![0u8; P::num_bytes()];
            let sig_witness = Witness::fill_witness(sig_layout, &s[p.sig_npub..], || {
                P::sample_from_source(&mut buf, |b| rng.fill_bytes(b))
            });
            let mut transcript = Transcript::new(c.seed, TranscriptMode::Normal)?;
            let hash_state = pr.hash_prover.commit(&hash_witness)?;
            transcript.write_byte_array(hash_state.commitment().as_bytes())?;
            let sig_state = pr.sig_prover.commit(&sig_witness)?;
            transcript.write_byte_array(sig_state.commitment().as_bytes())?;
            let a_v: G = transcript.generate_challenge::<G>(1)?[0];
            let mut tags = [G::ZERO; 6];
            for k in 0..6 {
                tags[k] = (a_p[k] + a_v) * tag_msgs[k];
            }
            set_mac_public(p, &mut h, &mut s, &a_v, &tags).map_err(|e| anyhow::anyhow!("{e}"))?;
            let hash_eval = pr.l.hash.evaluate(&h)?;
            let sig_eval = pr.l.sig.evaluate(&s)?;
            initialize_transcript(
                &mut transcript,
                &pr.l.hash,
                hash_eval.public_inputs(p.hash_npub),
            )?;
            let ProverResult {
                proof: hash_sumcheck,
                linear_constraints: hash_lc,
            } = SumcheckProtocol::new(&pr.l.hash).prove(
                &hash_eval,
                &mut transcript,
                &hash_witness,
            )?;
            let hash_ligero = pr
                .hash_prover
                .prove(&mut transcript, &hash_state, &hash_lc)?;
            initialize_transcript(
                &mut transcript,
                &pr.l.sig,
                sig_eval.public_inputs(p.sig_npub),
            )?;
            let ProverResult {
                proof: sig_sumcheck,
                linear_constraints: sig_lc,
            } = SumcheckProtocol::new(&pr.l.sig).prove(&sig_eval, &mut transcript, &sig_witness)?;
            let sig_ligero = pr.sig_prover.prove(&mut transcript, &sig_state, &sig_lc)?;
            let proof = Proof {
                mac_tags: tags,
                hash_commitment: *hash_state.commitment(),
                hash_sumcheck,
                hash_ligero,
                sig_commitment: *sig_state.commitment(),
                sig_sumcheck,
                sig_ligero,
            };
            let ctx = ProofContext {
                hash_circuit: &pr.l.hash,
                sig_circuit: &pr.l.sig,
                hash_layout: hash_state.tableau().layout(),
                sig_layout: sig_state.tableau().layout(),
            };
            let mut out = Vec::new();
            proof.encode_with_param(&ctx, &mut out)?;
            Ok(out)
        },
    ));
    crate::circuit::TEST_LENIENT_EVALUATE.with(|l| l.set(false));
    match r {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{e:#}")),
        Err(_) => Err("PANIC".into()),
    }
}
