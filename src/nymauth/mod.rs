//! The `nymauth` prover and verifier: the two-circuit Longfellow proof for the nym_auth mdoc
//! circuits of the `nym-auth-circuits` archive (SPEC.md sections L3 to L6).
//!
//! This is a separate module from [`crate::mdoc_zk`]: the nym_auth circuits have their own
//! statement (issuer signature, type, birth-date range, validity, device signature on a challenge
//! digest, `ssc = SHA-256(secret_seed)` and the pseudonym), their own input layout and their own
//! witness builder. Only the proving-system primitives (circuits, sumcheck, Ligero, transcript,
//! proof codecs) are shared with the generic mdoc prover.
//!
//! What a caller needs:
//!
//! * [`NymAuthProver::new`] / [`NymAuthVerifier::new`] load the decompressed circuit artifact (the
//!   signature circuit, then the hash circuit, as the catalog serves them) together with the
//!   catalog descriptor's parameters.
//! * [`NymAuthProver::prove`] builds both witnesses from the IssuerSigned CBOR, the secret seed,
//!   the issuer key, the verifier's request values and the device signature, then proves. It
//!   returns the proof and the pseudonym.
//! * [`NymAuthVerifier::verify`] checks a proof against the verifier's own request.
//!
//! SD-JWT VC nym_auth circuits are not supported; their hash circuit has a different input layout
//! and is refused as an unknown circuit id.

mod cbor;
mod ecdsa;
mod error;
mod lfc2;
mod mdoc;
mod profile;
mod sha;
#[cfg(test)]
mod tests;
mod wipe;

pub mod c_abi;
#[cfg(feature = "uniffi")]
pub mod ffi_uniffi;

pub use error::NymAuthError;
pub use profile::{MDOC_HASH_CIRCUIT_ID, SIG_CIRCUIT_ID};

use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    ligero::{
        LigeroParameters,
        merkle::Root,
        prover::{LigeroProof, LigeroProver},
        tableau::TableauLayout,
        verifier::LigeroVerifier,
    },
    sumcheck::{ProverResult, SumcheckProof, SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
    witness::Witness,
};
use profile::Profile;
use rand::RngCore;
use sha::sha256;
use std::{
    io::{Cursor, Write},
    panic::{AssertUnwindSafe, catch_unwind},
};
use wipe::Wiped;

const LIGERO_RATE_INV: usize = 7;
const LIGERO_NREQ: usize = 132;
/// Bytes of T, E and C: `YYYY-MM-DDThh:mm:ssZ`, `YYYY-MM-DD`, `YYYY-MM-DD`.
const TIME_LEN: usize = 20;
const DATE_LEN: usize = 10;

type G = Field2_128;
type P = FieldP256;

/// The catalog descriptor's parameters of a `longfellow-nymauth` circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NymAuthCircuitParams {
    /// Ligero `block_enc` of the hash circuit (catalog `block_enc_hash`).
    pub block_enc_hash: usize,
    /// Ligero `block_enc` of the signature circuit (catalog `block_enc_sig`).
    pub block_enc_sig: usize,
    /// Hex circuit id of the hash circuit (catalog `hash_circuit_id`).
    pub hash_circuit_id: String,
    /// Hex circuit id of the signature circuit (catalog `sig_circuit_id`).
    pub sig_circuit_id: String,
}

/// The values both sides know: the verifier's request and the bound issuer key.
#[derive(Debug, Clone, Copy)]
pub struct NymAuthRequest<'a> {
    /// Issuer key Q, x then y, big-endian, 32 bytes each.
    pub issuer_key_x: &'a [u8],
    pub issuer_key_y: &'a [u8],
    /// `T`: `YYYY-MM-DDThh:mm:ssZ`.
    pub time: &'a str,
    /// `E`: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
    pub earliest: &'a str,
    /// `C`: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
    pub cutoff: &'a str,
    /// `e2`: SHA-256 of the COSE message the device key signed.
    pub challenge_digest: &'a [u8],
    /// `SHA-256(verifier_id)`.
    pub verifier_input: &'a [u8],
    /// The Fiat-Shamir seed both sides bind the proof to (the SessionTranscript).
    pub transcript_seed: &'a [u8],
}

/// The holder's private inputs.
pub struct NymAuthWitnessInput<'a> {
    /// The credential's IssuerSigned structure as CBOR.
    pub issuer_signed: &'a [u8],
    /// The 16-byte secret seed. The prover copies it, uses the copy and zeroes the copy; the
    /// caller owns, and should zero, its own buffer.
    pub secret_seed: &'a [u8],
    /// The device key's ES256 signature on the challenge message: `r || s`.
    pub device_signature: &'a [u8],
}

/// A proof and the pseudonym it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NymAuthProof {
    /// The proof, in the layout of Google's `MdocProof::write`.
    pub proof: Vec<u8>,
    /// `SHA-256(DST || secret_seed || 0x00*32 || verifier_input)`.
    pub pseudonym: [u8; 32],
}

fn invalid(m: impl Into<String>) -> NymAuthError {
    NymAuthError::InvalidInput(m.into())
}

fn array<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N], NymAuthError> {
    b.try_into()
        .map_err(|_| invalid(format!("{what} must be {N} bytes, got {}", b.len())))
}

/// A request with its sizes checked.
struct Checked<'a> {
    qx: [u8; 32],
    qy: [u8; 32],
    t: &'a [u8],
    e: &'a [u8],
    c: &'a [u8],
    e2: [u8; 32],
    vi: [u8; 32],
    seed: &'a [u8],
}

fn check<'a>(r: &NymAuthRequest<'a>) -> Result<Checked<'a>, NymAuthError> {
    if r.time.len() != TIME_LEN || !r.time.is_ascii() {
        return Err(invalid("time must be 20 ASCII characters"));
    }
    for (n, v) in [("earliest", r.earliest), ("cutoff", r.cutoff)] {
        if v.len() != DATE_LEN || !v.is_ascii() {
            return Err(invalid(format!("{n} must be 10 ASCII characters")));
        }
    }
    Ok(Checked {
        qx: array(r.issuer_key_x, "issuer_key_x")?,
        qy: array(r.issuer_key_y, "issuer_key_y")?,
        t: r.time.as_bytes(),
        e: r.earliest.as_bytes(),
        c: r.cutoff.as_bytes(),
        e2: array(r.challenge_digest, "challenge_digest")?,
        vi: array(r.verifier_input, "verifier_input")?,
        seed: r.transcript_seed,
    })
}

fn hbit(b: u8) -> G {
    if b == 0 { G::ZERO } else { G::ONE }
}

fn pbit(b: usize) -> P {
    if b == 0 { P::ZERO } else { P::ONE }
}

fn g_from_u128(v: u128) -> Result<G, NymAuthError> {
    G::try_from(&v.to_le_bytes()[..]).map_err(|e| NymAuthError::Prover(e.to_string()))
}

fn g_to_u128(g: &G) -> Result<u128, NymAuthError> {
    let mut b = [0u8; 16];
    g.encode(&mut &mut b[..])
        .map_err(|e| NymAuthError::Prover(e.to_string()))?;
    Ok(u128::from_le_bytes(b))
}

fn bits_of(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes.iter().flat_map(|x| (0..8).map(move |j| (x >> j) & 1))
}

/// The public part of the hash input vector that the request determines, with a, tags and
/// pseudonym slots zero.
fn hash_public_base(p: &Profile, c: &Checked<'_>) -> Result<Vec<G>, NymAuthError> {
    let mut h = vec![G::ZERO; p.hash_npub];
    h[0] = G::ONE;
    let mut i = 1;
    for b in [c.t, c.e, c.c, &c.vi[..]] {
        for x in bits_of(b) {
            if i >= p.hash_npub - 9 {
                return Err(invalid("request sizes do not fit this circuit"));
            }
            h[i] = hbit(x);
            i += 1;
        }
    }
    if i != p.hash_npub - 9 {
        return Err(invalid("request sizes do not fit this circuit"));
    }
    Ok(h)
}

fn pseudonym_halves(nym: &[u8; 32]) -> Result<[G; 2], NymAuthError> {
    let mut lo: [u8; 16] = array(&nym[16..], "pseudonym")?;
    let mut hi: [u8; 16] = array(&nym[..16], "pseudonym")?;
    lo.reverse();
    hi.reverse();
    Ok([
        g_from_u128(u128::from_le_bytes(lo))?,
        g_from_u128(u128::from_le_bytes(hi))?,
    ])
}

/// The public part of the signature input vector (everything below slot 1155) from the request;
/// a_v and the tags are filled by [`set_mac_public`].
fn sig_public_base(p: &Profile, c: &Checked<'_>) -> Result<Vec<P>, NymAuthError> {
    let fx = ecdsa::fe_be(&c.qx).map_err(|_| invalid("issuer_key_x is not below p"))?;
    let fy = ecdsa::fe_be(&c.qy).map_err(|_| invalid("issuer_key_y is not below p"))?;
    let mut s = vec![P::ZERO; p.sig_npub];
    s[0] = P::ONE;
    s[1] = fx;
    s[2] = fy;
    for i in 0..256 {
        s[3 + i] = pbit(ecdsa::bit(&c.e2, i));
    }
    Ok(s)
}

/// Writes a_v and the tags into the public slots of both vectors (L3, L6).
fn set_mac_public(
    p: &Profile,
    h: &mut [G],
    s: &mut [P],
    a_v: &G,
    tags: &[G; 6],
) -> Result<(), NymAuthError> {
    let av = g_to_u128(a_v)?;
    h[p.hash_npub - 3] = *a_v;
    for j in 0..128 {
        s[259 + j] = pbit(((av >> j) & 1) as usize);
    }
    for (k, tag) in tags.iter().enumerate() {
        h[p.hash_npub - 9 + k] = *tag;
        let t = g_to_u128(tag)?;
        for j in 0..128 {
            s[387 + 128 * k + j] = pbit(((t >> j) & 1) as usize);
        }
    }
    Ok(())
}

/// Both input vectors, built from the credential, before the MAC key shares exist.
struct Built {
    h: Wiped<G>,
    s: Wiped<P>,
    msgs: [G; 6],
    pseudonym: [u8; 32],
}

/// Writes the prover's MAC key shares a_p into the private slots of both vectors.
fn set_prover_key_shares(
    p: &Profile,
    h: &mut [G],
    s: &mut [P],
    a_p: &[G; 6],
) -> Result<(), NymAuthError> {
    for (k, a) in a_p.iter().enumerate() {
        h[p.hash_ninputs - 6 + k] = *a;
        let av = g_to_u128(a)?;
        for j in 0..128 {
            s[1155 + 128 * k + j] = pbit(((av >> j) & 1) as usize);
        }
    }
    Ok(())
}

fn ligero_parameters(block_enc: usize) -> Result<LigeroParameters, NymAuthError> {
    let block_size = (block_enc + 1) / (2 + LIGERO_RATE_INV);
    if block_enc > 1 << 22 || block_size <= LIGERO_NREQ {
        return Err(NymAuthError::Circuit(format!(
            "block_enc {block_enc} is not a usable Ligero width"
        )));
    }
    let witnesses_per_row = block_size - LIGERO_NREQ;
    Ok(LigeroParameters {
        nreq: LIGERO_NREQ,
        witnesses_per_row,
        quadratic_constraints_per_row: witnesses_per_row,
        block_size,
        num_columns: block_enc,
    })
}

struct Loaded {
    profile: Profile,
    sig: Circuit<P>,
    hash: Circuit<G>,
    hash_params: LigeroParameters,
    sig_params: LigeroParameters,
}

fn load(circuit: &[u8], params: &NymAuthCircuitParams) -> Result<Loaded, NymAuthError> {
    let profile = profile::for_hash_circuit(&params.hash_circuit_id)?;
    if !params.sig_circuit_id.eq_ignore_ascii_case(SIG_CIRCUIT_ID) {
        return Err(NymAuthError::UnsupportedCircuit(format!(
            "unknown signature circuit {}",
            params.sig_circuit_id
        )));
    }
    // The catalog serves LFC2 pairs; the circuit type here reads the legacy layout.
    let legacy = lfc2::to_legacy_pair(circuit)?;
    let circuit = &legacy[..];
    let mut cursor = Cursor::new(circuit);
    let sig: Circuit<P> = Circuit::decode(&mut cursor)
        .map_err(|e| NymAuthError::Circuit(format!("signature circuit: {e:#}")))?;
    let hash: Circuit<G> = Circuit::decode(&mut cursor)
        .map_err(|e| NymAuthError::Circuit(format!("hash circuit: {e:#}")))?;
    if cursor.position() as usize != circuit.len() {
        return Err(NymAuthError::Circuit(
            "bytes left over after the hash circuit".into(),
        ));
    }
    let id = |d: crate::Sha256Digest| hex::encode(d.0);
    let sig_id = sig
        .circuit_id()
        .map(id)
        .map_err(|e| NymAuthError::Circuit(e.to_string()))?;
    let hash_id = hash
        .circuit_id()
        .map(id)
        .map_err(|e| NymAuthError::Circuit(e.to_string()))?;
    if !sig_id.eq_ignore_ascii_case(&params.sig_circuit_id)
        || !hash_id.eq_ignore_ascii_case(&params.hash_circuit_id)
    {
        return Err(NymAuthError::Circuit(
            "circuit bytes do not match the descriptor's circuit ids".into(),
        ));
    }
    if hash.num_inputs() != profile.hash_ninputs
        || hash.num_public_inputs() != profile.hash_npub
        || sig.num_inputs() != profile.sig_ninputs
        || sig.num_public_inputs() != profile.sig_npub
    {
        return Err(NymAuthError::Circuit(
            "circuit input counts do not match the profile".into(),
        ));
    }
    Ok(Loaded {
        profile,
        hash_params: ligero_parameters(params.block_enc_hash)?,
        sig_params: ligero_parameters(params.block_enc_sig)?,
        sig,
        hash,
    })
}

/// Runs `f`, turning a panic of the proving system into a typed error.
fn guarded<T>(f: impl FnOnce() -> Result<T, NymAuthError>) -> Result<T, NymAuthError> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(NymAuthError::Prover("internal panic".into())))
}

/// Proof layout of `MdocProof`: six MAC tags, then the hash proof, then the signature proof.
#[derive(Debug, PartialEq, Eq)]
struct Proof {
    mac_tags: [G; 6],
    hash_commitment: Root,
    hash_sumcheck: SumcheckProof<G>,
    hash_ligero: LigeroProof<G>,
    sig_commitment: Root,
    sig_sumcheck: SumcheckProof<P>,
    sig_ligero: LigeroProof<P>,
}

struct ProofContext<'a> {
    hash_circuit: &'a Circuit<G>,
    sig_circuit: &'a Circuit<P>,
    hash_layout: &'a TableauLayout,
    sig_layout: &'a TableauLayout,
}

impl<'a> ParameterizedCodec<ProofContext<'a>> for Proof {
    fn decode_with_param(
        ctx: &ProofContext<'a>,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let mut mac_tags = [G::ZERO; 6];
        for tag in mac_tags.iter_mut() {
            *tag = G::decode(cursor)?;
        }
        Ok(Self {
            mac_tags,
            hash_commitment: Root::decode(cursor)?,
            hash_sumcheck: SumcheckProof::decode_with_param(ctx.hash_circuit, cursor)?,
            hash_ligero: LigeroProof::decode_with_param(ctx.hash_layout, cursor)?,
            sig_commitment: Root::decode(cursor)?,
            sig_sumcheck: SumcheckProof::decode_with_param(ctx.sig_circuit, cursor)?,
            sig_ligero: LigeroProof::decode_with_param(ctx.sig_layout, cursor)?,
        })
    }

    fn encode_with_param<W: Write>(
        &self,
        ctx: &ProofContext<'a>,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        for tag in &self.mac_tags {
            tag.encode(bytes)?;
        }
        self.hash_commitment.encode(bytes)?;
        self.hash_sumcheck
            .encode_with_param(ctx.hash_circuit, bytes)?;
        self.hash_ligero.encode_with_param(ctx.hash_layout, bytes)?;
        self.sig_commitment.encode(bytes)?;
        self.sig_sumcheck
            .encode_with_param(ctx.sig_circuit, bytes)?;
        self.sig_ligero.encode_with_param(ctx.sig_layout, bytes)?;
        Ok(())
    }
}

/// The nym_auth prover for one circuit pair.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct NymAuthProver {
    l: Loaded,
    hash_prover: LigeroProver<G>,
    sig_prover: LigeroProver<P>,
}

impl NymAuthProver {
    /// Loads the decompressed circuit artifact (signature circuit, then hash circuit).
    pub fn new(circuit: &[u8], params: &NymAuthCircuitParams) -> Result<Self, NymAuthError> {
        guarded(|| {
            let l = load(circuit, params)?;
            let hash_prover = LigeroProver::new(&l.hash, l.hash_params);
            let sig_prover = LigeroProver::new(&l.sig, l.sig_params);
            Ok(Self {
                l,
                hash_prover,
                sig_prover,
            })
        })
    }

    /// Builds both witnesses and proves. Refuses, without producing a proof, if the inputs do
    /// not satisfy the statement.
    pub fn prove(
        &self,
        request: &NymAuthRequest<'_>,
        w: &NymAuthWitnessInput<'_>,
    ) -> Result<NymAuthProof, NymAuthError> {
        guarded(|| self.prove_inner(request, w))
    }

    /// Both input vectors with a_p, a_v and the tags unset, the MAC messages and the pseudonym.
    fn build_inputs(
        &self,
        c: &Checked<'_>,
        w: &NymAuthWitnessInput<'_>,
    ) -> Result<Built, NymAuthError> {
        let p = &self.l.profile;
        let dev_sig: [u8; 64] = array(w.device_signature, "device_signature")?;
        // Our own copy of the seed, wiped on every exit path.
        let seed_copy = wipe::SecretArray(array::<16>(w.secret_seed, "secret_seed")?);
        let seed = &seed_copy.0;

        // Semantic bits and the pseudonym.
        let (sem, parsed) = mdoc::semantic(w.issuer_signed, seed, &c.vi, p)?;
        if sem.len() != p.semantic_len {
            return Err(NymAuthError::Credential(
                "semantic bits do not match the circuit's slot map".into(),
            ));
        }
        let nym_msg = mdoc::nym_message(seed, &c.vi);
        let pseudonym = sha256(&nym_msg);
        drop(nym_msg);

        // Hash input vector.
        let mut h = Wiped::new(hash_public_base(p, c)?, G::ZERO);
        h.resize(p.hash_ninputs, G::ZERO);
        let halves = pseudonym_halves(&pseudonym)?;
        h[p.hash_npub - 2] = halves[0];
        h[p.hash_npub - 1] = halves[1];
        for &(slot, from, len) in &p.runs {
            for k in 0..len {
                h[slot + k] = hbit(sem[from + k]);
            }
        }
        drop(sem);

        // Signature input vector.
        let e_digest = sha256(&parsed.signed);
        let mut s = Wiped::new(sig_public_base(p, c)?, P::ZERO);
        s.resize(p.sig_ninputs, P::ZERO);
        for i in 0..256 {
            s[1923 + i] = pbit(ecdsa::bit(&e_digest, i));
            s[2179 + i] = pbit(ecdsa::bit(&parsed.x, i));
            s[2435 + i] = pbit(ecdsa::bit(&parsed.y, i));
        }
        let (r_iss, s_iss): ([u8; 32], [u8; 32]) = (
            array(&parsed.issuer_sig[..32], "issuer signature")?,
            array(&parsed.issuer_sig[32..], "issuer signature")?,
        );
        let iss = ecdsa::verification(&c.qx, &c.qy, &e_digest, &r_iss, &s_iss)
            .map_err(|_| NymAuthError::Unsatisfied("issuer signature does not verify".into()))?;
        let dev_key = (
            ecdsa::reduce_mod_p(&parsed.x),
            ecdsa::reduce_mod_p(&parsed.y),
        );
        let (r_dev, s_dev): ([u8; 32], [u8; 32]) = (
            array(&dev_sig[..32], "device signature")?,
            array(&dev_sig[32..], "device signature")?,
        );
        let dev = ecdsa::verification(&dev_key.0, &dev_key.1, &c.e2, &r_dev, &s_dev)
            .map_err(|_| NymAuthError::Unsatisfied("device signature does not verify".into()))?;
        s[2691..2691 + ecdsa::TRACE_LEN].copy_from_slice(&iss);
        s[2691 + ecdsa::TRACE_LEN..2691 + 2 * ecdsa::TRACE_LEN].copy_from_slice(&dev);

        // MAC messages.
        let half = |v: &[u8; 32]| -> Result<[G; 2], NymAuthError> {
            Ok([
                g_from_u128(u128::from_be_bytes(array(&v[16..], "half")?))?,
                g_from_u128(u128::from_be_bytes(array(&v[..16], "half")?))?,
            ])
        };
        let (me, mx, my) = (half(&e_digest)?, half(&parsed.x)?, half(&parsed.y)?);
        let msgs = [me[0], me[1], mx[0], mx[1], my[0], my[1]];
        Ok(Built {
            h,
            s,
            msgs,
            pseudonym,
        })
    }

    /// Evaluates both circuits and refuses unless every output is zero: a proof of a false
    /// statement is never produced.
    fn evaluate_satisfied(
        &self,
        h: &[G],
        s: &[P],
    ) -> Result<(crate::circuit::Evaluation<G>, crate::circuit::Evaluation<P>), NymAuthError> {
        // Evaluation fails on an in-circuit assertion: the statement is false.
        let unsat = |e: anyhow::Error| NymAuthError::Unsatisfied(format!("{e:#}"));
        let hash_eval = self.l.hash.evaluate(h).map_err(unsat)?;
        let sig_eval = self.l.sig.evaluate(s).map_err(unsat)?;
        if !hash_eval.outputs().iter().all(|o| bool::from(o.is_zero())) {
            return Err(NymAuthError::Unsatisfied(
                "the hash circuit is not satisfied (credential, seed or request do not match)"
                    .into(),
            ));
        }
        if !sig_eval.outputs().iter().all(|o| bool::from(o.is_zero())) {
            return Err(NymAuthError::Unsatisfied(
                "the signature circuit is not satisfied".into(),
            ));
        }
        Ok((hash_eval, sig_eval))
    }

    fn prove_inner(
        &self,
        request: &NymAuthRequest<'_>,
        w: &NymAuthWitnessInput<'_>,
    ) -> Result<NymAuthProof, NymAuthError> {
        let p = &self.l.profile;
        let c = check(request)?;
        let Built {
            mut h,
            mut s,
            msgs,
            pseudonym,
        } = self.build_inputs(&c, w)?;
        let mut a_p = [G::ZERO; 6];
        for a in a_p.iter_mut() {
            *a = G::sample();
        }
        set_prover_key_shares(p, &mut h, &mut s, &a_p)?;

        // Refuse a false statement before the expensive commitments. The MAC relation holds for
        // any a_v, so a placeholder a_v = 0 with matching tags exposes every other failure.
        let mut tags0 = [G::ZERO; 6];
        for k in 0..6 {
            tags0[k] = a_p[k] * msgs[k];
        }
        set_mac_public(p, &mut h, &mut s, &G::ZERO, &tags0)?;
        self.evaluate_satisfied(&h, &s)?;

        // Commit to both witnesses (the one-time pads come from the OS RNG).
        let hash_layout = self.hash_prover.witness_layout().clone();
        let sig_layout = self.sig_prover.witness_layout().clone();
        let mut rng = rand::rng();
        let mut buf = vec![0u8; G::num_bytes()];
        let hash_witness = Witness::fill_witness(hash_layout, &h[p.hash_npub..], || {
            G::sample_from_source(&mut buf, |b| rng.fill_bytes(b))
        });
        let mut buf = vec![0u8; P::num_bytes()];
        let sig_witness = Witness::fill_witness(sig_layout, &s[p.sig_npub..], || {
            P::sample_from_source(&mut buf, |b| rng.fill_bytes(b))
        });
        let mut transcript = Transcript::new(c.seed, TranscriptMode::Normal)
            .map_err(|e| NymAuthError::Prover(e.to_string()))?;
        let prov = |e: anyhow::Error| NymAuthError::Prover(format!("{e:#}"));
        let hash_state = self.hash_prover.commit(&hash_witness).map_err(prov)?;
        transcript
            .write_byte_array(hash_state.commitment().as_bytes())
            .map_err(prov)?;
        let sig_state = self.sig_prover.commit(&sig_witness).map_err(prov)?;
        transcript
            .write_byte_array(sig_state.commitment().as_bytes())
            .map_err(prov)?;

        // a_v from the transcript, then the tags, written into the public slots.
        let a_v: G = transcript.generate_challenge::<G>(1).map_err(prov)?[0];
        let mut tags = [G::ZERO; 6];
        for k in 0..6 {
            tags[k] = (a_p[k] + a_v) * msgs[k];
        }
        set_mac_public(p, &mut h, &mut s, &a_v, &tags)?;

        let (hash_eval, sig_eval) = self.evaluate_satisfied(&h, &s)?;

        initialize_transcript(
            &mut transcript,
            &self.l.hash,
            hash_eval.public_inputs(p.hash_npub),
        )
        .map_err(prov)?;
        let ProverResult {
            proof: hash_sumcheck,
            linear_constraints: hash_lc,
        } = SumcheckProtocol::new(&self.l.hash)
            .prove(&hash_eval, &mut transcript, &hash_witness)
            .map_err(prov)?;
        let hash_ligero = self
            .hash_prover
            .prove(&mut transcript, &hash_state, &hash_lc)
            .map_err(prov)?;

        initialize_transcript(
            &mut transcript,
            &self.l.sig,
            sig_eval.public_inputs(p.sig_npub),
        )
        .map_err(prov)?;
        let ProverResult {
            proof: sig_sumcheck,
            linear_constraints: sig_lc,
        } = SumcheckProtocol::new(&self.l.sig)
            .prove(&sig_eval, &mut transcript, &sig_witness)
            .map_err(prov)?;
        let sig_ligero = self
            .sig_prover
            .prove(&mut transcript, &sig_state, &sig_lc)
            .map_err(prov)?;

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
            hash_circuit: &self.l.hash,
            sig_circuit: &self.l.sig,
            hash_layout: hash_state.tableau().layout(),
            sig_layout: sig_state.tableau().layout(),
        };
        let mut out = Vec::with_capacity(1 << 19);
        proof.encode_with_param(&ctx, &mut out).map_err(prov)?;
        Ok(NymAuthProof {
            proof: out,
            pseudonym,
        })
    }
}

/// The nym_auth verifier for one circuit pair.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct NymAuthVerifier {
    l: Loaded,
    hash_verifier: LigeroVerifier<G>,
    sig_verifier: LigeroVerifier<P>,
}

impl NymAuthVerifier {
    pub fn new(circuit: &[u8], params: &NymAuthCircuitParams) -> Result<Self, NymAuthError> {
        guarded(|| {
            let l = load(circuit, params)?;
            let hash_verifier = LigeroVerifier::new(&l.hash, l.hash_params);
            let sig_verifier = LigeroVerifier::new(&l.sig, l.sig_params);
            Ok(Self {
                l,
                hash_verifier,
                sig_verifier,
            })
        })
    }

    /// Verifies `proof` against the verifier's own `request`; `pseudonym` is the value the
    /// holder reported and is accepted only if the proof binds it.
    pub fn verify(
        &self,
        request: &NymAuthRequest<'_>,
        pseudonym: &[u8],
        proof: &[u8],
    ) -> Result<(), NymAuthError> {
        guarded(|| self.verify_inner(request, pseudonym, proof))
    }

    fn verify_inner(
        &self,
        request: &NymAuthRequest<'_>,
        pseudonym: &[u8],
        proof: &[u8],
    ) -> Result<(), NymAuthError> {
        let p = &self.l.profile;
        let c = check(request)?;
        let pseudonym: [u8; 32] = array(pseudonym, "pseudonym")?;
        let ver = |e: anyhow::Error| NymAuthError::Verification(format!("{e:#}"));
        let ctx = ProofContext {
            hash_circuit: &self.l.hash,
            sig_circuit: &self.l.sig,
            hash_layout: self.hash_verifier.tableau_layout(),
            sig_layout: self.sig_verifier.tableau_layout(),
        };
        let proof = Proof::get_decoded_with_param(&ctx, proof)
            .map_err(|e| NymAuthError::Verification(format!("could not parse proof: {e:#}")))?;

        let mut transcript = Transcript::new(c.seed, TranscriptMode::Normal).map_err(ver)?;
        transcript
            .write_byte_array(proof.hash_commitment.as_bytes())
            .map_err(ver)?;
        transcript
            .write_byte_array(proof.sig_commitment.as_bytes())
            .map_err(ver)?;
        let a_v: G = transcript.generate_challenge::<G>(1).map_err(ver)?[0];

        let mut h = hash_public_base(p, &c)?;
        let mut s = sig_public_base(p, &c)?;
        let halves = pseudonym_halves(&pseudonym)?;
        h[p.hash_npub - 2] = halves[0];
        h[p.hash_npub - 1] = halves[1];
        set_mac_public(p, &mut h, &mut s, &a_v, &proof.mac_tags)?;

        initialize_transcript(&mut transcript, &self.l.hash, &h).map_err(ver)?;
        let hash_lc = SumcheckProtocol::new(&self.l.hash)
            .linear_constraints(&h, &mut transcript, &proof.hash_sumcheck)
            .map_err(ver)?;
        self.hash_verifier
            .verify(
                proof.hash_commitment,
                &proof.hash_ligero,
                &mut transcript,
                &hash_lc,
            )
            .map_err(ver)?;

        initialize_transcript(&mut transcript, &self.l.sig, &s).map_err(ver)?;
        let sig_lc = SumcheckProtocol::new(&self.l.sig)
            .linear_constraints(&s, &mut transcript, &proof.sig_sumcheck)
            .map_err(ver)?;
        self.sig_verifier
            .verify(
                proof.sig_commitment,
                &proof.sig_ligero,
                &mut transcript,
                &sig_lc,
            )
            .map_err(ver)?;
        Ok(())
    }
}
