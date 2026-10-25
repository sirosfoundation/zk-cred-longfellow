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
mod challenge;
mod ecdsa;
mod error;
mod lfc2;
mod mdoc;
mod profile;
mod sha;
// The end-to-end tests make dozens of proofs; they run natively only. The unit tests inside the
// other modules also run under wasm.
#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
mod wipe;

pub mod c_abi;
#[cfg(feature = "uniffi")]
pub mod ffi_uniffi;

pub use challenge::{
    MIN_NONCE_CHARS, NymAuthChallenge, challenge_digest, derive_challenge, verifier_input,
};
pub use error::NymAuthError;

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
    /// `e2`: SHA-256 of the COSE message the device key signed. A verifier derives it with
    /// [`derive_challenge`] from its own origin, nonce and the credential's docType.
    pub challenge_digest: &'a [u8],
    /// `SHA-256(verifier_id)`.
    pub verifier_input: &'a [u8],
    /// The Fiat-Shamir seed both sides bind the proof to: the SessionTranscript from
    /// [`derive_challenge`]. Between [`MIN_TRANSCRIPT_SEED_LEN`] and [`MAX_TRANSCRIPT_SEED_LEN`]
    /// bytes; shorter seeds, such as an empty one, are refused.
    pub transcript_seed: &'a [u8],
}

/// The holder's private inputs. `Debug` prints sizes only.
pub struct NymAuthWitnessInput<'a> {
    /// The credential's IssuerSigned structure as CBOR.
    pub issuer_signed: &'a [u8],
    /// The 16-byte secret seed. The prover copies it, uses the copy and zeroes the copy; the
    /// caller owns, and should zero, its own buffer.
    pub secret_seed: &'a [u8],
    /// The device key's ES256 signature on the challenge message: `r || s`.
    pub device_signature: &'a [u8],
}

impl std::fmt::Debug for NymAuthWitnessInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NymAuthWitnessInput(redacted)")
    }
}

/// A proof and the pseudonym it reports. `Debug` prints sizes only.
#[derive(Clone, PartialEq, Eq)]
pub struct NymAuthProof {
    /// The proof, in the layout of Google's `MdocProof::write`.
    pub proof: Vec<u8>,
    /// `SHA-256(DST || secret_seed || 0x00*32 || verifier_input)`.
    pub pseudonym: [u8; 32],
}

impl std::fmt::Debug for NymAuthProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NymAuthProof({} proof bytes, redacted)",
            self.proof.len()
        )
    }
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

/// Shortest accepted transcript seed. A SessionTranscript with a 32-byte handover hash is longer
/// than 50 bytes; this floor only rejects empty and trivial seeds, it does not parse the format.
pub const MIN_TRANSCRIPT_SEED_LEN: usize = 32;
/// Longest accepted transcript seed.
pub const MAX_TRANSCRIPT_SEED_LEN: usize = 1 << 16;

fn digits(b: &[u8]) -> Option<u32> {
    b.iter().try_fold(0u32, |v, &c| {
        c.is_ascii_digit().then(|| v * 10 + u32::from(c - b'0'))
    })
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) => 29,
        _ => 28,
    }
}

/// `YYYY-MM-DD`, digits only and calendar-valid in the proleptic Gregorian calendar (year 0000 to
/// 9999). With `allow_zero`, the sentinel `0000-00-00` (no lower bound) is accepted too.
fn valid_date(d: &[u8], allow_zero: bool) -> bool {
    if d.len() != DATE_LEN || d[4] != b'-' || d[7] != b'-' {
        return false;
    }
    if allow_zero && d == b"0000-00-00" {
        return true;
    }
    match (digits(&d[..4]), digits(&d[5..7]), digits(&d[8..])) {
        (Some(y), Some(m), Some(day)) => {
            (1..=12).contains(&m) && (1..=days_in_month(y, m)).contains(&day)
        }
        _ => false,
    }
}

/// `YYYY-MM-DDThh:mm:ssZ`, digits only and calendar-valid.
fn valid_time(t: &[u8]) -> bool {
    t.len() == TIME_LEN
        && t[10] == b'T'
        && t[19] == b'Z'
        && t[13] == b':'
        && t[16] == b':'
        && valid_date(&t[..10], false)
        && matches!(
            (digits(&t[11..13]), digits(&t[14..16]), digits(&t[17..19])),
            (Some(h), Some(m), Some(s)) if h < 24 && m < 60 && s < 60
        )
}

fn check<'a>(r: &NymAuthRequest<'a>) -> Result<Checked<'a>, NymAuthError> {
    if !valid_time(r.time.as_bytes()) {
        return Err(invalid(
            "time must be a calendar-valid YYYY-MM-DDThh:mm:ssZ",
        ));
    }
    if !valid_date(r.earliest.as_bytes(), true) {
        return Err(invalid(
            "earliest must be a calendar-valid YYYY-MM-DD or 0000-00-00",
        ));
    }
    if !valid_date(r.cutoff.as_bytes(), false) {
        return Err(invalid("cutoff must be a calendar-valid YYYY-MM-DD"));
    }
    if r.earliest > r.cutoff {
        return Err(invalid("earliest is after cutoff"));
    }
    if !(MIN_TRANSCRIPT_SEED_LEN..=MAX_TRANSCRIPT_SEED_LEN).contains(&r.transcript_seed.len()) {
        return Err(invalid(format!(
            "transcript_seed must be {MIN_TRANSCRIPT_SEED_LEN} to {MAX_TRANSCRIPT_SEED_LEN} bytes"
        )));
    }
    let qx: [u8; 32] = array(r.issuer_key_x, "issuer_key_x")?;
    let qy: [u8; 32] = array(r.issuer_key_y, "issuer_key_y")?;
    // The circuits do not check that Q is on the curve; both sides do, before anything else.
    ecdsa::validate_public_key(&qx, &qy)?;
    Ok(Checked {
        qx,
        qy,
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

/// The public part of the signature input vector (everything below `sig_npub`) from the request;
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
        s[p.sig_av() + j] = pbit(((av >> j) & 1) as usize);
    }
    for (k, tag) in tags.iter().enumerate() {
        h[p.hash_npub - 9 + k] = *tag;
        let t = g_to_u128(tag)?;
        for j in 0..128 {
            s[p.sig_tags() + 128 * k + j] = pbit(((t >> j) & 1) as usize);
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
    a_p: &[G],
) -> Result<(), NymAuthError> {
    for (k, a) in a_p.iter().enumerate() {
        h[p.hash_ninputs - 6 + k] = *a;
        let av = g_to_u128(a)?;
        for j in 0..128 {
            s[p.sig_ap() + 128 * k + j] = pbit(((av >> j) & 1) as usize);
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
    // Everything trusted about a circuit comes from the allowlisted profile, never from the
    // descriptor or the artifact: unlisted builds fail here, before any parsing.
    let profile = profile::for_hash_circuit(&params.hash_circuit_id)?;
    if !params
        .sig_circuit_id
        .eq_ignore_ascii_case(profile.sig_circuit_id)
    {
        return Err(NymAuthError::Circuit(
            "signature circuit id does not match the profile".into(),
        ));
    }
    if params.block_enc_hash != profile.block_enc_hash
        || params.block_enc_sig != profile.block_enc_sig
    {
        return Err(NymAuthError::Circuit(
            "block_enc does not match the profile".into(),
        ));
    }
    // Authenticate the artifact before touching its contents: its sizes are untrusted.
    if circuit.len() != profile.artifact_len
        || !hex::encode(sha256(circuit)).eq_ignore_ascii_case(profile.artifact_sha256)
    {
        return Err(NymAuthError::Circuit(
            "circuit artifact does not match the profile's length and SHA-256".into(),
        ));
    }
    let legacy = lfc2::to_legacy_pair(circuit)?;
    decode_pair(&legacy, params, profile)
}

/// Decodes the two circuits from the legacy layout and checks them against the profile. The
/// transcript binds each circuit's stored id, so the stored id must equal the recomputed one.
fn decode_pair(
    legacy: &[u8],
    params: &NymAuthCircuitParams,
    profile: Profile,
) -> Result<Loaded, NymAuthError> {
    let mut cursor = Cursor::new(legacy);
    let sig: Circuit<P> = Circuit::decode(&mut cursor)
        .map_err(|e| NymAuthError::Circuit(format!("signature circuit: {e:#}")))?;
    let hash: Circuit<G> = Circuit::decode(&mut cursor)
        .map_err(|e| NymAuthError::Circuit(format!("hash circuit: {e:#}")))?;
    if cursor.position() as usize != legacy.len() {
        return Err(NymAuthError::Circuit(
            "bytes left over after the hash circuit".into(),
        ));
    }
    let recomputed = |what: &str, d: Result<crate::Sha256Digest, anyhow::Error>| {
        d.map_err(|e| NymAuthError::Circuit(format!("{what} circuit id: {e}")))
    };
    let sig_id = recomputed("signature", sig.circuit_id())?;
    let hash_id = recomputed("hash", hash.circuit_id())?;
    if sig.id != sig_id || hash.id != hash_id {
        return Err(NymAuthError::Circuit(
            "a circuit's stored id differs from its recomputed id".into(),
        ));
    }
    if !hex::encode(sig_id.0).eq_ignore_ascii_case(&params.sig_circuit_id)
        || !hex::encode(hash_id.0).eq_ignore_ascii_case(&params.hash_circuit_id)
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
        hash_params: ligero_parameters(profile.block_enc_hash)?,
        sig_params: ligero_parameters(profile.block_enc_sig)?,
        profile,
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
        let dev_sig = wipe::SecretArray(array::<64>(w.device_signature, "device_signature")?);
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
        let e_digest = wipe::SecretArray(sha256(&parsed.signed));
        let mut s = Wiped::new(sig_public_base(p, c)?, P::ZERO);
        s.resize(p.sig_ninputs, P::ZERO);
        for i in 0..256 {
            s[p.sig_e() + i] = pbit(ecdsa::bit(&e_digest.0, i));
            s[p.sig_x() + i] = pbit(ecdsa::bit(&parsed.x, i));
            s[p.sig_y() + i] = pbit(ecdsa::bit(&parsed.y, i));
        }
        let (r_iss, s_iss) = (
            wipe::SecretArray(array::<32>(&parsed.issuer_sig[..32], "issuer signature")?),
            wipe::SecretArray(array::<32>(&parsed.issuer_sig[32..], "issuer signature")?),
        );
        let iss = ecdsa::verification(&c.qx, &c.qy, &e_digest.0, &r_iss.0, &s_iss.0)
            .map_err(|_| NymAuthError::Unsatisfied("issuer signature does not verify".into()))?;
        let dev_key = (
            wipe::SecretArray(ecdsa::reduce_mod_p(&parsed.x)),
            wipe::SecretArray(ecdsa::reduce_mod_p(&parsed.y)),
        );
        let (r_dev, s_dev) = (
            wipe::SecretArray(array::<32>(&dev_sig.0[..32], "device signature")?),
            wipe::SecretArray(array::<32>(&dev_sig.0[32..], "device signature")?),
        );
        let dev = ecdsa::verification(&dev_key.0.0, &dev_key.1.0, &c.e2, &r_dev.0, &s_dev.0)
            .map_err(|_| NymAuthError::Unsatisfied("device signature does not verify".into()))?;
        let at = p.sig_issuer_trace();
        s[at..at + ecdsa::TRACE_LEN].copy_from_slice(&iss);
        s[at + ecdsa::TRACE_LEN..at + 2 * ecdsa::TRACE_LEN].copy_from_slice(&dev);

        // MAC messages.
        let half = |v: &[u8; 32]| -> Result<[G; 2], NymAuthError> {
            Ok([
                g_from_u128(u128::from_be_bytes(array(&v[16..], "half")?))?,
                g_from_u128(u128::from_be_bytes(array(&v[..16], "half")?))?,
            ])
        };
        let (me, mx, my) = (half(&e_digest.0)?, half(&parsed.x)?, half(&parsed.y)?);
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
        // The error text is not forwarded: it is built from circuit state.
        let unsat =
            |_: anyhow::Error| NymAuthError::Unsatisfied("an in-circuit assertion failed".into());
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
        let mut a_p = Wiped::new(vec![G::ZERO; 6], G::ZERO);
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
        // The proving system's error text can contain witness values; it is not forwarded.
        let prov = |_: anyhow::Error| NymAuthError::Prover("the proving system failed".into());
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
            .map_err(|e| NymAuthError::ProofEncoding(format!("could not parse proof: {e:#}")))?;

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
