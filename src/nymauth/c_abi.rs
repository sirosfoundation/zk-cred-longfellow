//! Plain C ABI of the nym_auth prover and verifier, for cgo and other C callers.
//!
//! Same conventions as [`crate::go_ffi`]: opaque handles created with `Box::into_raw`, plain
//! pointer/length pairs, a small integer status, and no unwinding across the boundary (every
//! entry point runs under `catch_unwind`). The header is `include/zk_cred_longfellow_nymauth.h`.
//!
//! Status codes: `0` success; `-1` invalid input; `-2` bad circuit; `-3` unsupported circuit;
//! `-4` malformed credential; `-5` statement not satisfied; `-6` prover failure; `-7` proof
//! refused; `-100` an internal panic was caught.
//!
//! The prover copies `secret_seed` into a buffer it zeroes before returning; the caller still
//! owns, and should zero, its own copy.

use super::{
    NymAuthCircuitParams, NymAuthError, NymAuthProver, NymAuthRequest, NymAuthVerifier,
    NymAuthWitnessInput,
};
use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};

/// A byte buffer by pointer and length. A null pointer is accepted only with length zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NymAuthBytes {
    pub ptr: *const u8,
    pub len: usize,
}

/// The request values both sides know. Text fields are UTF-8 bytes, not NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NymAuthCRequest {
    pub issuer_key_x: NymAuthBytes,
    pub issuer_key_y: NymAuthBytes,
    pub time: NymAuthBytes,
    pub earliest: NymAuthBytes,
    pub cutoff: NymAuthBytes,
    pub challenge_digest: NymAuthBytes,
    pub verifier_input: NymAuthBytes,
    pub transcript_seed: NymAuthBytes,
}

/// The holder's private inputs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NymAuthCWitness {
    pub issuer_signed: NymAuthBytes,
    pub secret_seed: NymAuthBytes,
    pub device_signature: NymAuthBytes,
}

/// The catalog descriptor's parameters. The ids are lowercase or uppercase hex, not
/// NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NymAuthCParams {
    pub block_enc_hash: u32,
    pub block_enc_sig: u32,
    pub hash_circuit_id: NymAuthBytes,
    pub sig_circuit_id: NymAuthBytes,
}

fn status(e: &NymAuthError) -> i32 {
    match e {
        NymAuthError::InvalidInput(_) => -1,
        NymAuthError::Circuit(_) => -2,
        NymAuthError::UnsupportedCircuit(_) => -3,
        NymAuthError::Credential(_) => -4,
        NymAuthError::Unsatisfied(_) => -5,
        NymAuthError::Prover(_) => -6,
        NymAuthError::Verification(_) => -7,
    }
}

/// # Safety
/// `b.ptr` must be null with `b.len == 0`, or point to `b.len` readable bytes that outlive `'a`.
unsafe fn bytes<'a>(b: NymAuthBytes, what: &str) -> Result<&'a [u8], NymAuthError> {
    if b.len == 0 {
        return Ok(&[]);
    }
    if b.ptr.is_null() {
        return Err(NymAuthError::InvalidInput(format!(
            "{what} has a length but a null pointer"
        )));
    }
    // SAFETY: per this function's contract.
    Ok(unsafe { slice::from_raw_parts(b.ptr, b.len) })
}

/// # Safety
/// As [`bytes`].
unsafe fn text<'a>(b: NymAuthBytes, what: &str) -> Result<&'a str, NymAuthError> {
    // SAFETY: forwarded.
    std::str::from_utf8(unsafe { bytes(b, what) }?)
        .map_err(|_| NymAuthError::InvalidInput(format!("{what} is not UTF-8")))
}

/// # Safety
/// As [`bytes`] for every field.
unsafe fn request<'a>(r: &NymAuthCRequest) -> Result<NymAuthRequest<'a>, NymAuthError> {
    // SAFETY: forwarded.
    unsafe {
        Ok(NymAuthRequest {
            issuer_key_x: bytes(r.issuer_key_x, "issuer_key_x")?,
            issuer_key_y: bytes(r.issuer_key_y, "issuer_key_y")?,
            time: text(r.time, "time")?,
            earliest: text(r.earliest, "earliest")?,
            cutoff: text(r.cutoff, "cutoff")?,
            challenge_digest: bytes(r.challenge_digest, "challenge_digest")?,
            verifier_input: bytes(r.verifier_input, "verifier_input")?,
            transcript_seed: bytes(r.transcript_seed, "transcript_seed")?,
        })
    }
}

/// # Safety
/// `error_out` is null or points to a writable `*mut c_char`.
unsafe fn set_error(error_out: *mut *mut c_char, msg: &str) {
    if error_out.is_null() {
        return;
    }
    let c = CString::new(msg.replace('\0', "\u{fffd}")).unwrap_or_default();
    // SAFETY: per this function's contract.
    unsafe { *error_out = c.into_raw() };
}

/// # Safety
/// `error_out` is null or points to a writable `*mut c_char`.
unsafe fn clear_error(error_out: *mut *mut c_char) {
    if !error_out.is_null() {
        // SAFETY: per this function's contract.
        unsafe { *error_out = std::ptr::null_mut() };
    }
}

fn run<T>(f: impl FnOnce() -> Result<T, NymAuthError>) -> Result<T, (i32, String)> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err((status(&e), e.to_string())),
        Err(_) => Err((-100, "nymauth: internal panic".to_string())),
    }
}

/// Loads a prover. Returns null on failure, with `*error_out` set to an owned message to free
/// with [`nymauth_free_error_string`].
///
/// # Safety
/// All `NymAuthBytes` in `params` and `circuit` follow the rules of [`NymAuthBytes`];
/// `error_out` is null or points to a writable `*mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_prover_new(
    circuit: NymAuthBytes,
    params: *const NymAuthCParams,
    error_out: *mut *mut c_char,
) -> *mut NymAuthProver {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (c, p) = unsafe { (bytes(circuit, "circuit")?, c_params(params)?) };
        NymAuthProver::new(c, &p)
    });
    match r {
        Ok(p) => Box::into_raw(Box::new(p)),
        Err((_, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `p` is null or points to a valid struct whose id fields follow the rules of [`bytes`].
unsafe fn c_params(p: *const NymAuthCParams) -> Result<NymAuthCircuitParams, NymAuthError> {
    // SAFETY: per this function's contract.
    let p =
        unsafe { p.as_ref() }.ok_or_else(|| NymAuthError::InvalidInput("params is null".into()))?;
    // SAFETY: forwarded.
    unsafe {
        Ok(NymAuthCircuitParams {
            block_enc_hash: p.block_enc_hash as usize,
            block_enc_sig: p.block_enc_sig as usize,
            hash_circuit_id: text(p.hash_circuit_id, "hash_circuit_id")?.to_string(),
            sig_circuit_id: text(p.sig_circuit_id, "sig_circuit_id")?.to_string(),
        })
    }
}

/// Loads a verifier. Same contract as [`nymauth_prover_new`].
///
/// # Safety
/// As [`nymauth_prover_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_verifier_new(
    circuit: NymAuthBytes,
    params: *const NymAuthCParams,
    error_out: *mut *mut c_char,
) -> *mut NymAuthVerifier {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (c, p) = unsafe { (bytes(circuit, "circuit")?, c_params(params)?) };
        NymAuthVerifier::new(c, &p)
    });
    match r {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err((_, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            std::ptr::null_mut()
        }
    }
}

/// Frees a prover. Null is a no-op.
///
/// # Safety
/// `p` is null or a live handle from [`nymauth_prover_new`], with no call in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_prover_free(p: *mut NymAuthProver) {
    if !p.is_null() {
        // SAFETY: per this function's contract.
        drop(unsafe { Box::from_raw(p) });
    }
}

/// Frees a verifier. Null is a no-op.
///
/// # Safety
/// `v` is null or a live handle from [`nymauth_verifier_new`], with no call in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_verifier_free(v: *mut NymAuthVerifier) {
    if !v.is_null() {
        // SAFETY: per this function's contract.
        drop(unsafe { Box::from_raw(v) });
    }
}

/// Frees an error string written by this module.
///
/// # Safety
/// `s` is null or a string this module wrote, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_free_error_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: per this function's contract.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Frees a proof buffer returned by [`nymauth_prove`].
///
/// # Safety
/// `(ptr, len)` is exactly a buffer returned by [`nymauth_prove`], not yet freed; or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // SAFETY: per this function's contract; it was a leaked `Box<[u8]>` of this length.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

/// Proves. On success returns 0, writes the proof to `*proof_out` / `*proof_len_out` (free with
/// [`nymauth_free_buffer`]) and the 32-byte pseudonym to `pseudonym_out`. On failure returns a
/// negative status, writes nothing to the outputs and sets `*error_out`.
///
/// # Safety
/// `prover` is a live handle; `request` and `witness` point to valid structs whose buffers follow
/// the rules of [`NymAuthBytes`]; `proof_out`,
/// `proof_len_out` are writable; `pseudonym_out` points to 32 writable bytes; `error_out` is
/// null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_prove(
    prover: *const NymAuthProver,
    request: *const NymAuthCRequest,
    witness: *const NymAuthCWitness,
    proof_out: *mut *mut u8,
    proof_len_out: *mut usize,
    pseudonym_out: *mut u8,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    if prover.is_null()
        || request.is_null()
        || witness.is_null()
        || proof_out.is_null()
        || proof_len_out.is_null()
        || pseudonym_out.is_null()
    {
        // SAFETY: per this function's contract.
        unsafe { set_error(error_out, "nymauth invalid input: null argument") };
        return -1;
    }
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (req, w, prover) = unsafe {
            let witness = &*witness;
            (
                request_of(&*request)?,
                NymAuthWitnessInput {
                    issuer_signed: bytes(witness.issuer_signed, "issuer_signed")?,
                    secret_seed: bytes(witness.secret_seed, "secret_seed")?,
                    device_signature: bytes(witness.device_signature, "device_signature")?,
                },
                &*prover,
            )
        };
        prover.prove(&req, &w)
    });
    match r {
        Ok(p) => {
            let boxed = p.proof.into_boxed_slice();
            let len = boxed.len();
            // SAFETY: outputs are writable per the contract; `pseudonym_out` has 32 bytes.
            unsafe {
                *proof_len_out = len;
                *proof_out = Box::into_raw(boxed) as *mut u8;
                std::ptr::copy_nonoverlapping(p.pseudonym.as_ptr(), pseudonym_out, 32);
            }
            0
        }
        Err((code, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            code
        }
    }
}

/// # Safety
/// As [`request`].
unsafe fn request_of<'a>(r: &NymAuthCRequest) -> Result<NymAuthRequest<'a>, NymAuthError> {
    // SAFETY: forwarded.
    unsafe { request(r) }
}

/// Verifies. Returns 0 if the proof is accepted; a negative status otherwise.
///
/// # Safety
/// `verifier` is a live handle; `request` points to a valid struct whose buffers follow the rules
/// of [`NymAuthBytes`]; `pseudonym` and `proof` likewise; `error_out` is
/// null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_verify(
    verifier: *const NymAuthVerifier,
    request: *const NymAuthCRequest,
    pseudonym: NymAuthBytes,
    proof: NymAuthBytes,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    if verifier.is_null() || request.is_null() {
        // SAFETY: per this function's contract.
        unsafe { set_error(error_out, "nymauth invalid input: null argument") };
        return -1;
    }
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (req, nym, proof, verifier) = unsafe {
            (
                request_of(&*request)?,
                bytes(pseudonym, "pseudonym")?,
                bytes(proof, "proof")?,
                &*verifier,
            )
        };
        verifier.verify(&req, nym, proof)
    });
    match r {
        Ok(()) => 0,
        Err((code, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            code
        }
    }
}

/// Derives the SessionTranscript and `e2` per SPEC.md section 3 (see `challenge.rs`). On 0,
/// `*transcript_out` / `*transcript_len_out` receive a buffer to release with
/// [`nymauth_free_buffer`] and `digest_out` (32 bytes) receives `e2`. `jwk_thumbprint` of length
/// 0 means "no thumbprint" (CBOR null); otherwise it must be 32 bytes.
///
/// # Safety
/// The `NymAuthBytes` follow the rules of [`NymAuthBytes`]; `transcript_out` and
/// `transcript_len_out` are writable; `digest_out` points to 32 writable bytes; `error_out` is
/// null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_derive_challenge(
    origin: NymAuthBytes,
    nonce: NymAuthBytes,
    doc_type: NymAuthBytes,
    jwk_thumbprint: NymAuthBytes,
    transcript_out: *mut *mut u8,
    transcript_len_out: *mut usize,
    digest_out: *mut u8,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    if transcript_out.is_null() || transcript_len_out.is_null() || digest_out.is_null() {
        // SAFETY: per this function's contract.
        unsafe { set_error(error_out, "nymauth invalid input: null argument") };
        return -1;
    }
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (o, n, d, t) = unsafe {
            (
                text(origin, "origin")?,
                text(nonce, "nonce")?,
                text(doc_type, "doc_type")?,
                bytes(jwk_thumbprint, "jwk_thumbprint")?,
            )
        };
        super::derive_challenge(o, n, d, (!t.is_empty()).then_some(t))
    });
    match r {
        Ok(c) => {
            let boxed = c.session_transcript.into_boxed_slice();
            // SAFETY: outputs are writable per the contract; `digest_out` has 32 bytes and the
            // digest is 32 bytes.
            unsafe {
                *transcript_len_out = boxed.len();
                *transcript_out = Box::into_raw(boxed) as *mut u8;
                std::ptr::copy_nonoverlapping(c.challenge_digest.as_ptr(), digest_out, 32);
            }
            0
        }
        Err((code, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            code
        }
    }
}

/// `e2` for a SessionTranscript already in hand. On 0, `digest_out` (32 bytes) receives it.
///
/// # Safety
/// The `NymAuthBytes` follow the rules of [`NymAuthBytes`]; `digest_out` points to 32 writable
/// bytes; `error_out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_challenge_digest(
    session_transcript: NymAuthBytes,
    doc_type: NymAuthBytes,
    digest_out: *mut u8,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    if digest_out.is_null() {
        // SAFETY: per this function's contract.
        unsafe { set_error(error_out, "nymauth invalid input: null argument") };
        return -1;
    }
    let r = run(|| {
        // SAFETY: per this function's contract.
        let (st, d) = unsafe {
            (
                bytes(session_transcript, "session_transcript")?,
                text(doc_type, "doc_type")?,
            )
        };
        super::challenge_digest(st, d)
    });
    match r {
        Ok(d) => {
            // SAFETY: `digest_out` has 32 writable bytes per the contract.
            unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), digest_out, 32) };
            0
        }
        Err((code, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            code
        }
    }
}

/// `SHA-256(client_id)`, the request's `verifier_input`, into `digest_out` (32 bytes).
///
/// # Safety
/// `client_id` follows the rules of [`NymAuthBytes`]; `digest_out` points to 32 writable bytes;
/// `error_out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nymauth_verifier_input(
    client_id: NymAuthBytes,
    digest_out: *mut u8,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { clear_error(error_out) };
    if digest_out.is_null() {
        // SAFETY: per this function's contract.
        unsafe { set_error(error_out, "nymauth invalid input: null argument") };
        return -1;
    }
    let r = run(|| {
        // SAFETY: per this function's contract.
        let c = unsafe { text(client_id, "client_id") }?;
        super::verifier_input(c)
    });
    match r {
        Ok(d) => {
            // SAFETY: `digest_out` has 32 writable bytes per the contract.
            unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), digest_out, 32) };
            0
        }
        Err((code, m)) => {
            // SAFETY: per this function's contract.
            unsafe { set_error(error_out, &m) };
            code
        }
    }
}
