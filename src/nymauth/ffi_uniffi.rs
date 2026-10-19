// SPDX-License-Identifier: MPL-2.0

//! UniFFI surface of the nym_auth prover and verifier (Kotlin and Swift), separate from the
//! generic mdoc entry points in [`crate::ffi_api`].
//!
//! The prove request mirrors `NymAuthProveRequest` of the Kotlin SDK. The circuit artifact and
//! the catalog descriptor's parameters are given once, to the `initialize` functions; the handle
//! is then reused for every request.

use super::{
    NymAuthCircuitParams as Params, NymAuthError, NymAuthProver, NymAuthRequest, NymAuthVerifier,
    NymAuthWitnessInput, wipe,
};
use std::sync::Arc;

/// The catalog descriptor's `params` of a `longfellow-nymauth` circuit.
#[derive(uniffi::Record)]
pub struct NymAuthCircuitParams {
    pub block_enc_hash: u32,
    pub block_enc_sig: u32,
    pub hash_circuit_id: String,
    pub sig_circuit_id: String,
}

/// What the prover receives; see `NymAuthProveRequest` in the Kotlin SDK.
#[derive(uniffi::Record)]
pub struct NymAuthProveRequest {
    /// The credential's IssuerSigned structure as CBOR.
    pub issuer_signed: Vec<u8>,
    /// The 16-byte secret seed. Zeroed by `nymauth_prove` before it returns.
    pub secret_seed: Vec<u8>,
    pub issuer_key_x: Vec<u8>,
    pub issuer_key_y: Vec<u8>,
    pub time: String,
    pub earliest: String,
    pub cutoff: String,
    pub challenge_digest: Vec<u8>,
    /// `r || s`, 64 bytes.
    pub device_signature: Vec<u8>,
    pub verifier_input: Vec<u8>,
    pub transcript_seed: Vec<u8>,
}

/// The proof and the pseudonym it reports.
#[derive(uniffi::Record)]
pub struct NymAuthProveResponse {
    pub proof: Vec<u8>,
    pub pseudonym: Vec<u8>,
}

/// What a verifier knows from its own request.
#[derive(uniffi::Record)]
pub struct NymAuthVerifyRequest {
    pub issuer_key_x: Vec<u8>,
    pub issuer_key_y: Vec<u8>,
    pub time: String,
    pub earliest: String,
    pub cutoff: String,
    pub challenge_digest: Vec<u8>,
    pub verifier_input: Vec<u8>,
    pub transcript_seed: Vec<u8>,
    pub pseudonym: Vec<u8>,
    pub proof: Vec<u8>,
}

fn params(p: NymAuthCircuitParams) -> Params {
    Params {
        block_enc_hash: p.block_enc_hash as usize,
        block_enc_sig: p.block_enc_sig as usize,
        hash_circuit_id: p.hash_circuit_id,
        sig_circuit_id: p.sig_circuit_id,
    }
}

/// Loads the decompressed `longfellow-nymauth` circuit artifact (signature circuit, then hash
/// circuit) for proving.
#[uniffi::export]
pub fn nymauth_initialize_prover(
    circuit: &[u8],
    params_: NymAuthCircuitParams,
) -> Result<Arc<NymAuthProver>, NymAuthError> {
    NymAuthProver::new(circuit, &params(params_)).map(Arc::new)
}

/// Loads the circuit artifact for verifying.
#[uniffi::export]
pub fn nymauth_initialize_verifier(
    circuit: &[u8],
    params_: NymAuthCircuitParams,
) -> Result<Arc<NymAuthVerifier>, NymAuthError> {
    NymAuthVerifier::new(circuit, &params(params_)).map(Arc::new)
}

/// Proves; refuses, without a proof, if the inputs do not satisfy the statement.
#[uniffi::export]
pub fn nymauth_prove(
    prover: &NymAuthProver,
    mut request: NymAuthProveRequest,
) -> Result<NymAuthProveResponse, NymAuthError> {
    let r = prover.prove(
        &NymAuthRequest {
            issuer_key_x: &request.issuer_key_x,
            issuer_key_y: &request.issuer_key_y,
            time: &request.time,
            earliest: &request.earliest,
            cutoff: &request.cutoff,
            challenge_digest: &request.challenge_digest,
            verifier_input: &request.verifier_input,
            transcript_seed: &request.transcript_seed,
        },
        &NymAuthWitnessInput {
            issuer_signed: &request.issuer_signed,
            secret_seed: &request.secret_seed,
            device_signature: &request.device_signature,
        },
    );
    // The record owns the lifted seed bytes; zero them on every path.
    wipe::wipe(&mut request.secret_seed, 0);
    r.map(|p| NymAuthProveResponse {
        proof: p.proof,
        pseudonym: p.pseudonym.to_vec(),
    })
}

/// Verifies a proof against the verifier's own request.
#[uniffi::export]
pub fn nymauth_verify(
    verifier: &NymAuthVerifier,
    request: NymAuthVerifyRequest,
) -> Result<(), NymAuthError> {
    verifier.verify(
        &NymAuthRequest {
            issuer_key_x: &request.issuer_key_x,
            issuer_key_y: &request.issuer_key_y,
            time: &request.time,
            earliest: &request.earliest,
            cutoff: &request.cutoff,
            challenge_digest: &request.challenge_digest,
            verifier_input: &request.verifier_input,
            transcript_seed: &request.transcript_seed,
        },
        &request.pseudonym,
        &request.proof,
    )
}

impl std::fmt::Debug for NymAuthProveRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NymAuthProveRequest(redacted)")
    }
}

impl std::fmt::Debug for NymAuthProveResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NymAuthProveResponse({} proof bytes, redacted)",
            self.proof.len()
        )
    }
}

/// Derives the SessionTranscript (the transcript seed) and `e2` (the challenge digest) for the
/// DC API handover, exactly per SPEC.md section 3. `jwk_thumbprint` is the 32-byte thumbprint of
/// the response-encryption key, or `None` for an unencrypted response. A verifier uses this
/// for its own request instead of values from the holder.
#[uniffi::export]
pub fn nymauth_derive_challenge(
    origin: String,
    nonce: String,
    doc_type: String,
    jwk_thumbprint: Option<Vec<u8>>,
) -> Result<super::NymAuthChallenge, NymAuthError> {
    super::derive_challenge(&origin, &nonce, &doc_type, jwk_thumbprint.as_deref())
}

/// `e2` for a SessionTranscript already in hand and the credential's docType.
#[uniffi::export]
pub fn nymauth_challenge_digest(
    session_transcript: Vec<u8>,
    doc_type: String,
) -> Result<Vec<u8>, NymAuthError> {
    super::challenge_digest(&session_transcript, &doc_type).map(|d| d.to_vec())
}

/// `SHA-256(client_id)`, the request's `verifier_input`.
#[uniffi::export]
pub fn nymauth_verifier_input(client_id: String) -> Result<Vec<u8>, NymAuthError> {
    super::verifier_input(&client_id).map(|d| d.to_vec())
}
