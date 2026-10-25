//! wasm-bindgen surface of the nym_auth prover, for a wallet that proves in the page. It mirrors
//! `nymauth_initialize_prover` and `nymauth_prove` of [`super::ffi_uniffi`]: the circuit artifact
//! and the catalog descriptor's parameters are given once, and the handle is reused for every
//! request.

use super::{NymAuthCircuitParams, NymAuthProver, NymAuthRequest, NymAuthWitnessInput, wipe};
use wasm_bindgen::prelude::{JsError, wasm_bindgen};

/// A prover loaded from one circuit artifact.
#[wasm_bindgen(js_name = NymAuthProver)]
pub struct JsNymAuthProver(NymAuthProver);

/// The proof and the pseudonym it reports.
#[wasm_bindgen(js_name = NymAuthProveResponse, getter_with_clone)]
pub struct JsNymAuthProveResponse {
    pub proof: Vec<u8>,
    pub pseudonym: Vec<u8>,
}

fn js_error(e: super::NymAuthError) -> JsError {
    JsError::new(&e.to_string())
}

/// Loads the decompressed `longfellow-nymauth` circuit artifact (signature circuit, then hash
/// circuit) with the catalog descriptor's parameters, for proving.
#[wasm_bindgen]
pub fn nymauth_initialize_prover(
    circuit: &[u8],
    block_enc_hash: u32,
    block_enc_sig: u32,
    hash_circuit_id: String,
    sig_circuit_id: String,
) -> Result<JsNymAuthProver, JsError> {
    let params = NymAuthCircuitParams {
        block_enc_hash: block_enc_hash as usize,
        block_enc_sig: block_enc_sig as usize,
        hash_circuit_id,
        sig_circuit_id,
    };
    NymAuthProver::new(circuit, &params)
        .map(JsNymAuthProver)
        .map_err(js_error)
}

/// Proves; refuses, without a proof, if the inputs do not satisfy the statement. The arguments are
/// the fields of the UniFFI `NymAuthProveRequest`, in its order. The copies of `issuer_signed`,
/// `secret_seed` and `device_signature` in WASM memory are zeroed before this returns; the caller
/// zeroes its own.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn nymauth_prove(
    prover: &JsNymAuthProver,
    mut issuer_signed: Vec<u8>,
    mut secret_seed: Vec<u8>,
    issuer_key_x: &[u8],
    issuer_key_y: &[u8],
    time: &str,
    earliest: &str,
    cutoff: &str,
    challenge_digest: &[u8],
    mut device_signature: Vec<u8>,
    verifier_input: &[u8],
    transcript_seed: &[u8],
) -> Result<JsNymAuthProveResponse, JsError> {
    let r = prover.0.prove(
        &NymAuthRequest {
            issuer_key_x,
            issuer_key_y,
            time,
            earliest,
            cutoff,
            challenge_digest,
            verifier_input,
            transcript_seed,
        },
        &NymAuthWitnessInput {
            issuer_signed: &issuer_signed,
            secret_seed: &secret_seed,
            device_signature: &device_signature,
        },
    );
    wipe::wipe(&mut secret_seed, 0);
    wipe::wipe(&mut issuer_signed, 0);
    wipe::wipe(&mut device_signature, 0);
    r.map(|p| JsNymAuthProveResponse {
        proof: p.proof,
        pseudonym: p.pseudonym.to_vec(),
    })
    .map_err(js_error)
}
