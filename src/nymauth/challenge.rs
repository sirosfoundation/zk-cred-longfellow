// SPDX-License-Identifier: MPL-2.0

//! The verifier's challenge, derived exactly as `SPEC.md` section 3 defines it:
//!
//! ```text
//! SessionTranscript = cbor([null, null, ["OpenID4VPDCAPIHandover",
//!                           bstr(SHA-256(cbor([origin, nonce, jwk_thumbprint_or_null])))]])
//! DeviceAuthenticationBytes = #6.24(bstr(cbor(["DeviceAuthentication", SessionTranscript,
//!                           docType, #6.24(bstr(h'A0'))])))
//! message = cbor(["Signature1", bstr(h'A10126'), bstr(h''), bstr(DeviceAuthenticationBytes)])
//! e2 = SHA-256(message)
//! ```
//!
//! The SessionTranscript is the transcript seed of the proof; `e2` is `challenge_digest` of the
//! request. A verifier derives both here from its own `origin`, `nonce` and the credential's
//! `docType`, instead of trusting values from the holder, and passes them in its
//! [`super::NymAuthRequest`]. The identical algorithm is in zk-cred-vega; both are tested against
//! `test-vectors/nymauth/challenge-vectors.json`, which is byte-identical in the two repositories.

use super::{cbor, error::NymAuthError, sha::sha256};

/// Shortest accepted nonce, in characters: it is the verifier's anti-replay value.
pub const MIN_NONCE_CHARS: usize = 16;
const MAX_FIELD_BYTES: usize = 4096;

/// A derived challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NymAuthChallenge {
    /// The SessionTranscript, CBOR: the Fiat-Shamir seed (`transcript_seed`).
    pub session_transcript: Vec<u8>,
    /// `e2`, 32 bytes (`challenge_digest`).
    pub challenge_digest: Vec<u8>,
}

fn invalid(m: impl Into<String>) -> NymAuthError {
    NymAuthError::InvalidInput(m.into())
}

fn head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=255 => vec![m | 24, n as u8],
        256..=65535 => vec![m | 25, (n >> 8) as u8, n as u8],
        _ => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    }
}

fn tstr(s: &str) -> Vec<u8> {
    [head(3, s.len()), s.as_bytes().to_vec()].concat()
}

fn bstr(b: &[u8]) -> Vec<u8> {
    [head(2, b.len()), b.to_vec()].concat()
}

fn field(name: &str, v: &str) -> Result<(), NymAuthError> {
    if v.is_empty() {
        return Err(invalid(format!("{name} must not be empty")));
    }
    if v.len() > MAX_FIELD_BYTES {
        return Err(invalid(format!(
            "{name} is longer than {MAX_FIELD_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Derives the SessionTranscript and `e2` for the DC API handover.
///
/// `jwk_thumbprint` is the 32-byte JWK thumbprint of the response-encryption key, or `None`
/// (CBOR null) when the response is not encrypted. Refuses an empty origin or docType, a nonce
/// shorter than [`MIN_NONCE_CHARS`] characters, a field over 4096 bytes, and a thumbprint that
/// is not 32 bytes.
pub fn derive_challenge(
    origin: &str,
    nonce: &str,
    doc_type: &str,
    jwk_thumbprint: Option<&[u8]>,
) -> Result<NymAuthChallenge, NymAuthError> {
    field("origin", origin)?;
    field("nonce", nonce)?;
    field("doc_type", doc_type)?;
    if nonce.chars().count() < MIN_NONCE_CHARS {
        return Err(invalid(format!(
            "nonce must be at least {MIN_NONCE_CHARS} characters"
        )));
    }
    let thumb = match jwk_thumbprint {
        None => vec![0xf6],
        Some(t) if t.len() == 32 => bstr(t),
        Some(_) => return Err(invalid("jwk_thumbprint must be 32 bytes")),
    };
    let info = [head(4, 3), tstr(origin), tstr(nonce), thumb].concat();
    let st = [
        head(4, 3),
        vec![0xf6, 0xf6],
        head(4, 2),
        tstr("OpenID4VPDCAPIHandover"),
        bstr(&sha256(&info)),
    ]
    .concat();
    let digest = challenge_digest(&st, doc_type)?;
    Ok(NymAuthChallenge {
        session_transcript: st,
        challenge_digest: digest.to_vec(),
    })
}

/// `e2` for a SessionTranscript already in hand. The transcript must be one definite CBOR array
/// of three items with nothing after it; the docType must not be empty.
pub fn challenge_digest(
    session_transcript: &[u8],
    doc_type: &str,
) -> Result<[u8; 32], NymAuthError> {
    field("doc_type", doc_type)?;
    let st = session_transcript;
    let well_formed = matches!(cbor::head(st, 0), Ok((4, 3, _)))
        && matches!(cbor::end(st, 0), Ok(e) if e == st.len());
    if !well_formed {
        return Err(invalid(
            "session transcript must be one definite CBOR array of three items",
        ));
    }
    let auth = [
        head(4, 4),
        tstr("DeviceAuthentication"),
        st.to_vec(),
        tstr(doc_type),
        head(6, 24),
        bstr(&[0xa0]),
    ]
    .concat();
    let payload = [head(6, 24), bstr(&auth)].concat();
    let message = [
        head(4, 4),
        tstr("Signature1"),
        bstr(&[0xa1, 0x01, 0x26]),
        bstr(&[]),
        bstr(&payload),
    ]
    .concat();
    Ok(sha256(&message))
}

/// `verifier_input = SHA-256(client_id)`; refuses an empty client id.
pub fn verifier_input(client_id: &str) -> Result<[u8; 32], NymAuthError> {
    field("client_id", client_id)?;
    Ok(sha256(client_id.as_bytes()))
}
