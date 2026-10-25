use std::fmt;

/// Errors from the nym_auth prover and verifier. Nothing in this module panics on bad input; every
/// failure is one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum NymAuthError {
    /// An argument has the wrong size, format or range.
    InvalidInput(String),
    /// The circuit artifact is malformed, or its parameters or ids do not match.
    Circuit(String),
    /// The circuit is well-formed but is not one this module knows how to build a witness for.
    UnsupportedCircuit(String),
    /// The IssuerSigned structure does not follow the nym_auth issuance profile.
    Credential(String),
    /// The inputs do not satisfy the statement (for example a wrong seed, key or signature).
    /// No proof is produced.
    Unsatisfied(String),
    /// The proving system failed.
    Prover(String),
    /// The proof bytes do not decode: a short or malformed proof, or bytes after its end.
    ProofEncoding(String),
    /// The proof decodes, and a circuit's proof does not verify for the request.
    Verification(String),
}

impl fmt::Display for NymAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, msg) = match self {
            Self::InvalidInput(m) => ("invalid input", m),
            Self::Circuit(m) => ("circuit", m),
            Self::UnsupportedCircuit(m) => ("unsupported circuit", m),
            Self::Credential(m) => ("credential", m),
            Self::Unsatisfied(m) => ("statement not satisfied", m),
            Self::Prover(m) => ("prover", m),
            Self::ProofEncoding(m) => ("proof encoding", m),
            Self::Verification(m) => ("verification failed", m),
        };
        write!(f, "nymauth {kind}: {msg}")
    }
}

impl std::error::Error for NymAuthError {}

pub(super) fn credential(m: impl Into<String>) -> NymAuthError {
    NymAuthError::Credential(m.into())
}
