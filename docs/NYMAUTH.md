# nym_auth prover and verifier

`src/nymauth/` implements the two-circuit Longfellow proof for the nym_auth mdoc circuits of the
`nym-auth-circuits` archive (SPEC.md sections L3 to L6) on this crate's own circuit, sumcheck, Ligero
and transcript code. It is a separate module: `mdoc_zk` is untouched, and `lib.rs` only gains
`pub mod nymauth;`.

## API

Rust (`zk_cred_longfellow::nymauth`):

```rust
NymAuthProver::new(circuit: &[u8], params: &NymAuthCircuitParams) -> Result<NymAuthProver, NymAuthError>
NymAuthProver::prove(&self, request: &NymAuthRequest, witness: &NymAuthWitnessInput)
    -> Result<NymAuthProof { proof: Vec<u8>, pseudonym: [u8; 32] }, NymAuthError>
NymAuthVerifier::new(circuit, params) -> Result<NymAuthVerifier, NymAuthError>
NymAuthVerifier::verify(&self, request: &NymAuthRequest, pseudonym: &[u8], proof: &[u8]) -> Result<(), NymAuthError>
```

`NymAuthCircuitParams` is the catalog descriptor's `params`: `block_enc_hash`, `block_enc_sig`,
`hash_circuit_id`, `sig_circuit_id`. `NymAuthRequest` holds what both sides know (issuer key Q, `T`,
`E`, `C`, `e2`, `SHA-256(verifier_id)`, and the transcript seed). `NymAuthWitnessInput` holds the
IssuerSigned CBOR, the 16-byte `secret_seed` and the device signature `r || s`. The device key comes
from the credential's MSO, so the request does not carry it.

Bindings:

* UniFFI (Kotlin, Swift): `nymauth_initialize_prover`, `nymauth_initialize_verifier`, `nymauth_prove`,
  `nymauth_verify` in `src/nymauth/ffi_uniffi.rs`. Errors are the flat `NymAuthError` enum.
* Plain C ABI (cgo and others): `nymauth_*` in `src/nymauth/c_abi.rs`, header
  `include/zk_cred_longfellow_nymauth.h`, staged by `make go-cabi`.

## What it proves

The issuer signed the credential under Q; docType; birth date in `[E, C]`; valid at `T`; the device key
bound in the credential signed `e2`; `SHA-256(secret_seed)` is the signed `ssc`; and the pseudonym
`SHA-256(DST || secret_seed || 0x00*32 || verifier_input)`. The prover refuses, before committing to
anything, if the inputs do not satisfy both circuits (`NymAuthError::Unsatisfied`).

## Circuit artifact

The catalog serves the archive's `circuits.zst`: one zstd frame holding the signature circuit then the
hash circuit in the `LFC2` serialization of Google's newer Rust runtime. This crate's `Circuit` reads
the older layout, so `src/nymauth/lfc2.rs` converts LFC2 to the legacy layout (expanding the delta
dictionary), and the circuit ids, recomputed from the decoded structure, are checked against the
descriptor. The legacy layout is also accepted. The caller passes the decompressed bytes.

The map from the hash circuit's semantic bits to input slots (`hash-semantic.tsv`, 1,918 runs) is not
in the descriptor. It is compiled in (`src/nymauth/profiles/`), keyed by the hash circuit id; an unknown
id is refused as `UnsupportedCircuit`. A new circuit build needs its map added there.

## Tests

`cargo test --release --lib nymauth::` (add `--features uniffi` for the UniFFI test). Fixtures are in
`test-vectors/nymauth/` (archive circuits, credential, verifier request, the archive's complete input
vectors and its proof).

* The witness equals the archive's `hash-witness.bin` and `sig-witness.bin` slot for slot, and both
  circuits evaluate to zero on them.
* The archive's proof, made by Google's runtime, verifies here. A proof made here is accepted by the
  archive's reference verifier (`nymauth-lf verify`) and refused with another pseudonym.
* A real proof verifies and reports the fixture pseudonym, for both fixture verifiers.
* Refusals: wrong seed, issuer key, device signature, challenge or credential; a request the credential
  does not meet (not yet valid, too young, too old). Proof verification refuses flipped bits (tags,
  middle, last byte), truncation, other pseudonym, verifier input, key, `e2`, time, bounds and
  transcript.
* Malformed input (every prefix of the credential, garbage proofs, bad lengths, null pointers) gives a
  typed error or status, never a panic. A fuzz target is in `fuzz/fuzz_targets/nymauth.rs`.

## Notes and limits

* mdoc only. The SD-JWT VC circuits have a different hash input layout and are refused by circuit id.
* Proofs are about 620 kB, against 344 kB from Google's runtime on the same circuits: this crate's
  Ligero masks are full-field elements, so rows that hold only subfield values do not get the compact
  subfield encoding (the cause was not isolated further). Both verifiers accept either.
* `secret_seed` is copied once and the copy, the semantic bits and the input vectors are zeroed on
  every exit path. The witness and tableau copies the proving system makes internally are not.
* The off-circuit ECDSA arithmetic uses `num-bigint` and is not constant-time. It handles the issuer
  and device signatures, not the seed.
* Measured on one core of a Ryzen AI 5 340 (release): load 0.15 s, prove 0.8 s, verify 0.45 s, peak
  290 MB resident with a prover and a verifier loaded.
