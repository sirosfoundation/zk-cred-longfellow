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

## Request values: derive them, do not copy them

A verifier derives `challenge_digest` (`e2`) and `transcript_seed` (the SessionTranscript) from its
own origin, nonce and the credential's docType, exactly as SPEC.md section 3 defines them:

* Rust `derive_challenge(origin, nonce, doc_type, jwk_thumbprint: Option<&[u8]>)`,
  `challenge_digest(session_transcript, doc_type)`, `verifier_input(client_id)`;
* UniFFI `nymauth_derive_challenge`, `nymauth_challenge_digest`, `nymauth_verifier_input`;
* C `nymauth_derive_challenge`, `nymauth_challenge_digest`, `nymauth_verifier_input`.

They refuse an empty origin or docType, a nonce under 16 characters, fields over 4096 bytes and a
thumbprint that is not 32 bytes. The same algorithm is in zk-cred-vega. Both are tested against
`test-vectors/nymauth/challenge-vectors.json`, which is byte-identical in the two repositories
(including `e2` `205f2280...d1a0` for the Kotlin fixture transcript).

The prover and verifier validate the request: `transcript_seed` is 32 to 65,536 bytes (a
SessionTranscript with a 32-byte handover hash is over 50 bytes; the floor only rejects empty and
trivial seeds); `T` is `YYYY-MM-DDThh:mm:ssZ`; `E` and `C` are `YYYY-MM-DD`; all digits only and
calendar-valid (leap years included), `E` may be the sentinel `0000-00-00`, and `E <= C`. This is the
same digit-only, calendar-valid rule as the Vega library.

## Circuit artifact and the allowlist

The catalog serves the archive's `circuits.zst`: one zstd frame holding the signature circuit then
the hash circuit in the `LFC2` serialization of Google's newer Rust runtime. The caller passes the
decompressed bytes.

Nothing about a circuit is trusted from the catalog descriptor or from the artifact. Every usable
build has one entry in `src/nymauth/profile.rs`, keyed by the hash circuit id, which fixes:

* the signature circuit id;
* the artifact's exact length and SHA-256 (checked first, before anything is parsed or allocated);
* the canonical Ligero `block_enc` of both circuits (the descriptor must equal them);
* the input counts of both circuits;
* the slot map (`profiles/<build>.tsv`, the circuit's `hash-semantic.tsv`).

After that check, `src/nymauth/lfc2.rs` converts the LFC2 pair to the layout `Circuit` decodes
(exactly two circuits, nothing after them, bounded output); the recomputed circuit ids must equal the
stored ids (the transcript binds the stored one) and the descriptor's. The legacy layout is no longer
accepted. The decompressed catalog hash is the same SHA-256 that the entry pins.

### Adding a circuit build

The circuit author supplies, for each new build:

1. the decompressed artifact (signature circuit, then hash circuit, LFC2): its exact length and
   SHA-256;
2. the two circuit ids (hex) and the two `block_enc` values, as in the catalog descriptor;
3. the input counts (`ninputs`, `npub`) of both circuits;
4. `hash-semantic.tsv`: the profile line (`profile B_sig B_item B_ssc`) and the slot map.

Then add the `.tsv` under `src/nymauth/profiles/` and append one `Entry` to `ENTRIES` in
`profile.rs`. Nothing else in the crate names a circuit. A unit test checks that every entry's slot
map tiles the hash circuit's private input slots exactly once; add the build's fixtures to the tests
the same way as the existing build. A build whose input layout differs from SPEC.md section L3
(order or placement of the public values, the MAC tags, the private blocks) needs code, not only an
entry.

### Failing closed

* A hash circuit id with no entry: `UnsupportedCircuit`, before the artifact is looked at.
* A listed id with a different signature circuit id, `block_enc`, artifact length or SHA-256,
  stored id, ids or input counts: `Circuit`. This includes every artifact that is not exactly the
  listed build, and every attempt to feed a different circuit with a listed id.
* Over C and UniFFI these are statuses `-3` and `-2` and the flat `NymAuthError` variants; the
  loaders return no handle.

## Tests

`cargo test --release --lib nymauth::` (add `--features uniffi` for the UniFFI tests). The Go (cgo) smoke test is `make go-cabi-nymauth-smoke` (`go-cabi-smoketest/nymauth`): it loads the verifier from the circuit and parameters, derives the challenge, verifies an honest proof and reads the pseudonym, and checks that a tampered proof, another pseudonym, a short seed and an unlisted circuit are refused. Fixtures are in
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

* mdoc only. The SD-JWT VC circuits have a different hash input layout and are refused by circuit id
  (no allowlist entry).
* Proofs are about 620 kB, against 344 kB from Google's runtime on the same circuits: this crate's
  Ligero masks are full-field elements, so rows that hold only subfield values do not get the compact
  subfield encoding (the cause was not isolated further). Both verifiers accept either.
* Secret handling. `secret_seed` is copied once; the copy, the padded copies of it made while
  hashing, the semantic bits, the input vectors, the device signature and its r and s, the device key,
  the signed message and its digest, the issuer signature and the MAC key shares a_p are zeroed on
  every exit path. What is not wiped, because it is outside this module's control: the witness,
  tableau and evaluation copies inside the proving system (private fields upstream), the transient
  field-element and `BigUint` values of the ECDSA arithmetic, and compiler spills. Error text from
  the proving system and from circuit evaluation is never forwarded (it can carry wire values);
  `Debug` of the proof, witness input and the UniFFI records prints sizes only.
* The off-circuit ECDSA arithmetic uses `num-bigint` and is not constant-time. It handles the issuer
  and device signatures, not the seed.
* Circuit-level gap, for the circuit authors: the circuits do not check that the issuer key Q or the
  device key lies on the curve. This module checks both on the host (a point off the curve is
  refused before proving), and a verifier must not rely on the circuit for it.
* Measured on one core of a Ryzen AI 5 340 (release): load 0.15 s, prove 0.8 s, verify 0.45 s, peak
  290 MB resident with a prover and a verifier loaded.

## Provenance and licence

The circuits, slot map, credential, verifier request, witnesses and proof under `src/nymauth/profiles/`
and `test-vectors/nymauth/` come from the SIROS `nym-auth-circuits` archive (owned by SIROS; no
third-party licence applies to them). `src/nymauth/lfc2.rs` implements the LFC2 format following
the reader in google/longfellow-zk (`rust/core/proto`, Apache-2.0). New source files carry
`SPDX-License-Identifier: MPL-2.0`, the licence of this repository.
