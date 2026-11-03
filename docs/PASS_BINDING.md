# Pass binding: exposing a wallet credential as a short-lived pass

Status: draft design, for discussion. Nothing here is implemented. Related reading: the SEDI
"Credential Equivalence Proofs (CEPs)" proposal (Reed, Miller, Leon, V2, 2026-10-09) and
[`NYMAUTH.md`](NYMAUTH.md).

## 1. Problem

A holder has a primary credential (an ISO mdoc) in our wallet app. For some interactions (boarding,
venue entry, transit, member access) the holder wants a **pass** in a platform wallet (Apple Wallet,
Google Wallet) or another wallet. The pass is a simplified, short-lived object that a participating
**pass verifier** (gate, reader, back end) can check quickly, often offline and often by tapping or
scanning, without the holder opening our app.

We want participating pass verifiers to be able to validate, with zero-knowledge, that **the pass is
bound to a valid primary credential held by the same person**, without learning the credential, its
issuer signature, or any attribute beyond what the pass shows.

This is the "app-to-pass" case of CEPs: the secondary credential is the pass, and the CEP is the
binding proof. It differs from the general CEP proposal in two ways that shape the whole design:

1. The pass is **not a verifiable credential**. Platform wallets hold issuer-signed pass objects
   with small payloads. We cannot put a ZK proof in them or run holder-side cryptography at the gate.
2. Pass verifiers are a **closed, participating set**, so we can require them to implement
   verification and to trust a registry.

## 2. Goals and non-goals

Goals

* G1. A pass is cryptographically bound to a primary credential: it can only be obtained by someone
  who holds a valid credential and its device key, and a verifier can check that.
* G2. The binding reveals nothing beyond the pass's own claims (for example "over 18", "ticket
  class", a pass identifier). No issuer signature, no unique credential identifier, no unrelated claims.
* G3. Different passes from the same credential are unlinkable by verifiers (and by the pass issuer
  across unrelated contexts), unless the holder chooses otherwise.
* G4. Passes are short-lived; lifecycle is by expiry and refresh, not revocation lists.
* G5. Works with today's platform wallets as pass carriers, using only what they already accept.
* G6. A first phase that needs **no new circuit**: it reuses the existing `nymauth` proof.

Non-goals

* Making the platform wallet verify ZK proofs. It will not.
* Defeating a holder who deliberately shares a pass with another person. Section 9 states what is
  and is not prevented.
* Replacing issuer-native ZK credentials. If the primary issuer supports ZK natively, use that.

## 3. Roles

| Role | Description |
|---|---|
| Primary issuer | Issues the mdoc, signs the MSO. Unchanged, learns nothing about passes. |
| Wallet app | Our app. Holds the mdoc and the device key. Runs the prover (`zk-cred-longfellow`). |
| Pass issuer (PI) | Service that creates and signs the pass. May be the verifier's operator, an aggregator, or a service we run. Runs the verifier for the binding proof. |
| Platform wallet | Stores and displays the pass. Treated as an untrusted carrier. |
| Pass verifier (PV) | Gate, reader or back end that checks the pass. Participating verifiers can also check the binding. |
| Registry | Trust list of pass issuers, their signing keys, accepted primary issuer keys (Q), accepted circuit profiles. |

## 4. The binding statement

The prover shows, in zero knowledge, the following (this is what `nymauth` already proves, see
`NYMAUTH.md` "What it proves"):

* S1. A credential exists that is signed under an accepted primary issuer key Q and has an accepted
  docType.
* S2. The claim predicate holds. In phase 0 this is the existing predicate: birth date in `[E, C]`
  and validity at time `T`.
* S3. The device key in the credential signed the challenge `e2`, where `e2` is derived from the
  session transcript. The transcript commits to the pass issuer's origin and nonce, and optionally to
  the thumbprint of a **pass key** `Kp` (the `jwk_thumbprint` argument of `derive_challenge`).
* S4. **Pass nym** `N = SHA-256(DST || secret_seed || 0x00*32 || SHA-256(verifier_id))`, where
  `SHA-256(secret_seed)` is the `ssc` value signed in the credential.

The pass binding is S4 with a verifier id that names the pass:

```
verifier_id = "pass:v1:" || pass_issuer_id || ":" || pass_serial
```

The pass carries `N`. Because `secret_seed` is committed in the signed credential, only a holder of the
credential can produce an `N` consistent with S1 to S3, and `N` is different for every `pass_serial`
(G3). Nothing in the pass reveals `secret_seed`, `ssc` or the issuer signature.

Because `verifier_id` is just an input, **phase 0 needs no circuit change** and no new profile entry.

## 5. What goes in the pass

The pass is a normal platform pass issued by the PI. Besides its display fields it carries a compact
binding block:

| Field | Size | Purpose |
|---|---|---|
| `pass_serial` | 16 bytes | Unique per pass, part of `verifier_id` |
| `nym` (`N`) | 32 bytes | S4 value |
| `pred` | few bytes | Which predicate S2 proved (for example `age>=18`) and the `E`, `C`, `T` window |
| `kp` (optional) | 32 bytes | Thumbprint of the pass key bound by S3 (Tier B) |
| `proof_ref` | URL or id | Where the full proof bundle can be fetched (Tier A2) |
| `exp` | 4 bytes | Short expiry |
| PI signature | 64 bytes | Over all of the above, by the PI's registered key |

The Longfellow proof is far too large for a barcode or NFC payload, which is why the pass carries a
commitment (`N`) and a reference, not the proof. Sizes of the real proof and verification time on
reader hardware must be benchmarked before choosing tiers (open question 1).

## 6. Flows

### 6.1 Provisioning (app to pass issuer)

1. App asks the PI for a pass for context `ctx` (event, flight, venue).
2. PI creates `pass_serial` and a fresh nonce, and returns the request: origin, nonce, predicate
   window, `verifier_id`. The PI derives `e2` and the transcript seed itself with `derive_challenge`
   (never copied from the holder, see `NYMAUTH.md`).
3. App checks that the PI is in the registry and that `verifier_id` has the pass form, and shows the
   consent screen (what the pass will reveal).
4. App runs `NymAuthProver::prove`, which returns `{proof, pseudonym = N}`.
5. PI runs `NymAuthVerifier::verify(request, N, proof)`. On success it signs and issues the pass with
   `N`. It stores the proof bundle (`proof`, request) under `proof_ref` if Tier A2 is offered.
6. App adds the pass to the platform wallet (PKPass or Google Wallet pass object).

The PI learns: the predicate result, `N`, and whatever the app discloses for the context. It does not
learn the credential, `secret_seed`, or an identifier linking this pass to other passes.

### 6.2 Verification at the gate

Participating verifiers choose a tier. They can all run the same registry data.

* **Tier A1, issuer-attested.** PV reads the pass, checks the PI signature, `exp` and context. The
  binding was verified by the PI at issuance (step 5). PV trusts the PI for it. Offline and fast.
  This is the baseline, and what a non-participating verifier effectively gets.
* **Tier A2, verifier-validated ZK binding.** As A1, plus PV obtains the proof bundle via `proof_ref`
  (online, or pre-fetched for the day's passes), re-derives the request from the pass fields, and runs
  `NymAuthVerifier::verify(request, N, proof)` itself. PV then no longer trusts the PI for the binding,
  only for pass identity and context. It can be done lazily (audit, or on first sight of a pass).
* **Tier B, live possession.** The app (open, nearby) answers a fresh PV challenge with a signature
  from `kp` (and, if the PV wants a fresh ZK proof, a new `nymauth` proof under a PV-chosen
  `verifier_id`). Because `kp` was bound by S3 at provisioning, the PV checks pass, `kp` and the
  credential together. This is the only tier that resists copying of the pass.

A deployment can mix tiers per context (for example A1 at a low-risk gate, A2 for age-restricted sales,
B for high-value access).

### 6.3 Refresh and expiry

* Passes are short-lived (minutes to days by context). The app refreshes them by repeating 6.1 with a
  new `pass_serial`, so the new `N` is unlinkable to the old one.
* A refresh can be silent while the app runs in the background and the user has pre-consented to the
  context. Otherwise it needs the user to open the app.
* Platform pass update mechanisms (push-updated passes, rotating barcode tokens) are the transport.
  Which of these a given wallet allows, and the size and frequency limits, must be checked against
  current Apple and Google documentation. This document has not verified them.

### 6.4 Revocation

There is no pass revocation list. The PI checks the primary credential's status (if the issuer
publishes one) at provisioning, and short expiry bounds the exposure. A PV that needs faster
revocation uses Tier B or a PI-side kill list keyed by `pass_serial`.

## 7. Verifier participation and trust

The registry (a signed list, versioned, fetched and cached by PVs) holds:

* PI ids, their pass signing keys, and the contexts they may issue for.
* Accepted primary issuer keys Q and docTypes per context.
* Accepted circuit profiles. The `nymauth` crate already treats circuits as an allowlist keyed by the
  hash circuit id (`src/nymauth/profile.rs`), and a PV must run only listed builds.
* Verifier-side requirements: minimum `nym` version, maximum pass lifetime, required tier per context.

A PV never trusts anything from the pass itself about a circuit or issuer key, matching the crate's
rule that nothing is trusted from the descriptor or the artifact.

## 8. Privacy analysis

* **Cross-pass unlinkability.** `N` depends on `pass_serial`, so two passes from one credential carry
  unrelated nyms, and colluding PVs cannot join them. If a context needs a stable id (loyalty), use
  a context-stable `verifier_id` instead, as an explicit, consented choice.
* **Primary issuer.** Not involved, learns nothing, cannot collude with verifiers. This preserves the
  CEP benefit.
* **Pass issuer.** Sees the proof and `N` for its own passes. It can link its own passes only if the
  holder reuses `verifier_id` parts. It cannot link them to the issuer or other PIs.
* **Disclosure.** Only the predicate and the pass's display fields. The pass fields themselves are
  visible to the platform wallet vendor, which is outside our control. The pass should contain only
  what the context needs.
* **Proof storage (A2).** A stored proof bundle holds no credential data, but is tied to `N`.
  Retention should be short and match `exp`.
* **Side channels.** `proof_ref` fetches reveal to the PI which passes are checked where. Pre-fetch
  per day or per event rather than per tap.

## 9. Threat model and residual risks

| Threat | Handled by | Residual |
|---|---|---|
| Forged pass | PI signature, registry | PI compromise |
| Pass without a real credential | S1 to S4, verified by PI (A1) or PV (A2) | A1 trusts the PI |
| Stolen credential file | Device key signature (S3), key in secure hardware | Same as the wallet today |
| Pass copied to another device | Short expiry, rotating tokens. Tier B for strong prevention | A1/A2 do not stop a deliberate share or screenshot |
| Replay of the provisioning proof | PI nonce and transcript binding, `e2` per request | None beyond nonce quality |
| Substituting another holder's `N` into a pass | `N` is bound to `secret_seed` in the signed credential | None |
| Downgrade to A1 by a malicious PI | PV-required tier per context from the registry | Registry integrity |
| Wrong or malicious circuit | Allowlist by circuit id and artifact hash | Circuit correctness. Needs ZK review, as the CEP document says |

The key honest limit: a static pass in a platform wallet is a bearer object. The ZK binding proves it
was derived from a valid credential and cannot be forged, but it does not by itself bind the
person presenting it. That needs Tier B (live app) or the platform wallet's own device binding.

## 10. Relationship to CEPs

| CEP document | This design |
|---|---|
| Secondary credential in another VC format | Secondary is a platform pass |
| CEP proves claim equivalence at presentation | Binding proof is made at provisioning, then referenced by the pass |
| Verifier must run CEP verification | Optional: A1 needs none, A2 and B run it |
| Equivalence proves identical claim values | Phase 0 proves a predicate and holder binding, not full equivalence |

A full CEP (the pass's claim values equal the credential's, in a chosen format) needs a new circuit
that reveals chosen attributes, see phase 2.

## 11. Implementation plan

Phase 0, existing circuit, no crate changes

* Define the `verifier_id` pass form and binding block encoding (this document).
* Provisioning and A1/A2 verification using `NymAuthProver`/`NymAuthVerifier` as they are.
* A reference PI service, a reference verifier (Rust and the C ABI for Go/embedded), and a pass
  generator for one carrier.
* Add test vectors for `verifier_id` encoding next to `test-vectors/nymauth/`.
* Benchmark proving on phones and verification on reader-class hardware.

Phase 1, holder binding

* Use the `jwk_thumbprint` argument of `derive_challenge` to bind `Kp` at provisioning, and define the
  Tier B challenge-response over BLE or NFC.

Phase 2, richer claims

* New circuit and profile entry (`src/nymauth/profile.rs` allowlist) that discloses selected
  attributes (ticket class, membership level, name initials) under S1 to S3, for full equivalence.
  Needs the circuit author's artifact, ids and review.

Phase 3, optional

* Non-revocation proof of the primary credential inside the circuit, for contexts that need it.

## 12. Open questions

1. Real proof size, prover time on phones, verifier time on gate hardware. This decides whether A2 is
   per-tap or batch only.
2. What each platform wallet allows: payload size, update cadence, NFC and barcode formats, who may
   issue passes (a PI needs platform issuer accounts). Not verified here.
3. Who runs pass issuers: the verifier operator, a neutral service, or the wallet vendor.
4. Is stable pseudonymity across a context ever required, and under what consent?
5. Which claim predicates beyond age and validity are needed first.
6. Governance of the registry and who reviews circuits (the CEP document's own caveat).
