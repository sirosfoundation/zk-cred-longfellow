# `zk-cred-longfellow`

A Rust implementation of the [Anonymous Credentials from ECDSA][anon-creds-ecdsa] scheme, also known
as Longfellow, following the [draft `libZK` specification][draft-google-cfrg-libzk].

This project is part of [ISRG](https://abetterinternet.org)'s research into
[digital identity][isrg-digital-identity].

[anon-creds-ecdsa]: https://eprint.iacr.org/2024/2010.pdf
[draft-google-cfrg-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
[isrg-digital-identity]: https://www.abetterinternet.org/post/humandigitalidentityspace/

## Foreign language bindings

Run `wasm-pack build` to produce a WASM build with JavaScript bindings.

Run the following commands to produce a native build with bindings for Kotlin, Swift, or other
languages.

```bash
cargo build --release --features uniffi
cargo run \
    --features uniffi \
    --bin uniffi-bindgen \
    generate \
    --library target/release/libzk_cred_longfellow.so
    --language <LANGUAGE>
    --out-dir out
```

## nym_auth prover

`zk_cred_longfellow::nymauth` proves and verifies the `longfellow-nymauth` mdoc circuits (age range,
validity, issuer and device signatures, and the verifier-specific pseudonym). It is separate from the
generic mdoc entry points. See [`docs/NYMAUTH.md`](docs/NYMAUTH.md); the C header is
`include/zk_cred_longfellow_nymauth.h`, the UniFFI functions are `nymauth_*`, and
`make go-cabi-nymauth-smoke` runs a cgo smoke test.

Verifiers derive `e2` and the transcript seed with `derive_challenge` (SPEC.md section 3), not from
the holder.

### Circuit builds are an allowlist

The crate trusts nothing about a circuit from the catalog descriptor or the artifact. A build is
usable only if `src/nymauth/profile.rs` has an entry for it. To add a new build, the circuit author
supplies:

1. the decompressed LFC2 artifact (signature circuit, then hash circuit): its exact length and
   SHA-256;
2. both circuit ids (hex) and both Ligero `block_enc` values;
3. the input counts (`ninputs`, `npub`) of both circuits;
4. `hash-semantic.tsv` (the profile line and the slot map), added under `src/nymauth/profiles/`.

Then one `Entry` is appended to `ENTRIES`; nothing else names a circuit. Anything not on the list
fails closed: an unlisted hash circuit id is `UnsupportedCircuit` before the artifact is parsed, and
a listed id with any other artifact length or SHA-256, signature circuit id, `block_enc`, stored id
or input count is refused as `Circuit`. No handle is returned.

## Provenance

`test-vectors/nymauth/` and `src/nymauth/profiles/` are copied from the SIROS `nym-auth-circuits`
archive (SIROS-owned). `src/nymauth/lfc2.rs` follows the LFC2 reader of google/longfellow-zk
(Apache-2.0). New files are MPL-2.0 (`SPDX-License-Identifier`).
