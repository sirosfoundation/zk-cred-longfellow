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
`include/zk_cred_longfellow_nymauth.h` and the UniFFI functions are `nymauth_*`.
