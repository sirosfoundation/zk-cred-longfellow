#!/usr/bin/env bash
# Builds the in-page nym_auth prover (src/nymauth/js_api.rs) as measured in the WASM benchmark.
#   bench/wasm-build.sh <plain|simd|wide> <out dir>
# plain: baseline; simd: +simd128; wide: +wide-arithmetic (i64.mul_wide_u, i64.add128, ...),
# which needs a runtime with WebAssembly wide arithmetic (Chromium 156: --js-flags=--wasm-wide-arithmetic).
# WASM_OPT must be binaryen 133 or later for the wide variant (binaryen 116 predates it).
set -euo pipefail
variant=$1 out=$2
cd "$(dirname "$0")/.."
base='--cfg getrandom_backend="wasm_js"'
case $variant in
  plain) export RUSTFLAGS="$base" ;;
  simd)  export RUSTFLAGS="$base -C target-feature=+simd128" ;;
  wide)  export RUSTFLAGS="$base -C target-feature=+wide-arithmetic" ;;
  *) echo "variant must be plain, simd or wide" >&2; exit 2 ;;
esac
export CARGO_TARGET_DIR="target-wasm-$variant"
wasm-pack build --release --no-opt --target web --out-dir "$out" --out-name lf
"${WASM_OPT:-wasm-opt}" -O3 "$out/lf_bg.wasm" -o "$out/lf_bg.wasm"
