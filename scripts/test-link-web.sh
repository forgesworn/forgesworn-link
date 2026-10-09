#!/usr/bin/env bash
# WASM timer and shutdown regressions, run in Node.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
scripts/build-link-web.sh --check
if [[ -n "${WASI_SDK:-}" ]]; then
    export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-${WASI_SDK}/bin/clang}"
    export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-${WASI_SDK}/bin/llvm-ar}"
fi
export RUSTFLAGS='--cfg getrandom_backend="wasm_js"'
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_TEST_TIMEOUT=15
cargo test --locked --target wasm32-unknown-unknown -p link-endpoint --lib cancelled_open_and_replaced
cargo test --locked --target wasm32-unknown-unknown -p link-web --lib
