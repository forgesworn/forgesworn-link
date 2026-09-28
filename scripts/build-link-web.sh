#!/usr/bin/env bash
# Build the link-web browser package: link-web for wasm32-unknown-unknown,
# then wasm-bindgen's JavaScript and TypeScript glue.
#
#   scripts/build-link-web.sh [--target web|bundler|nodejs] [--out DIR]
#
# Defaults: --target web, --out dist/link-web.  The build is locked to
# Cargo.lock, uses the pinned toolchain, strips local paths from the binary
# and requires the wasm-bindgen CLI to match the locked wasm-bindgen crate
# exactly, so the same checkout gives the same package.
#
# ring's C code needs a clang that targets wasm32.  Set
# CC_wasm32_unknown_unknown and AR_wasm32_unknown_unknown, or WASI_SDK to a
# wasi-sdk directory (its clang and llvm-ar are used).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=web
OUT="${REPO_ROOT}/dist/link-web"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "usage: $0 [--target web|bundler|nodejs] [--out DIR]" >&2; exit 2 ;;
    esac
done
case "${TARGET}" in
    web|bundler|nodejs) ;;
    *) echo "error: --target must be web, bundler or nodejs" >&2; exit 2 ;;
esac

if [[ -z "${CC_wasm32_unknown_unknown:-}" ]]; then
    if [[ -n "${WASI_SDK:-}" ]]; then
        export CC_wasm32_unknown_unknown="${WASI_SDK}/bin/clang"
        export AR_wasm32_unknown_unknown="${WASI_SDK}/bin/llvm-ar"
    else
        echo "error: set CC_wasm32_unknown_unknown (and AR_...) or WASI_SDK to a wasm32-capable clang" >&2
        exit 1
    fi
fi
if [[ ! -x "${CC_wasm32_unknown_unknown}" ]] && ! command -v "${CC_wasm32_unknown_unknown}" >/dev/null; then
    echo "error: ${CC_wasm32_unknown_unknown} is not an executable clang" >&2
    exit 1
fi

cd "${REPO_ROOT}"
if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
    echo "error: the wasm32-unknown-unknown target is not installed (rustup target add wasm32-unknown-unknown)" >&2
    exit 1
fi

locked="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
if ! command -v wasm-bindgen >/dev/null; then
    echo "error: wasm-bindgen ${locked} is not installed (cargo install wasm-bindgen-cli --version ${locked} --locked)" >&2
    exit 1
fi
installed="$(wasm-bindgen --version | awk '{ print $2 }')"
if [[ "${installed}" != "${locked}" ]]; then
    echo "error: wasm-bindgen CLI ${installed} does not match the locked crate ${locked}" >&2
    exit 1
fi

CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-${HOME}/.rustup}"
export CARGO_TARGET_DIR="${LINK_WEB_TARGET_DIR:-${REPO_ROOT}/target/link-web}"
# getrandom's browser backend, then path remapping so no local directory
# ends up in panic messages inside the binary (the last matching prefix wins).
export RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\" \
--remap-path-prefix=${HOME}=/home \
--remap-path-prefix=${RUSTUP_HOME_DIR}=/rustup \
--remap-path-prefix=${CARGO_HOME_DIR}=/cargo \
--remap-path-prefix=${REPO_ROOT}=/link"

echo "==> cargo build --locked --release -p link-web --target wasm32-unknown-unknown"
cargo build --locked --release -p link-web --target wasm32-unknown-unknown

echo "==> wasm-bindgen ${installed} --target ${TARGET} --out-dir ${OUT}"
rm -rf "${OUT}"
wasm-bindgen --target "${TARGET}" --out-dir "${OUT}" \
    "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/link_web.wasm"
echo "==> ${OUT}"
ls -l "${OUT}"
