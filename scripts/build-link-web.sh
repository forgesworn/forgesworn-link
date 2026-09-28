#!/usr/bin/env bash
# Build the link-web browser package: link-web for wasm32-unknown-unknown,
# then wasm-bindgen's JavaScript and TypeScript glue.
#
#   scripts/build-link-web.sh [--target web|bundler|nodejs] [--out DIR]
#   scripts/build-link-web.sh --check
#
# Defaults: --target web, --out dist/link-web.  Every input is pinned and
# checked before building: Cargo.lock (--locked), the Rust toolchain
# (rust-toolchain.toml), the wasm-bindgen CLI (must equal the locked crate)
# and the clang that compiles ring's C code (wasi-sdk ${WASI_SDK_VERSION},
# checked by its exact version line).  Local paths are remapped out of the
# binary, so the same checkout gives the same package on any host with
# those inputs.  --check runs only the checks and exits 3 when an input is
# missing or does not match.
#
# Point WASI_SDK at a wasi-sdk directory (its clang and llvm-ar are used),
# or set CC_wasm32_unknown_unknown and AR_wasm32_unknown_unknown to the same
# clang and llvm-ar.

set -euo pipefail

WASI_SDK_VERSION=34.0
CLANG_VERSION_LINE="clang version 23.1.0-wasi-sdk (https://github.com/llvm/llvm-project 895aa2c896ada719451be2e3673c83da8ddf1141)"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=web
OUT="${REPO_ROOT}/dist/link-web"
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        *) echo "usage: $0 [--target web|bundler|nodejs] [--out DIR] | --check" >&2; exit 2 ;;
    esac
done

# A missing or mismatched input: exit 3, which --check callers read as
# "cannot build here" rather than as a failed build.
missing() {
    echo "error: $*" >&2
    exit 3
}
case "${TARGET}" in
    web|bundler|nodejs) ;;
    *) echo "error: --target must be web, bundler or nodejs" >&2; exit 2 ;;
esac

if [[ -z "${CC_wasm32_unknown_unknown:-}" ]]; then
    if [[ -n "${WASI_SDK:-}" ]]; then
        export CC_wasm32_unknown_unknown="${WASI_SDK}/bin/clang"
        export AR_wasm32_unknown_unknown="${WASI_SDK}/bin/llvm-ar"
    else
        missing "set WASI_SDK to a wasi-sdk ${WASI_SDK_VERSION} directory (or CC_wasm32_unknown_unknown and AR_wasm32_unknown_unknown)"
    fi
fi
if [[ ! -x "${CC_wasm32_unknown_unknown}" ]] && ! command -v "${CC_wasm32_unknown_unknown}" >/dev/null; then
    missing "${CC_wasm32_unknown_unknown} is not an executable clang"
fi
clang_line="$("${CC_wasm32_unknown_unknown}" --version | head -n 1)"
if [[ "${clang_line}" != "${CLANG_VERSION_LINE}" ]]; then
    missing "the wasm32 clang is not wasi-sdk ${WASI_SDK_VERSION}'s (found: ${clang_line})"
fi
if [[ -z "${AR_wasm32_unknown_unknown:-}" ]]; then
    missing "set AR_wasm32_unknown_unknown to wasi-sdk ${WASI_SDK_VERSION}'s llvm-ar"
fi

cd "${REPO_ROOT}"
if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
    missing "the wasm32-unknown-unknown target is not installed (rustup target add wasm32-unknown-unknown)"
fi

locked="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
if ! command -v wasm-bindgen >/dev/null; then
    missing "wasm-bindgen ${locked} is not installed (cargo install wasm-bindgen-cli --version ${locked} --locked)"
fi
installed="$(wasm-bindgen --version | awk '{ print $2 }')"
if [[ "${installed}" != "${locked}" ]]; then
    missing "wasm-bindgen CLI ${installed} does not match the locked crate ${locked}"
fi
if [[ "${CHECK_ONLY}" == 1 ]]; then
    echo "link-web build inputs present: wasi-sdk ${WASI_SDK_VERSION} clang, wasm32 target, wasm-bindgen ${locked}"
    exit 0
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
