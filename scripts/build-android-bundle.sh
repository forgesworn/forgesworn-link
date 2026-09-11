#!/usr/bin/env bash
# Build the exact Android hand-off consumed by KithMoot. The result contains
# two stripped JNI libraries, UniFFI Kotlin generated from an unstripped host
# cdylib, and a manifest that identifies every byte by SHA-256.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if (( $# != 0 )); then
    echo "usage: scripts/build-android-bundle.sh" >&2
    exit 2
fi

# The manifest makes a commit-level claim. Refuse tracked local changes rather
# than assigning the current HEAD to locally modified source.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "error: build from a clean tracked worktree so the manifest commit is exact" >&2
    exit 1
fi

: "${ANDROID_NDK_HOME:=${ANDROID_NDK_ROOT:-}}"
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
    echo "error: set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an Android NDK" >&2
    exit 1
fi
export ANDROID_NDK_HOME

: "${CARGO_TARGET_DIR:=${REPO_ROOT}/target}"
export CARGO_TARGET_DIR
: "${LINK_ANDROID_OUT_DIR:=${REPO_ROOT}/dist/link-ffi-android}"
export LINK_ANDROID_OUT_DIR

if [[ -e "${LINK_ANDROID_OUT_DIR}" ]]; then
    echo "error: output already exists: ${LINK_ANDROID_OUT_DIR}" >&2
    echo "       choose an empty LINK_ANDROID_OUT_DIR; existing bundles are immutable" >&2
    exit 1
fi

mkdir -p "$(dirname "${LINK_ANDROID_OUT_DIR}")"
mkdir "${LINK_ANDROID_OUT_DIR}"
JNI_OUT="${LINK_ANDROID_OUT_DIR}/jniLibs"
KOTLIN_OUT="${LINK_ANDROID_OUT_DIR}/kotlin"
mkdir -p "${JNI_OUT}" "${KOTLIN_OUT}"

echo "==> cargo ndk -t arm64-v8a -t x86_64 -P 26 -o ${JNI_OUT} build --release -p link-ffi"
cargo ndk -t arm64-v8a -t x86_64 -P 26 -o "${JNI_OUT}" build --release -p link-ffi

HOST_EXT=so
if [[ "$(uname -s)" == Darwin ]]; then
    HOST_EXT=dylib
fi
echo "==> cargo build -p link-ffi for UniFFI metadata"
cargo build -p link-ffi
HOST_LIBRARY="${CARGO_TARGET_DIR}/debug/liblink_ffi.${HOST_EXT}"
if [[ ! -s "${HOST_LIBRARY}" ]]; then
    echo "error: no host UniFFI library at ${HOST_LIBRARY}" >&2
    exit 1
fi

echo "==> generate Kotlin bindings"
cargo run -p link-ffi --bin uniffi-bindgen --features uniffi/cli -- \
    generate --library "${HOST_LIBRARY}" --language kotlin --no-format --out-dir "${KOTLIN_OUT}"
KOTLIN_FILE="${KOTLIN_OUT}/dev/forgesworn/link/ffi/link_ffi.kt"
if [[ ! -s "${KOTLIN_FILE}" ]]; then
    echo "error: UniFFI produced no Kotlin binding" >&2
    exit 1
fi

LLVM_STRIP="$(find "${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt" -path '*/bin/llvm-strip' -print | head -n1)"
if [[ -z "${LLVM_STRIP}" || ! -x "${LLVM_STRIP}" ]]; then
    echo "error: llvm-strip not found under ${ANDROID_NDK_HOME}" >&2
    exit 1
fi

for ABI in arm64-v8a x86_64; do
    LIBRARY="${JNI_OUT}/${ABI}/liblink_ffi.so"
    if [[ ! -s "${LIBRARY}" ]]; then
        echo "error: cargo-ndk produced no ${ABI} library" >&2
        exit 1
    fi
    "${LLVM_STRIP}" --strip-all "${LIBRARY}"
done

sha256() {
    shasum -a 256 "$1" | awk '{print $1}'
}

ARM64_LIBRARY="${JNI_OUT}/arm64-v8a/liblink_ffi.so"
X86_64_LIBRARY="${JNI_OUT}/x86_64/liblink_ffi.so"
MANIFEST="${LINK_ANDROID_OUT_DIR}/manifest.json"
SOURCE_COMMIT="$(git rev-parse HEAD)"

printf '%s\n' \
    '{' \
    '  "format": 1,' \
    "  \"source_commit\": \"${SOURCE_COMMIT}\"," \
    '  "min_sdk": 26,' \
    '  "files": [' \
    "    {\"path\": \"jniLibs/arm64-v8a/liblink_ffi.so\", \"sha256\": \"$(sha256 "${ARM64_LIBRARY}")\", \"bytes\": $(wc -c < "${ARM64_LIBRARY}" | tr -d ' ')}," \
    "    {\"path\": \"jniLibs/x86_64/liblink_ffi.so\", \"sha256\": \"$(sha256 "${X86_64_LIBRARY}")\", \"bytes\": $(wc -c < "${X86_64_LIBRARY}" | tr -d ' ')}," \
    "    {\"path\": \"kotlin/dev/forgesworn/link/ffi/link_ffi.kt\", \"sha256\": \"$(sha256 "${KOTLIN_FILE}")\", \"bytes\": $(wc -c < "${KOTLIN_FILE}" | tr -d ' ')}" \
    '  ]' \
    '}' > "${MANIFEST}"

echo "==> Android bundle: ${LINK_ANDROID_OUT_DIR}"
echo "    source commit: ${SOURCE_COMMIT}"
echo "    manifest SHA-256: $(sha256 "${MANIFEST}")"
