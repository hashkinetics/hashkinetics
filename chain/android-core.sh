#!/usr/bin/env bash
# android-core.sh -- WA1b: cross-compile hk-wallet-core for Android and generate the Kotlin bindings.
#
#   ./android-core.sh setup            # one-time: rust targets + cargo-ndk (+ says what NDK to install)
#   ./android-core.sh build            # arm64-v8a + x86_64 .so files → $OUT/jniLibs/<abi>/libhk_wallet_core.so
#   ./android-core.sh bindings         # Kotlin file from the HOST cdylib's UniFFI metadata → $OUT/kotlin/…
#   ./android-core.sh all              # build + bindings
#
# Env: ANDROID_NDK_HOME (required for build; the NDK r27 directory, e.g. ~/android/ndk/27.2.12479018)
#      HK_ANDROID_OUT   (default ../android/core-out — what the app copies into app/src/main/jniLibs and app/src/main/java)
#      CARGO_TARGET_DIR (as in every other script; default target)
#
# Why two ABIs: arm64-v8a is every phone since 2017; x86_64 is the Android Studio emulator. armeabi-v7a is
# deliberately left out (32-bit; Argon2id at 256 MiB and ML-KEM belong on 64-bit). The .so is a cdylib with
# the UniFFI metadata baked in; the Kotlin file is generated from the HOST build of the same source, so the
# two never drift (bindgen reads the proc-macro metadata, no UDL to keep in sync).
set -euo pipefail
cd "$(dirname "$0")"
OUT="${HK_ANDROID_OUT:-../android/core-out}"
TARGET="${CARGO_TARGET_DIR:-target}"
ABIS=(arm64-v8a x86_64)

case "${1:-}" in
setup)
    rustup target add aarch64-linux-android x86_64-linux-android
    cargo install cargo-ndk --locked
    echo
    echo "NDK: install r27 (LTS) and export ANDROID_NDK_HOME. Either"
    echo "  - Android Studio → SDK Manager → SDK Tools → NDK (Side by side) 27.x  → ~/Android/Sdk/ndk/27.x (Windows: %LOCALAPPDATA%\\Android\\Sdk\\ndk\\27.x)"
    echo "  - or in WSL:  mkdir -p ~/android && cd ~/android && curl -LO https://dl.google.com/android/repository/android-ndk-r27c-linux.zip && unzip -q android-ndk-r27c-linux.zip"
    echo "    export ANDROID_NDK_HOME=~/android/android-ndk-r27c"
    echo "then: ./android-core.sh all"
    ;;
build)
    [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]] || { echo "ANDROID_NDK_HOME is not set / not a directory (run: ./android-core.sh setup)"; exit 1; }
    command -v cargo-ndk >/dev/null || { echo "cargo-ndk missing (run: ./android-core.sh setup)"; exit 1; }
    mkdir -p "$OUT/jniLibs"
    for abi in "${ABIS[@]}"; do
        echo "== $abi"
        cargo ndk -t "$abi" -o "$OUT/jniLibs" --platform 26 build --release -p hk-wallet-core
        ls -la "$OUT/jniLibs/$abi/libhk_wallet_core.so"
        sha256sum "$OUT/jniLibs/$abi/libhk_wallet_core.so" | cut -c1-16
    done
    ;;
bindings)
    # The host cdylib (built by `cargo build --release -p hk-wallet-core`) carries the same metadata as the
    # Android ones — bindgen reads it from the library, no UDL.
    HOST_SO="$TARGET/release/libhk_wallet_core.so"
    [[ -f "$HOST_SO" ]] || cargo build --release -p hk-wallet-core
    mkdir -p "$OUT/kotlin"
    cargo run --release -p hk-wallet-core --features cli --bin uniffi-bindgen -- generate --library "$HOST_SO" --language kotlin --out-dir "$OUT/kotlin"
    KT=$(find "$OUT/kotlin" -name '*.kt' | head -1)
    echo "== bindings: $KT ($(wc -l < "$KT") lines)"
    grep -cE "^\s*(fun|class|interface|object) " "$KT" | sed 's/^/   declarations: /'
    grep -oE "fun [a-zA-Z]+\(" "$KT" | sort -u | tr '\n' ' ' | fold -w 160 | sed 's/^/   /'
    ;;
all)
    "$0" build
    "$0" bindings
    echo
    echo "copy into the app:  jniLibs/  → android/app/src/main/jniLibs/   ·   kotlin/org/…/hk_wallet_core.kt → android/app/src/main/java/org/hashkinetics/wallet/core/"
    ;;
*)
    echo "usage: $0 setup | build | bindings | all"; exit 1;;
esac
