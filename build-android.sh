#!/usr/bin/env bash
# Builds libepistola_crypto.so for every ABI the app ships and regenerates the
# Kotlin binding. Output drops straight into the Android source tree.
#
#   ./build-android.sh [path-to-Epistola]
#
# Requires: cargo-ndk (cargo install cargo-ndk) and ANDROID_NDK_HOME.
set -euo pipefail

cd "$(dirname "$0")"
APP="${1:-$HOME/AndroidStudioProjects/Epistola}"

: "${ANDROID_NDK_HOME:=$HOME/Library/Android/sdk/ndk/27.2.12479018}"
export ANDROID_NDK_HOME
[ -d "$ANDROID_NDK_HOME" ] || { echo "ANDROID_NDK_HOME not found: $ANDROID_NDK_HOME" >&2; exit 1; }

echo "==> building native libraries"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release --lib

# The binding is generated from the compiled library's embedded metadata, so it
# needs a host build too — the Android .so cannot be introspected on macOS.
echo "==> generating Kotlin bindings"
cargo build --release --lib
rm -rf bindings/kotlin
cargo run -q --bin uniffi-bindgen -- generate \
    --library "target/release/libepistola_crypto.dylib" \
    --language kotlin --out-dir bindings/kotlin

if [ -d "$APP/app/src/main" ]; then
    echo "==> installing into $APP"
    mkdir -p "$APP/app/src/main/jniLibs" "$APP/app/src/main/java/uniffi"
    rsync -a --delete jniLibs/ "$APP/app/src/main/jniLibs/"
    rsync -a --delete bindings/kotlin/uniffi/ "$APP/app/src/main/java/uniffi/"
    echo "    jniLibs + uniffi package updated"
else
    echo "!! $APP does not look like the Epistola client; left output in ./jniLibs and ./bindings"
fi

echo "done."
