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
# Build with debug line tables, then split them off below. Without this the
# shipped .so carry no .debug_info at all and a native crash in vodozemac
# reaches Play Console as bare hex addresses that nothing can resolve after the
# fact.
#
# Set through the environment rather than [profile.release] in Cargo.toml on
# purpose: build-ios.sh builds the same --release profile, and there is no
# reason to grow the XCFramework to fix an Android symbol-upload problem.
# `line-tables-only` is what a symbolicated stack needs — full `debug = 2`
# would be several times larger for no extra benefit here.
# Scoped to this command, not exported: the host build below only exists to be
# introspected by uniffi-bindgen and has no reason to carry debug info.
CARGO_PROFILE_RELEASE_STRIP=none \
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release --lib

# Split the symbols off: the unstripped originals are set aside for upload, and
# the copies that ship are stripped back to what they were before this change,
# so the app itself grows by nothing.
echo "==> splitting debug symbols"
STRIP="$(echo "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-strip)"
[ -x "$STRIP" ] || { echo "llvm-strip not found under $ANDROID_NDK_HOME" >&2; exit 1; }

rm -rf native-debug-symbols native-debug-symbols.zip
for abi_dir in jniLibs/*/; do
    abi="$(basename "$abi_dir")"
    mkdir -p "native-debug-symbols/$abi"
    cp "$abi_dir/libepistola_crypto.so" "native-debug-symbols/$abi/"
    "$STRIP" --strip-debug --strip-unneeded "$abi_dir/libepistola_crypto.so"
done
(cd native-debug-symbols && zip -qr ../native-debug-symbols.zip .)
echo "    native-debug-symbols.zip written (upload against the release in Play Console)"

# The binding is generated from the compiled library's embedded metadata, so it
# needs a host build too — the Android .so cannot be introspected on macOS.
echo "==> generating Kotlin bindings"
cargo build --release --lib
rm -rf bindings/kotlin
cargo run -q --bin uniffi-bindgen -- generate \
    --library "target/release/libepistola_crypto.dylib" \
    --config uniffi.toml \
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
echo
echo "Symbols for this build: $(pwd)/native-debug-symbols.zip"
echo "Play Console -> the release -> App bundle explorer -> Upload native debug symbols."
echo "They match THIS build only; a rebuilt .so needs its zip re-uploaded."
