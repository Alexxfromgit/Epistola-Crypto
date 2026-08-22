#!/usr/bin/env bash
# Builds EpistolaCrypto.xcframework (device + simulator) and the Swift binding.
#
#   ./build-ios.sh
#
# Drag the resulting xcframework into the iOS project, and add
# bindings/swift/epistola_crypto.swift to the target's sources.
set -euo pipefail

cd "$(dirname "$0")"
OUT="ios/EpistolaCrypto.xcframework"

echo "==> building static libraries"
cargo build --release --lib --target aarch64-apple-ios
cargo build --release --lib --target aarch64-apple-ios-sim

echo "==> generating Swift bindings"
cargo build --release --lib
rm -rf bindings/swift
cargo run -q --bin uniffi-bindgen -- generate \
    --library "target/release/libepistola_crypto.dylib" \
    --language swift --out-dir bindings/swift

# xcframework wants the modulemap named module.modulemap alongside the header,
# in a headers directory it can copy wholesale.
echo "==> assembling headers"
rm -rf ios/headers && mkdir -p ios/headers
cp bindings/swift/epistola_cryptoFFI.h ios/headers/
cp bindings/swift/epistola_cryptoFFI.modulemap ios/headers/module.modulemap

echo "==> creating xcframework"
rm -rf "$OUT"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libepistola_crypto.a \
    -headers ios/headers \
    -library target/aarch64-apple-ios-sim/release/libepistola_crypto.a \
    -headers ios/headers \
    -output "$OUT"

echo "done: $OUT"
