# Epistola Crypto

Olm core for Epistola **secret chats**, shared by the Android and iOS clients.

The Rust crate wraps [vodozemac](https://github.com/matrix-org/vodozemac)
behind UniFFI. The [Android](https://github.com/Alexxfromgit/Epistola-Android)
and [iOS](https://github.com/Alexxfromgit/Epistola-iOS) clients use generated
Kotlin and Swift bindings to the same Olm implementation. Both client
repositories are private.

Cloud chats do not touch this crate at all — they are server-stored plaintext.
This exists only for the opt-in, 1:1, device-bound secret chats.

## Scope

Secret chats are 1:1 and pinned to a device pair, which removes almost
everything a general messenger crypto layer normally carries:

| | |
|---|---|
| Ratchet | Olm (Double Ratchet), one session per device pair |
| Group messaging | none — groups are cloud-only |
| Multi-device | none — a secret chat lives on the device that created it |
| Post-quantum | none — Olm is Curve25519 only |

## API

`Account` owns the long-term identity and prekeys; `Session` is the ratchet with
one peer. Keys and ciphertext cross the boundary as base64 strings, matching how
the server already stores key material.

```
Account()                                  Session
Account.fromPickle(pickle, key)              .fromPickle(pickle, key)
  .pickle(key)                               .pickle(key)
  .identityKeys()                            .sessionId()
  .sign(message)                             .encrypt(plaintext)
  .generateOneTimeKeys(count)                .decrypt(message)
  .oneTimeKeys()
  .storedOneTimeKeyCount()
  .markKeysAsPublished()
  .generateFallbackKey() / .fallbackKey()
  .createOutboundSession(identityKey, oneTimeKey)
  .createInboundSession(theirIdentityKey, message)
```

### Threading

- Calls are synchronous. Run them off the main thread.
- Each `Account` and `Session` has its own Rust mutex to serialize operations
  on that object.

### Persistence

Both types pickle to a string encrypted with a 32-byte key; on Android that is
the Keystore-wrapped secret already protecting SQLCipher. Anything that mutates
state must be re-pickled:

* `createInboundSession` consumes a one-time key — re-pickle the **account** or
  the key stays replayable.
* Every `encrypt` and `decrypt` advances the ratchet — re-pickle the **session**
  or everything after it becomes undecryptable.

## Building

Install stable Rust with Cargo and rustup. Run host tests from the crate root.
These tests use the host compiler and link no Android or iOS SDK.

```bash
cargo test --locked
```

### Android

Run the mobile build on macOS. Install the Android NDK, point
`ANDROID_NDK_HOME` at the installed NDK, and install `cargo-ndk` and the
cross-compilation targets.

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
export ANDROID_NDK_HOME=/path/to/android/sdk/ndk/27.2.12479018
./build-android.sh ../Epistola-Android
```

The script builds stripped libraries for `arm64-v8a`, `armeabi-v7a`, and
`x86_64` under `jniLibs/` and generates Kotlin bindings under
`bindings/kotlin/`. It copies them into the Android checkout supplied on the
command line. Keep `native-debug-symbols.zip` with the release built from the
same libraries for Play Console crash symbolication.

### iOS and macOS host tests

On macOS with Xcode installed and selected, add the Apple Rust targets and
build the framework.

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin
./build-ios.sh
```

The script writes `ios/EpistolaCrypto.xcframework` and Swift bindings under
`bindings/swift/`. The XCFramework contains arm64 slices for iOS devices,
iOS Simulator, and macOS host tests.

Bindings are generated from the *compiled host library's* embedded metadata, not
from a `.udl` file, which is why both scripts do a host build before running
`uniffi-bindgen`.

## Verified

Host: 9 `cargo test` cases — handshake, ratchet, pickling mid-conversation,
one-time key consumption, tampered ciphertext, wrong pickle key.

Through the real FFI, against the built native library:

* **Kotlin/JVM** — 22 checks including out-of-order delivery and 400 concurrent
  encrypts on one session from 8 threads.
* **Swift** — 18 checks covering the same ground.
* **Cross-language** — Kotlin opens a session and pickles Bob's account; Swift
  restores that pickle, decrypts Kotlin's pre-key message, and replies; Kotlin
  decrypts the reply. Pickle format and wire format are identical across the two
  generated bindings, which is what lets Android and iOS interoperate.

## Size

Stripped, arm64-v8a:

| | |
|---|---|
| `libsignal_jni.so` | 6.4 MB |
| `libepistola_crypto.so` | 0.9 MB |

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the crate licence
and third-party notices.

## Security

This wrapper has not had an independent security audit. `vodozemac`, the Olm
implementation it wraps, has. Nothing here modifies vodozemac's cryptographic
code — this crate only adds the UniFFI boundary, pickling, and mutex
serialisation around it — but treat the wrapper itself as unaudited.
