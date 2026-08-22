# Epistola Crypto

Olm core for Epistola **secret chats**, shared by the Android and iOS clients.

Wraps [vodozemac](https://github.com/matrix-org/vodozemac) (Apache-2.0) behind a
UniFFI boundary so both platforms link the same crypto instead of each
maintaining their own. Replaces libsignal, which is AGPL-3.0 and therefore
cannot ship on the App Store by anyone who does not own its copyright.

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

### Two invariants, carried over from the libsignal implementation

* **Native and blocking.** Nothing suspends; callers must already be off the
  main thread.
* **Not concurrency-safe** — except that now it is. Every object holds its own
  `Mutex` on the Rust side, so serialisation is enforced here rather than
  relying on the caller. The Kotlin `SessionManager` contract gets *stronger*
  than it was under libsignal.

### Persistence

Both types pickle to a string encrypted with a 32-byte key; on Android that is
the Keystore-wrapped secret already protecting SQLCipher. Anything that mutates
state must be re-pickled:

* `createInboundSession` consumes a one-time key — re-pickle the **account** or
  the key stays replayable.
* Every `encrypt` and `decrypt` advances the ratchet — re-pickle the **session**
  or everything after it becomes undecryptable.

## Building

```bash
cargo test                       # 9 tests, host only, no toolchain needed

./build-android.sh               # .so for 3 ABIs + Kotlin binding, installed
                                 # into ../../AndroidStudioProjects/Epistola
./build-ios.sh                   # EpistolaCrypto.xcframework + Swift binding
```

Android needs `cargo install cargo-ndk` and `ANDROID_NDK_HOME`. iOS needs the
`aarch64-apple-ios` and `aarch64-apple-ios-sim` targets.

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

Apache-2.0, matching vodozemac. This is the point of the exercise: nothing here
is AGPL, so the clients that link it need not be either.
