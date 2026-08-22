//! Olm core for Epistola secret chats.
//!
//! Wraps [`vodozemac`] behind a UniFFI boundary so Android and iOS link the same
//! crypto rather than each maintaining their own. The surface is deliberately
//! narrow: an [`Account`] owns long-term identity and prekeys, a [`Session`] is
//! the Double Ratchet with exactly one peer device.
//!
//! Two invariants carried over from the libsignal implementation:
//!
//! * **Native and blocking.** Nothing here suspends; callers must already be off
//!   the main thread.
//! * **Not concurrency-safe.** Olm sessions have mutable ratchet state. Every
//!   object holds its own `Mutex`, so the serialisation is enforced *here*
//!   rather than relying on the caller's discipline — this is the one place the
//!   Kotlin `SessionManager` contract gets stronger than it was.
//!
//! Keys and ciphertext cross the boundary as base64 strings, matching how the
//! server already stores key material (base64 TEXT), so nothing needs re-coding
//! on the way to the wire.

uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex};

use vodozemac::{
    Curve25519PublicKey, base64_decode, base64_encode,
    olm::{
        Account as OlmAccount, AccountPickle, OlmMessage, Session as OlmSession, SessionConfig,
        SessionPickle,
    },
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong across the boundary.
///
/// Deliberately flattened to strings: the caller's only sane responses are to
/// drop the session, warn the user, or log — none of which need the structured
/// detail vodozemac's error enums carry.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("malformed message: {0}")]
    BadMessage(String),

    #[error("pickle key must be exactly 32 bytes, got {0}")]
    BadPickleKey(usize),

    #[error("could not unpickle: {0}")]
    Pickle(String),

    #[error("could not create session: {0}")]
    SessionCreation(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    /// The message handed to `create_inbound_session` was a normal message, not
    /// a pre-key message, so there is no session to build from it.
    #[error("expected a pre-key message, got a normal message")]
    NotAPreKeyMessage,
}

type Result<T> = std::result::Result<T, CryptoError>;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// An account's long-term public identity, base64. `curve25519` establishes
/// shared secrets; `ed25519` signs. Both feed the safety-number glyph.
#[derive(uniffi::Record)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

/// A published prekey. `id` is vodozemac's own key id, echoed back by the peer
/// so the account can find the matching secret.
#[derive(uniffi::Record)]
pub struct OneTimeKey {
    pub id: String,
    pub key: String,
}

/// An Olm message split for transport. `message_type` is 0 for pre-key and 1
/// for normal; both travel in the envelope's existing `ciphertext` field.
#[derive(uniffi::Record)]
pub struct OlmMessageParts {
    pub message_type: u32,
    pub ciphertext: String,
}

/// Result of accepting a pre-key message: the session it established, and the
/// plaintext that message carried. The first message is decrypted as part of
/// session setup, so it would be lost if this only returned the session.
#[derive(uniffi::Record)]
pub struct InboundSession {
    pub session: Arc<Session>,
    pub plaintext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pickle_key(key: &[u8]) -> Result<[u8; 32]> {
    key.try_into()
        .map_err(|_| CryptoError::BadPickleKey(key.len()))
}

fn curve_key(base64: &str) -> Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_base64(base64).map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

fn to_parts(message: &OlmMessage) -> OlmMessageParts {
    let (message_type, bytes) = message.to_parts();
    OlmMessageParts {
        message_type: message_type as u32,
        ciphertext: base64_encode(bytes),
    }
}

fn from_parts(parts: &OlmMessageParts) -> Result<OlmMessage> {
    let bytes =
        base64_decode(&parts.ciphertext).map_err(|e| CryptoError::BadMessage(e.to_string()))?;
    OlmMessage::from_parts(parts.message_type as usize, &bytes)
        .map_err(|e| CryptoError::BadMessage(e.to_string()))
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

/// One per device. Holds the identity keypair and the unpublished prekeys.
///
/// Persisted by pickling to an encrypted string; on Android the pickle key is
/// the Keystore-wrapped secret that already protects SQLCipher.
#[derive(uniffi::Object)]
pub struct Account {
    inner: Mutex<OlmAccount>,
}

#[uniffi::export]
impl Account {
    /// Fresh identity. Called once per install, then immediately pickled.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(OlmAccount::new()),
        })
    }

    /// Restore from [`Account::pickle`].
    #[uniffi::constructor]
    pub fn from_pickle(pickle: String, pickle_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = self::pickle_key(&pickle_key)?;
        let pickle = AccountPickle::from_encrypted(&pickle, &key)
            .map_err(|e| CryptoError::Pickle(e.to_string()))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(OlmAccount::from_pickle(pickle)),
        }))
    }

    /// Serialise to an encrypted string. Must be re-pickled after any operation
    /// that mutates state — generating keys, or creating an inbound session.
    pub fn pickle(&self, pickle_key: Vec<u8>) -> Result<String> {
        let key = self::pickle_key(&pickle_key)?;
        Ok(self.inner.lock().unwrap().pickle().encrypt(&key))
    }

    pub fn identity_keys(&self) -> IdentityKeys {
        let keys = self.inner.lock().unwrap().identity_keys();
        IdentityKeys {
            curve25519: keys.curve25519.to_base64(),
            ed25519: keys.ed25519.to_base64(),
        }
    }

    /// Sign with the Ed25519 identity key. Used to prove the prekey bundle
    /// published to the server belongs to this device.
    pub fn sign(&self, message: String) -> String {
        self.inner.lock().unwrap().sign(message).to_base64()
    }

    /// Generate `count` new one-time keys and return everything now awaiting
    /// publication — including any generated earlier but not yet marked.
    pub fn generate_one_time_keys(&self, count: u32) -> Vec<OneTimeKey> {
        let mut account = self.inner.lock().unwrap();
        account.generate_one_time_keys(count as usize);
        collect_keys(account.one_time_keys())
    }

    /// Keys generated but not yet confirmed as published.
    pub fn one_time_keys(&self) -> Vec<OneTimeKey> {
        collect_keys(self.inner.lock().unwrap().one_time_keys())
    }

    /// How many one-time secrets are still held locally. Drops as peers consume
    /// them; the client tops up when this falls below its threshold.
    pub fn stored_one_time_key_count(&self) -> u32 {
        self.inner.lock().unwrap().stored_one_time_key_count() as u32
    }

    /// Call only after the server has acknowledged the upload — until then the
    /// keys must stay in the unpublished set so a failed upload can be retried.
    pub fn mark_keys_as_published(&self) {
        self.inner.lock().unwrap().mark_keys_as_published();
    }

    /// Rotate the fallback key, used when a peer has exhausted the one-time
    /// keys. Returns the *previous* key if one was replaced.
    pub fn generate_fallback_key(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .generate_fallback_key()
            .map(|k| k.to_base64())
    }

    pub fn fallback_key(&self) -> Option<OneTimeKey> {
        collect_keys(self.inner.lock().unwrap().fallback_key())
            .into_iter()
            .next()
    }

    /// Start a session from a peer's published bundle. The caller has already
    /// verified the bundle's signature against the peer's Ed25519 key.
    pub fn create_outbound_session(
        &self,
        identity_key: String,
        one_time_key: String,
    ) -> Result<Arc<Session>> {
        let session = self
            .inner
            .lock()
            .unwrap()
            .create_outbound_session(
                SessionConfig::version_1(),
                curve_key(&identity_key)?,
                curve_key(&one_time_key)?,
            )
            .map_err(|e| CryptoError::SessionCreation(e.to_string()))?;

        Ok(Arc::new(Session {
            inner: Mutex::new(session),
        }))
    }

    /// Accept a pre-key message. Consumes the one-time key it names, so the
    /// account **must** be re-pickled afterwards or the key is reusable.
    pub fn create_inbound_session(
        &self,
        their_identity_key: String,
        message: OlmMessageParts,
    ) -> Result<InboundSession> {
        let OlmMessage::PreKey(prekey) = from_parts(&message)? else {
            return Err(CryptoError::NotAPreKeyMessage);
        };

        let result = self
            .inner
            .lock()
            .unwrap()
            .create_inbound_session(
                SessionConfig::version_1(),
                curve_key(&their_identity_key)?,
                &prekey,
            )
            .map_err(|e| CryptoError::SessionCreation(e.to_string()))?;

        Ok(InboundSession {
            session: Arc::new(Session {
                inner: Mutex::new(result.session),
            }),
            plaintext: result.plaintext,
        })
    }
}

fn collect_keys(
    keys: std::collections::HashMap<vodozemac::KeyId, Curve25519PublicKey>,
) -> Vec<OneTimeKey> {
    let mut keys: Vec<_> = keys
        .into_iter()
        .map(|(id, key)| OneTimeKey {
            id: id.to_base64(),
            key: key.to_base64(),
        })
        .collect();
    // HashMap order is not stable; sort so upload batches and tests are.
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    keys
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A ratchet with exactly one peer device. Secret chats are pinned to a device
/// pair, so a conversation has exactly one of these on each side.
#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<OlmSession>,
}

#[uniffi::export]
impl Session {
    /// Restore from [`Session::pickle`].
    #[uniffi::constructor]
    pub fn from_pickle(pickle: String, pickle_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = self::pickle_key(&pickle_key)?;
        let pickle = SessionPickle::from_encrypted(&pickle, &key)
            .map_err(|e| CryptoError::Pickle(e.to_string()))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(OlmSession::from_pickle(pickle)),
        }))
    }

    /// Serialise to an encrypted string. Every encrypt and decrypt advances the
    /// ratchet, so this must be written back after each one — losing a pickle
    /// loses the ability to decrypt everything that follows.
    pub fn pickle(&self, pickle_key: Vec<u8>) -> Result<String> {
        let key = self::pickle_key(&pickle_key)?;
        Ok(self.inner.lock().unwrap().pickle().encrypt(&key))
    }

    /// Stable identifier, used to match an incoming message to a stored session.
    pub fn session_id(&self) -> String {
        self.inner.lock().unwrap().session_id()
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<OlmMessageParts> {
        let message = self
            .inner
            .lock()
            .unwrap()
            .encrypt(&plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        Ok(to_parts(&message))
    }

    pub fn decrypt(&self, message: OlmMessageParts) -> Result<Vec<u8>> {
        let message = from_parts(&message)?;
        self.inner
            .lock()
            .unwrap()
            .decrypt(&message)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    /// Stand up both sides the way the app will: Bob publishes a bundle, Alice
    /// fetches it and opens the session with her first message.
    fn handshake() -> (Arc<Account>, Arc<Account>, Arc<Session>, Arc<Session>) {
        let alice = Account::new();
        let bob = Account::new();

        let bob_otk = bob.generate_one_time_keys(1).remove(0);
        bob.mark_keys_as_published();

        let alice_session = alice
            .create_outbound_session(bob.identity_keys().curve25519, bob_otk.key)
            .expect("outbound session");

        let hello = alice_session.encrypt(b"hello".to_vec()).unwrap();
        assert_eq!(hello.message_type, 0, "first message must be a pre-key");

        let inbound = bob
            .create_inbound_session(alice.identity_keys().curve25519, hello)
            .expect("inbound session");
        assert_eq!(inbound.plaintext, b"hello");

        (alice, bob, alice_session, inbound.session)
    }

    #[test]
    fn full_round_trip() {
        let (_alice, _bob, alice_session, bob_session) = handshake();

        // Bob replies; Alice reads it. This is the step that proves the ratchet
        // advanced correctly on both sides, not just that setup worked.
        let reply = bob_session
            .encrypt("hi back \u{1f512}".as_bytes().to_vec())
            .unwrap();
        assert_eq!(
            alice_session.decrypt(reply).unwrap(),
            "hi back \u{1f512}".as_bytes()
        );

        // Now that Alice has heard back, her next message is a normal one.
        let second = alice_session.encrypt(b"and again".to_vec()).unwrap();
        assert_eq!(second.message_type, 1);
        assert_eq!(bob_session.decrypt(second).unwrap(), b"and again");

        assert_eq!(alice_session.session_id(), bob_session.session_id());
    }

    #[test]
    fn survives_pickling_mid_conversation() {
        let (_alice, _bob, alice_session, bob_session) = handshake();

        // Simulate the app being killed between messages: both sides go to disk
        // and come back. Ratchet state must survive or history is lost.
        let alice_session =
            Session::from_pickle(alice_session.pickle(KEY.to_vec()).unwrap(), KEY.to_vec())
                .unwrap();
        let bob_session =
            Session::from_pickle(bob_session.pickle(KEY.to_vec()).unwrap(), KEY.to_vec()).unwrap();

        let message = alice_session.encrypt(b"after restart".to_vec()).unwrap();
        assert_eq!(bob_session.decrypt(message).unwrap(), b"after restart");
    }

    #[test]
    fn account_pickle_preserves_identity_and_keys() {
        let account = Account::new();
        account.generate_one_time_keys(5);
        let identity = account.identity_keys();
        let keys = account.one_time_keys();

        let restored =
            Account::from_pickle(account.pickle(KEY.to_vec()).unwrap(), KEY.to_vec()).unwrap();

        assert_eq!(restored.identity_keys().curve25519, identity.curve25519);
        assert_eq!(restored.identity_keys().ed25519, identity.ed25519);
        assert_eq!(restored.one_time_keys().len(), keys.len());
        assert_eq!(restored.stored_one_time_key_count(), 5);
    }

    #[test]
    fn one_time_key_is_consumed_by_inbound_session() {
        let (_alice, bob, _a, _b) = handshake();
        // The key Alice used is gone, so a replay cannot open a second session.
        assert_eq!(bob.stored_one_time_key_count(), 0);
    }

    #[test]
    fn rejects_wrong_pickle_key() {
        let account = Account::new();
        let pickled = account.pickle(KEY.to_vec()).unwrap();
        assert!(matches!(
            Account::from_pickle(pickled, [9u8; 32].to_vec()),
            Err(CryptoError::Pickle(_))
        ));
    }

    #[test]
    fn rejects_short_pickle_key() {
        let account = Account::new();
        assert!(matches!(
            account.pickle(vec![0u8; 16]),
            Err(CryptoError::BadPickleKey(16))
        ));
    }

    #[test]
    fn rejects_normal_message_as_session_opener() {
        let (alice, _bob, alice_session, bob_session) = handshake();
        // Drive the session to normal messages, then try to open with one.
        let reply = bob_session.encrypt(b"x".to_vec()).unwrap();
        alice_session.decrypt(reply).unwrap();
        let normal = alice_session.encrypt(b"y".to_vec()).unwrap();
        assert_eq!(normal.message_type, 1);

        let fresh = Account::new();
        assert!(matches!(
            fresh.create_inbound_session(alice.identity_keys().curve25519, normal),
            Err(CryptoError::NotAPreKeyMessage)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let (_alice, _bob, alice_session, bob_session) = handshake();
        let mut message = alice_session.encrypt(b"authentic".to_vec()).unwrap();

        // Flip a byte in the payload.
        let mut bytes = base64_decode(&message.ciphertext).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        message.ciphertext = base64_encode(bytes);

        assert!(bob_session.decrypt(message).is_err());
    }

    #[test]
    fn signature_is_base64_and_stable() {
        let account = Account::new();
        let signature = account.sign("prekey-bundle".to_string());
        assert!(base64_decode(&signature).is_ok());
        assert_eq!(signature, account.sign("prekey-bundle".to_string()));
    }
}
