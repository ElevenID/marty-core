//! ISO 18013-5 session management
//!
//! This module handles session establishment, encryption, and key derivation
//! for secure communication between mDL holder and reader.

use crate::error::{Error, Result};
use marty_crypto::ecdh::P256KeyPair;
use marty_crypto::kdf::derive_mdl_session_keys;
use marty_crypto::symmetric::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};
use zeroize::{Zeroize, Zeroizing};

/// Session encryption and decryption state
pub struct SessionEncryption {
    /// Key used for messages sent by this party.
    send_key: Vec<u8>,

    /// Key used for messages received by this party.
    receive_key: Vec<u8>,

    /// Message counter for encryption
    send_counter: u32,

    /// Message counter for decryption (validation)
    receive_counter: u32,

    /// Direction identifiers used in ISO 18013-5 initialization vectors.
    send_is_device: bool,
    receive_is_device: bool,
}

impl Drop for SessionEncryption {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

impl SessionEncryption {
    /// Create new session encryption from ECDH shared secret
    #[cfg(test)]
    pub fn new(shared_secret: &[u8], session_transcript: &[u8]) -> Result<Self> {
        let (device_key, _) = derive_mdl_session_keys(shared_secret, session_transcript)?;

        Ok(Self {
            send_key: device_key.clone(),
            receive_key: device_key,
            send_counter: 0,
            receive_counter: 0,
            send_is_device: true,
            receive_is_device: true,
        })
    }

    /// Create directional encryption state for one protocol peer.
    ///
    /// `send_as_device` selects the ISO 18013-5 direction: a device sends
    /// with SKDevice and receives with SKReader; a reader does the reverse.
    pub fn new_directional(
        shared_secret: &[u8],
        session_transcript: &[u8],
        send_as_device: bool,
    ) -> Result<Self> {
        let (device_key, reader_key) = derive_mdl_session_keys(shared_secret, session_transcript)?;
        let (send_key, receive_key) = if send_as_device {
            (device_key, reader_key)
        } else {
            (reader_key, device_key)
        };

        Ok(Self {
            send_key,
            receive_key,
            send_counter: 0,
            receive_counter: 0,
            send_is_device: send_as_device,
            receive_is_device: !send_as_device,
        })
    }

    /// Encrypt a message with AES-256-GCM
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let next_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| Error::Encryption("message counter exhausted".to_string()))?;

        // ISO 18013-5 starts message counters at one. `new()` is the
        // symmetric compatibility constructor and uses the device direction.
        let mut iv = [0u8; 12];
        iv[7] = u8::from(self.send_is_device);
        iv[8..].copy_from_slice(&next_counter.to_be_bytes());

        let ciphertext = aes_256_gcm_encrypt(&self.send_key, &iv, plaintext, &[])?;

        self.send_counter = next_counter;
        Ok(ciphertext)
    }

    /// Decrypt a message with AES-256-GCM
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let next_counter = self
            .receive_counter
            .checked_add(1)
            .ok_or_else(|| Error::Decryption("message counter exhausted".to_string()))?;

        let mut iv = [0u8; 12];
        iv[7] = u8::from(self.receive_is_device);
        iv[8..].copy_from_slice(&next_counter.to_be_bytes());

        let plaintext = aes_256_gcm_decrypt(&self.receive_key, &iv, ciphertext, &[])?;

        self.receive_counter = next_counter;
        Ok(plaintext)
    }

    /// Get the current send counter
    pub fn send_counter(&self) -> u32 {
        self.send_counter
    }

    /// Get the current receive counter
    pub fn receive_counter(&self) -> u32 {
        self.receive_counter
    }
}

/// ECDH key agreement for session establishment
pub struct SessionKeyAgreement {
    /// Our ephemeral key pair
    key_pair: Option<P256KeyPair>,

    /// Public key retained after the one-use private agreement state is consumed.
    public_key: Vec<u8>,

    /// Peer's public key
    peer_public_key: Option<Vec<u8>>,
}

impl SessionKeyAgreement {
    /// Create a new session key agreement with an ephemeral key pair
    pub fn new() -> Result<Self> {
        let key_pair = P256KeyPair::generate();
        Ok(Self::from_key_pair(key_pair))
    }

    pub(crate) fn from_key_pair(key_pair: P256KeyPair) -> Self {
        let public_key = key_pair.public_key_uncompressed();

        Self {
            key_pair: Some(key_pair),
            public_key,
            peer_public_key: None,
        }
    }

    /// Get our public key for sending to peer
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Drop all retained private/peer agreement state when a session closes.
    pub(crate) fn clear_private_state(&mut self) {
        self.key_pair = None;
        self.peer_public_key = None;
    }

    #[cfg(test)]
    pub(crate) fn has_private_state(&self) -> bool {
        self.key_pair.is_some() || self.peer_public_key.is_some()
    }

    /// Set the peer's public key
    #[cfg(not(test))]
    pub fn set_peer_key(&mut self, peer_key: Vec<u8>) -> Result<()> {
        self.validate_and_set_peer_key(peer_key)
    }

    #[cfg(test)]
    pub fn set_peer_key(&mut self, peer_key: Vec<u8>) {
        self.validate_and_set_peer_key(peer_key)
            .expect("valid P-256 peer key in test vector");
    }

    pub(crate) fn validate_and_set_peer_key(&mut self, peer_key: Vec<u8>) -> Result<()> {
        marty_crypto::ecdh::validate_p256_public_key(&peer_key)?;
        self.peer_public_key = Some(peer_key);
        Ok(())
    }

    /// Perform ECDH and derive shared secret
    pub fn derive_shared_secret(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let peer_key = self
            .peer_public_key
            .as_ref()
            .ok_or_else(|| Error::InvalidState("Peer public key not set".to_string()))?;

        let key_pair = self
            .key_pair
            .take()
            .ok_or_else(|| Error::InvalidState("ECDH agreement already consumed".to_string()))?;
        Ok(key_pair.agree(peer_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_agreement() {
        // Simulate two parties
        let mut alice = SessionKeyAgreement::new().unwrap();
        let mut bob = SessionKeyAgreement::new().unwrap();

        // Exchange public keys
        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        alice.set_peer_key(bob_pub);
        bob.set_peer_key(alice_pub);

        // Derive shared secrets
        let alice_secret = alice.derive_shared_secret().unwrap();
        let bob_secret = bob.derive_shared_secret().unwrap();

        // Secrets should match
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_session_encryption() {
        let shared_secret = vec![0x42; 32];
        let session_transcript = b"test session";

        let mut alice =
            SessionEncryption::new_directional(&shared_secret, session_transcript, true).unwrap();
        let mut bob =
            SessionEncryption::new_directional(&shared_secret, session_transcript, false).unwrap();

        // Encrypt with Alice, decrypt with Bob
        let plaintext = b"Hello, World!";
        let ciphertext = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_message_counters() {
        let shared_secret = vec![0x42; 32];
        let session_transcript = b"test session";

        let mut encryption =
            SessionEncryption::new_directional(&shared_secret, session_transcript, true).unwrap();

        assert_eq!(encryption.send_counter(), 0);

        encryption.encrypt(b"message 1").unwrap();
        assert_eq!(encryption.send_counter(), 1);

        encryption.encrypt(b"message 2").unwrap();
        assert_eq!(encryption.send_counter(), 2);
    }

    #[test]
    fn test_exhausted_counters_fail_before_crypto() {
        let shared_secret = vec![0x42; 32];
        let session_transcript = b"counter exhaustion";
        let mut encryption =
            SessionEncryption::new_directional(&shared_secret, session_transcript, true).unwrap();

        encryption.send_counter = u32::MAX;
        encryption.receive_counter = u32::MAX;

        assert!(encryption.encrypt(b"must not encrypt").is_err());
        assert!(encryption.decrypt(&[0; 16]).is_err());
        assert_eq!(encryption.send_counter(), u32::MAX);
        assert_eq!(encryption.receive_counter(), u32::MAX);
    }

    #[test]
    fn peer_key_validation_rejects_unbounded_or_invalid_points() {
        let mut agreement = SessionKeyAgreement::new().unwrap();
        assert!(agreement
            .validate_and_set_peer_key(vec![0x04; 1024 * 1024])
            .is_err());
        assert!(agreement.validate_and_set_peer_key(vec![0x04; 65]).is_err());
    }
}
