//! ISO 18013-5 session management
//!
//! This module handles session establishment, encryption, and key derivation
//! for secure communication between mDL holder and reader.

use crate::error::{Error, Result};
use marty_crypto::ecdh::P256KeyPair;
use marty_crypto::kdf::derive_mdl_session_keys;
use marty_crypto::symmetric::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};

/// Session encryption and decryption state
pub struct SessionEncryption {
    /// Session encryption key (derived from ECDH)
    sk_encryption: Vec<u8>,
    
    /// Session MAC key (derived from ECDH)
    #[allow(dead_code)]
    sk_mac: Vec<u8>,
    
    /// Message counter for encryption
    send_counter: u32,
    
    /// Message counter for decryption (validation)
    receive_counter: u32,
}

impl SessionEncryption {
    /// Create new session encryption from ECDH shared secret
    pub fn new(shared_secret: &[u8], session_transcript: &[u8]) -> Result<Self> {
        let (sk_encryption, sk_mac) = derive_mdl_session_keys(
            shared_secret,
            session_transcript,
        )?;
        
        Ok(Self {
            sk_encryption,
            sk_mac,
            send_counter: 0,
            receive_counter: 0,
        })
    }

    /// Encrypt a message with AES-256-GCM
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Construct IV from counter
        let mut iv = vec![0u8; 12];
        iv[8..].copy_from_slice(&self.send_counter.to_be_bytes());
        
        let ciphertext = aes_256_gcm_encrypt(&self.sk_encryption, &iv, plaintext, &[])?;
        
        self.send_counter += 1;
        Ok(ciphertext)
    }

    /// Decrypt a message with AES-256-GCM
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Construct IV from counter
        let mut iv = vec![0u8; 12];
        iv[8..].copy_from_slice(&self.receive_counter.to_be_bytes());
        
        let plaintext = aes_256_gcm_decrypt(&self.sk_encryption, &iv, ciphertext, &[])?;
        
        self.receive_counter += 1;
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
    key_pair: P256KeyPair,
    
    /// Peer's public key
    peer_public_key: Option<Vec<u8>>,
}

impl SessionKeyAgreement {
    /// Create a new session key agreement with an ephemeral key pair
    pub fn new() -> Result<Self> {
        let key_pair = P256KeyPair::generate();
        
        Ok(Self {
            key_pair,
            peer_public_key: None,
        })
    }

    /// Get our public key for sending to peer
    pub fn public_key(&self) -> Vec<u8> {
        self.key_pair.public_key_uncompressed()
    }

    /// Set the peer's public key
    pub fn set_peer_key(&mut self, peer_key: Vec<u8>) {
        self.peer_public_key = Some(peer_key);
    }

    /// Perform ECDH and derive shared secret
    pub fn derive_shared_secret(&self) -> Result<Vec<u8>> {
        let peer_key = self.peer_public_key.as_ref()
            .ok_or_else(|| Error::InvalidState("Peer public key not set".to_string()))?;
        
        Ok(self.key_pair.agree(peer_key)?)
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
        
        let mut alice = SessionEncryption::new(&shared_secret, session_transcript).unwrap();
        let mut bob = SessionEncryption::new(&shared_secret, session_transcript).unwrap();
        
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
        
        let mut encryption = SessionEncryption::new(&shared_secret, session_transcript).unwrap();
        
        assert_eq!(encryption.send_counter(), 0);
        
        encryption.encrypt(b"message 1").unwrap();
        assert_eq!(encryption.send_counter(), 1);
        
        encryption.encrypt(b"message 2").unwrap();
        assert_eq!(encryption.send_counter(), 2);
    }
}
