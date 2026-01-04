//! Hash computation utilities.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::HashAlgorithm;

/// Compute a hash using the specified algorithm.
///
/// # Arguments
///
/// * `algorithm` - The hash algorithm to use
/// * `data` - The data to hash
///
/// # Returns
///
/// The hash digest as a byte vector.
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha1 => hash_sha1(data),
        HashAlgorithm::Sha256 => hash_sha256(data),
        HashAlgorithm::Sha384 => hash_sha384(data),
        HashAlgorithm::Sha512 => hash_sha512(data),
    }
}

/// Compute SHA-1 hash (legacy, 160-bit).
///
/// **Warning**: SHA-1 is considered cryptographically weak.
/// Only use for legacy compatibility.
pub fn hash_sha1(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash (256-bit).
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-384 hash (384-bit).
pub fn hash_sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-512 hash (512-bit).
pub fn hash_sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Incremental hasher for streaming data.
///
/// UniFFI-compatible: Uses trait objects internally but exposes simple API.
pub struct IncrementalHasher {
    algorithm: HashAlgorithm,
    state: HasherState,
}

enum HasherState {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl IncrementalHasher {
    /// Create a new incremental hasher.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha1 => HasherState::Sha1(Sha1::new()),
            HashAlgorithm::Sha256 => HasherState::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => HasherState::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => HasherState::Sha512(Sha512::new()),
        };
        Self { algorithm, state }
    }

    /// Update the hasher with more data.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            HasherState::Sha1(h) => h.update(data),
            HasherState::Sha256(h) => h.update(data),
            HasherState::Sha384(h) => h.update(data),
            HasherState::Sha512(h) => h.update(data),
        }
    }

    /// Finalize and return the hash.
    pub fn finalize(self) -> Vec<u8> {
        match self.state {
            HasherState::Sha1(h) => h.finalize().to_vec(),
            HasherState::Sha256(h) => h.finalize().to_vec(),
            HasherState::Sha384(h) => h.finalize().to_vec(),
            HasherState::Sha512(h) => h.finalize().to_vec(),
        }
    }

    /// Get the algorithm being used.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string
        let result = hash_sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_hello() {
        let result = hash_sha256(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha1_known_vector() {
        // SHA-1 of empty string
        let result = hash_sha1(b"");
        let expected = hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_incremental_hasher() {
        let mut hasher = IncrementalHasher::new(HashAlgorithm::Sha256);
        hasher.update(b"hel");
        hasher.update(b"lo");
        let result = hasher.finalize();

        let expected = hash_sha256(b"hello");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_dispatch() {
        let data = b"test";

        assert_eq!(hash(HashAlgorithm::Sha1, data), hash_sha1(data));
        assert_eq!(hash(HashAlgorithm::Sha256, data), hash_sha256(data));
        assert_eq!(hash(HashAlgorithm::Sha384, data), hash_sha384(data));
        assert_eq!(hash(HashAlgorithm::Sha512, data), hash_sha512(data));
    }
}

// We need hex for tests, but it's commonly available
#[cfg(test)]
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
