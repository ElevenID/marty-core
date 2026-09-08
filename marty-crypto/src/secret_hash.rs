// Copyright 2026 ElevenID
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SHA-2, HMAC, HKDF, and PBKDF2 scratch which can be erased deterministically.
//!
//! RustCrypto's SHA-2 state does not implement `Zeroize`. Native builds use
//! AWS-LC for keyed hashing; this module keeps the browser fallback synchronous
//! while ensuring every owned intermediate is erased on success and error.

use sha2::{compress256, compress512, digest::generic_array::GenericArray};
use zeroize::{Zeroize, Zeroizing};

const SHA256_BLOCK_BYTES: usize = 64;
const SHA512_BLOCK_BYTES: usize = 128;
const MAX_DIGEST_BYTES: usize = 64;

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA384_INITIAL_STATE: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

#[derive(Clone, Copy)]
pub(crate) enum SecureHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl SecureHashAlgorithm {
    fn block_len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_BLOCK_BYTES,
            Self::Sha384 | Self::Sha512 => SHA512_BLOCK_BYTES,
        }
    }

    pub(crate) fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
struct HashCleanupObserver(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl HashCleanupObserver {
    fn cleanup_count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub(crate) struct SecureSha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_BYTES],
    buffer_len: usize,
    message_len: u64,
    #[cfg(test)]
    cleanup_observer: Option<HashCleanupObserver>,
}

impl SecureSha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0; SHA256_BLOCK_BYTES],
            buffer_len: 0,
            message_len: 0,
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn new_with_cleanup_observer(observer: HashCleanupObserver) -> Self {
        Self {
            cleanup_observer: Some(observer),
            ..Self::new()
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.message_len = self
            .message_len
            .checked_add(u64::try_from(data.len()).expect("SHA-256 input exceeds u64"))
            .expect("SHA-256 input length overflow");

        if self.buffer_len != 0 {
            let copied = (SHA256_BLOCK_BYTES - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copied].copy_from_slice(&data[..copied]);
            self.buffer_len += copied;
            data = &data[copied..];
            if self.buffer_len == SHA256_BLOCK_BYTES {
                self.compress_buffer();
            }
        }

        while data.len() >= SHA256_BLOCK_BYTES {
            let (block, remaining) = data.split_at(SHA256_BLOCK_BYTES);
            compress256(
                &mut self.state,
                core::slice::from_ref(GenericArray::from_slice(block)),
            );
            data = remaining;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub(crate) fn finish(mut self) -> Zeroizing<[u8; 32]> {
        let bit_len = self
            .message_len
            .checked_mul(8)
            .expect("SHA-256 bit length overflow");
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            self.compress_buffer();
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.buffer_len = SHA256_BLOCK_BYTES;
        self.compress_buffer();

        let mut digest = Zeroizing::new([0u8; 32]);
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        self.clear();
        digest
    }

    fn compress_buffer(&mut self) {
        compress256(
            &mut self.state,
            core::slice::from_ref(GenericArray::from_slice(&self.buffer)),
        );
        self.buffer.zeroize();
        self.buffer_len.zeroize();
    }

    fn clear(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_len.zeroize();
        self.message_len.zeroize();
    }
}

impl Drop for SecureSha256 {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            assert!(self.state.iter().all(|word| *word == 0));
            assert!(self.buffer.iter().all(|byte| *byte == 0));
            assert_eq!(self.buffer_len, 0);
            assert_eq!(self.message_len, 0);
            observer.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct SecureSha512 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_BYTES],
    buffer_len: usize,
    message_len: u128,
    output_len: usize,
    #[cfg(test)]
    cleanup_observer: Option<HashCleanupObserver>,
}

impl SecureSha512 {
    fn new(algorithm: SecureHashAlgorithm) -> Self {
        let (state, output_len) = match algorithm {
            SecureHashAlgorithm::Sha384 => (SHA384_INITIAL_STATE, 48),
            SecureHashAlgorithm::Sha512 => (SHA512_INITIAL_STATE, 64),
            SecureHashAlgorithm::Sha256 => unreachable!("SHA-256 has a distinct block size"),
        };
        Self {
            state,
            buffer: [0; SHA512_BLOCK_BYTES],
            buffer_len: 0,
            message_len: 0,
            output_len,
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn new_with_cleanup_observer(
        algorithm: SecureHashAlgorithm,
        observer: HashCleanupObserver,
    ) -> Self {
        Self {
            cleanup_observer: Some(observer),
            ..Self::new(algorithm)
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.message_len = self
            .message_len
            .checked_add(u128::try_from(data.len()).expect("SHA-512 input exceeds u128"))
            .expect("SHA-512 input length overflow");

        if self.buffer_len != 0 {
            let copied = (SHA512_BLOCK_BYTES - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copied].copy_from_slice(&data[..copied]);
            self.buffer_len += copied;
            data = &data[copied..];
            if self.buffer_len == SHA512_BLOCK_BYTES {
                self.compress_buffer();
            }
        }

        while data.len() >= SHA512_BLOCK_BYTES {
            let (block, remaining) = data.split_at(SHA512_BLOCK_BYTES);
            compress512(
                &mut self.state,
                core::slice::from_ref(GenericArray::from_slice(block)),
            );
            data = remaining;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    fn finish(mut self) -> Zeroizing<[u8; MAX_DIGEST_BYTES]> {
        let bit_len = self
            .message_len
            .checked_mul(8)
            .expect("SHA-512 bit length overflow");
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..].fill(0);
            self.compress_buffer();
        }
        self.buffer[self.buffer_len..112].fill(0);
        self.buffer[112..].copy_from_slice(&bit_len.to_be_bytes());
        self.buffer_len = SHA512_BLOCK_BYTES;
        self.compress_buffer();

        let mut digest = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
        for (chunk, word) in digest.chunks_exact_mut(8).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest[self.output_len..].zeroize();
        self.clear();
        digest
    }

    fn compress_buffer(&mut self) {
        compress512(
            &mut self.state,
            core::slice::from_ref(GenericArray::from_slice(&self.buffer)),
        );
        self.buffer.zeroize();
        self.buffer_len.zeroize();
    }

    fn clear(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_len.zeroize();
        self.message_len.zeroize();
        self.output_len.zeroize();
    }
}

impl Drop for SecureSha512 {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            assert!(self.state.iter().all(|word| *word == 0));
            assert!(self.buffer.iter().all(|byte| *byte == 0));
            assert_eq!(self.buffer_len, 0);
            assert_eq!(self.message_len, 0);
            assert_eq!(self.output_len, 0);
            observer.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn hash_parts(
    algorithm: SecureHashAlgorithm,
    parts: &[&[u8]],
    output: &mut [u8; MAX_DIGEST_BYTES],
) {
    output.zeroize();
    match algorithm {
        SecureHashAlgorithm::Sha256 => {
            let mut hash = SecureSha256::new();
            for part in parts {
                hash.update(part);
            }
            output[..32].copy_from_slice(&*hash.finish());
        }
        SecureHashAlgorithm::Sha384 | SecureHashAlgorithm::Sha512 => {
            let mut hash = SecureSha512::new(algorithm);
            for part in parts {
                hash.update(part);
            }
            let digest = hash.finish();
            output[..algorithm.digest_len()].copy_from_slice(&digest[..algorithm.digest_len()]);
        }
    }
}

pub(crate) struct HmacScratch {
    key_block: [u8; SHA512_BLOCK_BYTES],
    inner_digest: [u8; MAX_DIGEST_BYTES],
}

impl Zeroize for HmacScratch {
    fn zeroize(&mut self) {
        self.key_block.zeroize();
        self.inner_digest.zeroize();
    }
}

impl Default for HmacScratch {
    fn default() -> Self {
        Self {
            key_block: [0; SHA512_BLOCK_BYTES],
            inner_digest: [0; MAX_DIGEST_BYTES],
        }
    }
}

struct ScratchGuard<'a>(&'a mut HmacScratch);

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct OutputGuard<'a> {
    output: &'a mut [u8],
    keep: bool,
}

impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.output.zeroize();
        }
    }
}

fn hmac_into(
    algorithm: SecureHashAlgorithm,
    key: &[u8],
    message_parts: &[&[u8]],
    scratch: &mut HmacScratch,
    output: &mut [u8],
) {
    let block_len = algorithm.block_len();
    let digest_len = algorithm.digest_len();
    scratch.zeroize();
    output.zeroize();

    if key.len() > block_len {
        hash_parts(algorithm, &[key], &mut scratch.inner_digest);
        scratch.key_block[..digest_len].copy_from_slice(&scratch.inner_digest[..digest_len]);
        scratch.inner_digest.zeroize();
    } else {
        scratch.key_block[..key.len()].copy_from_slice(key);
    }

    for byte in &mut scratch.key_block[..block_len] {
        *byte ^= 0x36;
    }
    let mut inner_parts = Vec::with_capacity(message_parts.len() + 1);
    inner_parts.push(&scratch.key_block[..block_len]);
    inner_parts.extend_from_slice(message_parts);
    hash_parts(algorithm, &inner_parts, &mut scratch.inner_digest);

    for byte in &mut scratch.key_block[..block_len] {
        *byte ^= 0x36 ^ 0x5c;
    }
    let outer_parts = [
        &scratch.key_block[..block_len],
        &scratch.inner_digest[..digest_len],
    ];
    let mut digest = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    hash_parts(algorithm, &outer_parts, &mut digest);
    output.copy_from_slice(&digest[..digest_len]);
}

pub(crate) fn hmac_with_scratch<F>(
    algorithm: SecureHashAlgorithm,
    key: &[u8],
    message_parts: &[&[u8]],
    output: &mut [u8],
    scratch: &mut HmacScratch,
    after_compute: F,
) -> Result<(), ()>
where
    F: FnOnce() -> Result<(), ()>,
{
    scratch.zeroize();
    if output.len() != algorithm.digest_len() {
        output.zeroize();
        return Err(());
    }
    let guarded_scratch = ScratchGuard(scratch);
    let mut guarded_output = OutputGuard {
        output,
        keep: false,
    };
    hmac_into(
        algorithm,
        key,
        message_parts,
        guarded_scratch.0,
        guarded_output.output,
    );
    after_compute()?;
    guarded_output.keep = true;
    Ok(())
}

#[cfg(target_family = "wasm")]
pub(crate) fn hmac_sha256(key: &[u8], message_parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0u8; 32]);
    let mut scratch = HmacScratch::default();
    hmac_with_scratch(
        SecureHashAlgorithm::Sha256,
        key,
        message_parts,
        &mut *output,
        &mut scratch,
        || Ok(()),
    )
    .expect("fixed SHA-256 output length");
    output
}

#[cfg(target_family = "wasm")]
pub(crate) fn hkdf<F>(
    algorithm: SecureHashAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output: &mut [u8],
    after_extract: F,
) -> Result<(), ()>
where
    F: FnOnce() -> Result<(), ()>,
{
    let digest_len = algorithm.digest_len();
    if output.len() > 255 * digest_len {
        output.zeroize();
        return Err(());
    }

    let mut guarded_output = OutputGuard {
        output,
        keep: false,
    };
    let mut scratch = HmacScratch::default();
    let mut prk = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    hmac_with_scratch(
        algorithm,
        salt,
        &[ikm],
        &mut prk[..digest_len],
        &mut scratch,
        || Ok(()),
    )?;
    after_extract()?;

    let mut previous = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    let mut next = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    let mut previous_len = 0;
    let mut written = 0;
    for counter in 1..=guarded_output.output.len().div_ceil(digest_len) {
        hmac_with_scratch(
            algorithm,
            &prk[..digest_len],
            &[
                &previous[..previous_len],
                info,
                &[u8::try_from(counter).expect("HKDF counter is bounded to 255")],
            ],
            &mut next[..digest_len],
            &mut scratch,
            || Ok(()),
        )?;
        previous[..digest_len].copy_from_slice(&next[..digest_len]);
        next.zeroize();
        previous_len = digest_len;
        let copied = digest_len.min(guarded_output.output.len() - written);
        guarded_output.output[written..written + copied].copy_from_slice(&previous[..copied]);
        written += copied;
    }
    guarded_output.keep = true;
    Ok(())
}

#[cfg(target_family = "wasm")]
pub(crate) fn pbkdf2(
    algorithm: SecureHashAlgorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) {
    assert!(iterations != 0, "PBKDF2 iterations must be nonzero");
    let digest_len = algorithm.digest_len();
    let block_count = output.len().div_ceil(digest_len);
    assert!(
        u32::try_from(block_count).is_ok(),
        "PBKDF2 output is too long"
    );

    let mut scratch = HmacScratch::default();
    let mut current = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    let mut next = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    let mut accumulated = Zeroizing::new([0u8; MAX_DIGEST_BYTES]);
    let mut written = 0;
    for block in 1..=block_count {
        let block = u32::try_from(block).expect("PBKDF2 block count was validated");
        hmac_with_scratch(
            algorithm,
            password,
            &[salt, &block.to_be_bytes()],
            &mut current[..digest_len],
            &mut scratch,
            || Ok(()),
        )
        .expect("fixed HMAC output length");
        accumulated[..digest_len].copy_from_slice(&current[..digest_len]);
        for _ in 1..iterations {
            hmac_with_scratch(
                algorithm,
                password,
                &[&current[..digest_len]],
                &mut next[..digest_len],
                &mut scratch,
                || Ok(()),
            )
            .expect("fixed HMAC output length");
            for index in 0..digest_len {
                accumulated[index] ^= next[index];
            }
            current[..digest_len].copy_from_slice(&next[..digest_len]);
            next.zeroize();
        }
        let copied = digest_len.min(output.len() - written);
        output[written..written + copied].copy_from_slice(&accumulated[..copied]);
        written += copied;
    }
}

#[cfg(target_family = "wasm")]
pub(crate) fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hash = SecureSha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finish()
}

#[cfg(test)]
impl HmacScratch {
    fn is_zero(&self) -> bool {
        self.key_block.iter().all(|byte| *byte == 0)
            && self.inner_digest.iter().all(|byte| *byte == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    #[test]
    fn secure_hashes_match_reference_at_padding_boundaries() {
        for len in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 65_537] {
            let input: Vec<u8> = (0..len)
                .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
                .collect();

            let mut sha256 = SecureSha256::new();
            let mut sha384 = SecureSha512::new(SecureHashAlgorithm::Sha384);
            let mut sha512 = SecureSha512::new(SecureHashAlgorithm::Sha512);
            for chunk in input.chunks(19) {
                sha256.update(chunk);
                sha384.update(chunk);
                sha512.update(chunk);
            }
            assert_eq!(&*sha256.finish(), Sha256::digest(&input).as_slice());
            assert_eq!(&sha384.finish()[..48], Sha384::digest(&input).as_slice());
            assert_eq!(&sha512.finish()[..64], Sha512::digest(&input).as_slice());
        }
    }

    #[test]
    fn hash_and_hmac_scratch_wipe_on_finish_error_and_unwind() {
        let finish_observer = HashCleanupObserver::default();
        let mut finishing_hash = SecureSha256::new_with_cleanup_observer(finish_observer.clone());
        finishing_hash.update(&[0xa5; 31]);
        let _digest = finishing_hash.finish();
        assert_eq!(finish_observer.cleanup_count(), 1);

        let sha512_observer = HashCleanupObserver::default();
        let mut finishing_hash = SecureSha512::new_with_cleanup_observer(
            SecureHashAlgorithm::Sha512,
            sha512_observer.clone(),
        );
        finishing_hash.update(&[0xa5; 131]);
        let _digest = finishing_hash.finish();
        assert_eq!(sha512_observer.cleanup_count(), 1);

        let mut output = [0xa5; 32];
        let mut scratch = HmacScratch::default();
        assert!(hmac_with_scratch(
            SecureHashAlgorithm::Sha256,
            b"recognizable key",
            &[b"message"],
            &mut output,
            &mut scratch,
            || Err(())
        )
        .is_err());
        assert_eq!(output, [0; 32]);
        assert!(scratch.is_zero());

        let unwind_observer = HashCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let mut hash = SecureSha256::new_with_cleanup_observer(observer);
                hash.update(b"recognizable intermediate state");
                panic!("injected secure-hash unwind")
            }
        });
        assert!(unwind.is_err());
        assert_eq!(unwind_observer.cleanup_count(), 1);
    }

    #[cfg(target_family = "wasm")]
    mod wasm {
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        #[wasm_bindgen_test]
        fn wasm_hmac_and_hkdf_match_kats_and_wipe_returned_error_state() {
            let expected_hmac =
                hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                    .unwrap();
            assert_eq!(
                hmac_sha256(b"key", &[b"The quick brown fox jumps over the lazy dog"]).as_slice(),
                expected_hmac
            );

            let mut hkdf_output = [0u8; 42];
            hkdf(
                SecureHashAlgorithm::Sha256,
                &[0x0b; 22],
                &hex::decode("000102030405060708090a0b0c").unwrap(),
                &hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
                &mut hkdf_output,
                || Ok(()),
            )
            .unwrap();
            assert_eq!(
                hkdf_output.as_slice(),
                hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                    .unwrap()
            );

            let mut error_output = [0xa5; 32];
            let mut scratch = HmacScratch::default();
            assert!(hmac_with_scratch(
                SecureHashAlgorithm::Sha256,
                b"recognizable browser key",
                &[b"message"],
                &mut error_output,
                &mut scratch,
                || Err(())
            )
            .is_err());
            assert_eq!(error_output, [0; 32]);
            assert!(scratch.is_zero());

            let mut hkdf_error_output = [0xa5; 32];
            assert!(hkdf(
                SecureHashAlgorithm::Sha256,
                b"recognizable browser IKM",
                b"salt",
                b"info",
                &mut hkdf_error_output,
                || Err(())
            )
            .is_err());
            assert_eq!(hkdf_error_output, [0; 32]);
        }
    }
}
