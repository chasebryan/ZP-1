//! Provider traits for cryptographic primitives.

use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Provider failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("provider failure")]
pub struct ProviderError;

/// Zeroizing secret byte buffer.
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Wrap a secret byte vector.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
        }
    }

    /// Return the secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Return the length of the secret.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return true if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Zeroize the secret in place.
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.as_slice().to_vec())
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

/// KEM provider interface.
pub trait KemProvider {
    /// Recipient public key type.
    type KemPublicKey: AsRef<[u8]>;
    /// Recipient secret key type.
    type KemSecretKey;

    /// Return canonical recipient public-key bytes.
    fn kem_public_key_bytes(pk: &Self::KemPublicKey) -> &[u8] {
        pk.as_ref()
    }

    /// Encapsulate to a recipient public key.
    fn encapsulate(
        &mut self,
        recipient_pk: &Self::KemPublicKey,
    ) -> Result<(Vec<u8>, SecretBytes), ProviderError>;

    /// Decapsulate a KEM ciphertext.
    fn decapsulate(
        &mut self,
        recipient_sk: &Self::KemSecretKey,
        kem_ciphertext: &[u8],
    ) -> Result<SecretBytes, ProviderError>;

    /// Derive the ZP-1 recipient public-key hash from a recipient secret key.
    fn derive_public_key_hash_from_secret(
        &self,
        recipient_sk: &Self::KemSecretKey,
    ) -> Result<[u8; 48], ProviderError>;
}

/// ML-DSA-87 signature provider interface.
pub trait SignatureProvider {
    /// Signer public key type.
    type SignaturePublicKey: AsRef<[u8]>;
    /// Signer secret key type.
    type SignatureSecretKey;

    /// Return canonical signer public-key bytes.
    fn signature_public_key_bytes(pk: &Self::SignaturePublicKey) -> &[u8] {
        pk.as_ref()
    }

    /// Sign with ML-DSA-87.
    fn sign_mldsa87(
        &mut self,
        signing_sk: &Self::SignatureSecretKey,
        message: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Verify with ML-DSA-87.
    fn verify_mldsa87(
        &self,
        signing_pk: &Self::SignaturePublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ProviderError>;
}

/// SLH-DSA archive-signature provider interface.
pub trait ArchiveSignatureProvider {
    /// Archive signer public key type.
    type ArchivePublicKey: AsRef<[u8]>;
    /// Archive signer secret key type.
    type ArchiveSecretKey;

    /// Sign with SLH-DSA level 5.
    fn sign_slhdsa_level5(
        &mut self,
        signing_sk: &Self::ArchiveSecretKey,
        message: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Verify with SLH-DSA level 5.
    fn verify_slhdsa_level5(
        &self,
        signing_pk: &Self::ArchivePublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ProviderError>;
}

/// Random byte provider interface.
pub trait RandomProvider {
    /// Fill `out` with random bytes.
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), ProviderError>;
}

/// Complete ZP-1 Core provider interface.
pub trait Zp1Provider: KemProvider + SignatureProvider + RandomProvider {}

impl<T> Zp1Provider for T where T: KemProvider + SignatureProvider + RandomProvider {}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    //! NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.

    use subtle::ConstantTimeEq;

    use super::{KemProvider, ProviderError, RandomProvider, SecretBytes, SignatureProvider};
    use crate::constants::{
        DOMAIN_RECIPIENT_PK, MAX_KEM_CT_LEN, MAX_PUBLIC_KEY_LEN, MAX_SIGNATURE_LEN,
    };
    use crate::hash::{hash1, hash_many};

    /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
    #[derive(Clone, Debug)]
    pub struct TestKemPublicKey(Vec<u8>);

    impl AsRef<[u8]> for TestKemPublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
    #[derive(Clone, Debug)]
    pub struct TestKemSecretKey {
        public_key: TestKemPublicKey,
        secret: Vec<u8>,
    }

    /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
    #[derive(Clone, Debug)]
    pub struct TestSignaturePublicKey(Vec<u8>);

    impl AsRef<[u8]> for TestSignaturePublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
    #[derive(Clone, Debug)]
    pub struct TestSignatureSecretKey {
        public_key: TestSignaturePublicKey,
        secret: Vec<u8>,
    }

    /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
    #[derive(Clone, Debug)]
    pub struct InsecureTestProvider {
        seed: [u8; 48],
        counter: u64,
    }

    impl InsecureTestProvider {
        /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
        pub fn new(seed: &[u8]) -> Self {
            Self {
                seed: hash1(b"ZP1 insecure test provider seed", seed),
                counter: 0,
            }
        }

        /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
        pub fn generate_kem_keypair(&self, label: &[u8]) -> (TestKemPublicKey, TestKemSecretKey) {
            let pk = hash_many(b"ZP1 insecure test kem pk", &[&self.seed, label]).to_vec();
            let sk = hash_many(b"ZP1 insecure test kem sk", &[&self.seed, label]).to_vec();
            let public_key = TestKemPublicKey(pk);
            (
                public_key.clone(),
                TestKemSecretKey {
                    public_key,
                    secret: sk,
                },
            )
        }

        /// NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
        pub fn generate_signature_keypair(
            &self,
            label: &[u8],
        ) -> (TestSignaturePublicKey, TestSignatureSecretKey) {
            let pk = hash_many(b"ZP1 insecure test sig pk", &[&self.seed, label]).to_vec();
            let sk = hash_many(b"ZP1 insecure test sig sk", &[&self.seed, label]).to_vec();
            let public_key = TestSignaturePublicKey(pk);
            (
                public_key.clone(),
                TestSignatureSecretKey {
                    public_key,
                    secret: sk,
                },
            )
        }
    }

    impl Default for InsecureTestProvider {
        fn default() -> Self {
            Self::new(b"default insecure zp1 test provider")
        }
    }

    impl RandomProvider for InsecureTestProvider {
        fn fill_random(&mut self, out: &mut [u8]) -> Result<(), ProviderError> {
            let mut offset = 0usize;
            while offset < out.len() {
                let counter = self.counter.to_be_bytes();
                self.counter = self.counter.checked_add(1).ok_or(ProviderError)?;
                let block = hash_many(b"ZP1 insecure test random", &[&self.seed, &counter]);
                let take = core::cmp::min(out.len() - offset, block.len());
                out[offset..offset + take].copy_from_slice(&block[..take]);
                offset += take;
            }
            Ok(())
        }
    }

    impl KemProvider for InsecureTestProvider {
        type KemPublicKey = TestKemPublicKey;
        type KemSecretKey = TestKemSecretKey;

        fn encapsulate(
            &mut self,
            recipient_pk: &Self::KemPublicKey,
        ) -> Result<(Vec<u8>, SecretBytes), ProviderError> {
            if recipient_pk.as_ref().len() > MAX_PUBLIC_KEY_LEN {
                return Err(ProviderError);
            }
            let mut kem_ciphertext = vec![0u8; 64];
            self.fill_random(&mut kem_ciphertext)?;
            if kem_ciphertext.len() > MAX_KEM_CT_LEN {
                return Err(ProviderError);
            }
            let ss = hash_many(
                b"ZP1 insecure test kem ss",
                &[recipient_pk.as_ref(), &kem_ciphertext],
            );
            Ok((kem_ciphertext, SecretBytes::new(ss.to_vec())))
        }

        fn decapsulate(
            &mut self,
            recipient_sk: &Self::KemSecretKey,
            kem_ciphertext: &[u8],
        ) -> Result<SecretBytes, ProviderError> {
            if kem_ciphertext.len() > MAX_KEM_CT_LEN {
                return Err(ProviderError);
            }
            let _ = recipient_sk.secret.len();
            let ss = hash_many(
                b"ZP1 insecure test kem ss",
                &[recipient_sk.public_key.as_ref(), kem_ciphertext],
            );
            Ok(SecretBytes::new(ss.to_vec()))
        }

        fn derive_public_key_hash_from_secret(
            &self,
            recipient_sk: &Self::KemSecretKey,
        ) -> Result<[u8; 48], ProviderError> {
            Ok(hash1(DOMAIN_RECIPIENT_PK, recipient_sk.public_key.as_ref()))
        }
    }

    impl SignatureProvider for InsecureTestProvider {
        type SignaturePublicKey = TestSignaturePublicKey;
        type SignatureSecretKey = TestSignatureSecretKey;

        fn sign_mldsa87(
            &mut self,
            signing_sk: &Self::SignatureSecretKey,
            message: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            let _ = signing_sk.secret.len();
            let sig = hash_many(
                b"ZP1 insecure test mldsa87 signature",
                &[signing_sk.public_key.as_ref(), message],
            )
            .to_vec();
            if sig.len() > MAX_SIGNATURE_LEN {
                return Err(ProviderError);
            }
            Ok(sig)
        }

        fn verify_mldsa87(
            &self,
            signing_pk: &Self::SignaturePublicKey,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, ProviderError> {
            let expected = hash_many(
                b"ZP1 insecure test mldsa87 signature",
                &[signing_pk.as_ref(), message],
            );
            Ok(signature.len() == expected.len()
                && bool::from(signature.ct_eq(expected.as_slice())))
        }
    }
}
