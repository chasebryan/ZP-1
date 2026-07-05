#![allow(dead_code)]

#[cfg(feature = "test-utils")]
pub use zp1::provider::test_utils::{
    InsecureTestProvider, TestKemPublicKey, TestKemSecretKey, TestSignaturePublicKey,
    TestSignatureSecretKey,
};

#[cfg(not(feature = "test-utils"))]
mod local_provider {
    use subtle::ConstantTimeEq;
    use zp1::constants::{
        DOMAIN_RECIPIENT_PK, MAX_KEM_CT_LEN, MAX_PUBLIC_KEY_LEN, MAX_SIGNATURE_LEN,
    };
    use zp1::hash::{hash1, hash_many};
    use zp1::provider::{
        KemProvider, ProviderError, RandomProvider, SecretBytes, SignatureProvider,
    };

    #[derive(Clone, Debug)]
    pub struct TestKemPublicKey(Vec<u8>);

    impl AsRef<[u8]> for TestKemPublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestKemSecretKey {
        public_key: TestKemPublicKey,
        secret: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    pub struct TestSignaturePublicKey(Vec<u8>);

    impl AsRef<[u8]> for TestSignaturePublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestSignatureSecretKey {
        public_key: TestSignaturePublicKey,
        secret: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    pub struct InsecureTestProvider {
        seed: [u8; 48],
        counter: u64,
    }

    impl InsecureTestProvider {
        pub fn new(seed: &[u8]) -> Self {
            Self {
                seed: hash1(b"ZP1 insecure test provider seed", seed),
                counter: 0,
            }
        }

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

#[cfg(not(feature = "test-utils"))]
pub use local_provider::{
    InsecureTestProvider, TestKemPublicKey, TestKemSecretKey, TestSignaturePublicKey,
    TestSignatureSecretKey,
};

use zp1::object::Zp1Object;
use zp1::open::{open, OpenOptions};
use zp1::seal::{seal, SealOptions};
use zp1::{SuiteId, Zp1Error};

pub struct Fixture {
    pub provider: InsecureTestProvider,
    pub recipient_pks: Vec<TestKemPublicKey>,
    pub recipient_sks: Vec<TestKemSecretKey>,
    pub signer_pk: TestSignaturePublicKey,
    pub signer_sk: TestSignatureSecretKey,
}

pub fn fixture(seed: &[u8], recipient_count: usize) -> Fixture {
    let provider = InsecureTestProvider::new(seed);
    let mut recipient_pks = Vec::new();
    let mut recipient_sks = Vec::new();
    for index in 0..recipient_count {
        let label = format!("recipient-{index}");
        let (pk, sk) = provider.generate_kem_keypair(label.as_bytes());
        recipient_pks.push(pk);
        recipient_sks.push(sk);
    }
    let (signer_pk, signer_sk) = provider.generate_signature_keypair(b"signer");
    Fixture {
        provider,
        recipient_pks,
        recipient_sks,
        signer_pk,
        signer_sk,
    }
}

pub fn sealed_fixture(
    seed: &[u8],
    recipient_count: usize,
    chunk_size: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> (Fixture, Vec<u8>) {
    let mut fx = fixture(seed, recipient_count);
    let object = seal(
        &mut fx.provider,
        &fx.recipient_pks,
        &fx.signer_sk,
        &fx.signer_pk,
        aad,
        plaintext,
        SealOptions {
            chunk_size,
            suite_id: SuiteId::Zp1Core,
        },
    )
    .unwrap();
    (fx, object)
}

pub fn open_ok(fx: &mut Fixture, recipient_index: usize, aad: &[u8], object: &[u8]) -> Vec<u8> {
    open(
        &mut fx.provider,
        &fx.recipient_sks[recipient_index],
        &fx.signer_pk,
        aad,
        object,
        OpenOptions::default(),
    )
    .unwrap()
}

pub fn assert_auth(
    provider: &mut InsecureTestProvider,
    recipient_sk: &TestKemSecretKey,
    signer_pk: &TestSignaturePublicKey,
    aad: &[u8],
    object: &[u8],
) {
    let err = open(
        provider,
        recipient_sk,
        signer_pk,
        aad,
        object,
        OpenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::Auth);
}

#[derive(Debug)]
pub struct ObjectOffsets {
    pub base_header_start: usize,
    pub recipient_stanza_starts: Vec<usize>,
    pub public_manifest_start: usize,
    pub chunk_count_offset: usize,
    pub chunk_starts: Vec<usize>,
    pub manifest_tag_len_offset: usize,
    pub manifest_tag_start: usize,
    pub signature_block_start: usize,
}

pub fn locate_object_parts(bytes: &[u8]) -> ObjectOffsets {
    let mut pos = 8usize;
    let base_header_len = read_u32(bytes, pos);
    pos += 4;
    let base_header_start = pos;
    pos += base_header_len;

    let recipient_count = usize::from(read_u16(bytes, pos));
    pos += 2;
    let mut recipient_stanza_starts = Vec::new();
    for _ in 0..recipient_count {
        let stanza_len = read_u32(bytes, pos);
        pos += 4;
        recipient_stanza_starts.push(pos);
        pos += stanza_len;
    }

    let public_manifest_len = read_u32(bytes, pos);
    pos += 4;
    let public_manifest_start = pos;
    pos += public_manifest_len;

    let chunk_count_offset = pos;
    let chunk_count = usize::try_from(read_u64(bytes, pos)).unwrap();
    pos += 8;
    let mut chunk_starts = Vec::new();
    for _ in 0..chunk_count {
        let chunk_len = read_u32(bytes, pos);
        pos += 4;
        chunk_starts.push(pos);
        pos += chunk_len;
    }

    let manifest_tag_len_offset = pos;
    let manifest_tag_len = usize::from(read_u16(bytes, pos));
    pos += 2;
    let manifest_tag_start = pos;
    pos += manifest_tag_len;

    let signature_block_len = read_u32(bytes, pos);
    pos += 4;
    let signature_block_start = pos;
    pos += signature_block_len;
    assert_eq!(pos, bytes.len());

    ObjectOffsets {
        base_header_start,
        recipient_stanza_starts,
        public_manifest_start,
        chunk_count_offset,
        chunk_starts,
        manifest_tag_len_offset,
        manifest_tag_start,
        signature_block_start,
    }
}

pub fn archive_present_offset(bytes: &[u8]) -> usize {
    let parts = locate_object_parts(bytes);
    let mut pos = parts.signature_block_start;
    let domain_len = usize::from(read_u16(bytes, pos));
    pos += 2 + domain_len;
    let signer_pk_len = read_u32(bytes, pos);
    pos += 4 + signer_pk_len;
    let sig_len = read_u32(bytes, pos);
    pos += 4 + sig_len;
    pos
}

pub fn decoded(bytes: &[u8]) -> Zp1Object {
    Zp1Object::decode(bytes).unwrap()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> usize {
    let value = u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    usize::try_from(value).unwrap()
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
