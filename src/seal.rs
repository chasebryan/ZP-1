//! ZP-1 sealing API.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use zeroize::Zeroizing;

use crate::constants::{
    AEAD_KEY_LEN, AES_GCM_SIV_NONCE_LEN, CONTENT_SECRET_LEN, DEFAULT_CHUNK_SIZE, DOMAIN_AAD,
    DOMAIN_CHUNK_AEAD_KEY, DOMAIN_CONTENT_KEY_COMMITMENT, DOMAIN_CONTENT_SALT,
    DOMAIN_KEY_COMMITMENT_KEY, DOMAIN_MANIFEST_MAC_KEY, DOMAIN_MANIFEST_TAG, DOMAIN_RECIPIENT_PK,
    DOMAIN_RECIPIENT_STANZAS, DOMAIN_RECIPIENT_WRAP_SALT, DOMAIN_SIGNATURE_INPUT, DOMAIN_SIGNER_PK,
    DOMAIN_WRAP_KEY, KEY_COMMITMENT_LEN, MAX_AAD_LEN, MAX_CHUNKS, MAX_CHUNK_SIZE, MAX_KEM_CT_LEN,
    MAX_PLAINTEXT_LEN, MAX_PUBLIC_KEY_LEN, MAX_RECIPIENTS, MAX_SIGNATURE_LEN, MIN_CHUNK_SIZE,
    OBJECT_ID_LEN,
};
use crate::error::{InternalCryptoError, Zp1Error};
use crate::hash::{hash1, hash_many, hash_many_input, sha384};
use crate::kdf::{encode_context, expand, extract, hmac_sha384, secret_to_key32};
use crate::merkle::{merkle_leaf, merkle_root};
use crate::object::{
    encode_chunk_aad, BaseHeader, ChunkAadInput, PublicManifest, RecipientHeader, RecipientStanza,
    SignatureBlock, SuiteId, Zp1Object,
};
use crate::provider::{SecretBytes, Zp1Provider};

/// Seal options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealOptions {
    /// Fixed plaintext chunk size.
    pub chunk_size: u32,
    /// ZP-1 suite ID.
    pub suite_id: SuiteId,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            suite_id: SuiteId::Zp1Core,
        }
    }
}

/// Validate seal limits for caller-supplied lengths.
#[doc(hidden)]
pub fn validate_seal_limits(
    recipient_count: usize,
    aad_len: usize,
    plaintext_len: usize,
    chunk_size: u32,
    suite_id: SuiteId,
) -> Result<u64, Zp1Error> {
    if suite_id != SuiteId::Zp1Core {
        return Err(Zp1Error::UnsupportedSuite);
    }
    if recipient_count == 0 || recipient_count > MAX_RECIPIENTS {
        return Err(Zp1Error::LimitExceeded);
    }
    if u64::try_from(aad_len).map_err(|_| Zp1Error::LimitExceeded)? > MAX_AAD_LEN {
        return Err(Zp1Error::LimitExceeded);
    }
    let plaintext_len_u64 = u64::try_from(plaintext_len).map_err(|_| Zp1Error::LimitExceeded)?;
    if plaintext_len_u64 > MAX_PLAINTEXT_LEN {
        return Err(Zp1Error::LimitExceeded);
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Zp1Error::LimitExceeded);
    }
    let chunk_size_u64 = u64::from(chunk_size);
    let chunk_count = if plaintext_len_u64 == 0 {
        1
    } else {
        plaintext_len_u64
            .checked_add(chunk_size_u64 - 1)
            .ok_or(Zp1Error::LimitExceeded)?
            / chunk_size_u64
    };
    if chunk_count == 0 || chunk_count > MAX_CHUNKS {
        return Err(Zp1Error::LimitExceeded);
    }
    Ok(chunk_count)
}

/// Seal plaintext into a ZP-1 object.
pub fn seal<P>(
    provider: &mut P,
    recipient_public_keys: &[P::KemPublicKey],
    signer_secret_key: &P::SignatureSecretKey,
    signer_public_key: &P::SignaturePublicKey,
    aad: &[u8],
    plaintext: &[u8],
    options: SealOptions,
) -> Result<Vec<u8>, Zp1Error>
where
    P: Zp1Provider,
{
    let chunk_count = validate_seal_limits(
        recipient_public_keys.len(),
        aad.len(),
        plaintext.len(),
        options.chunk_size,
        options.suite_id,
    )?;
    let chunk_count_usize = usize::try_from(chunk_count).map_err(|_| Zp1Error::LimitExceeded)?;

    let signer_public_key_bytes = P::signature_public_key_bytes(signer_public_key);
    if signer_public_key_bytes.len() > MAX_PUBLIC_KEY_LEN {
        return Err(Zp1Error::LimitExceeded);
    }

    let mut content_secret_bytes = vec![0u8; CONTENT_SECRET_LEN];
    provider.fill_random(&mut content_secret_bytes)?;
    let mut content_secret = SecretBytes::new(content_secret_bytes);

    let mut object_id = [0u8; OBJECT_ID_LEN];
    provider.fill_random(&mut object_id)?;

    let aad_hash = hash1(DOMAIN_AAD, aad);
    let signer_pk_hash = hash1(DOMAIN_SIGNER_PK, signer_public_key_bytes);
    let plaintext_length = u64::try_from(plaintext.len()).map_err(|_| Zp1Error::LimitExceeded)?;

    let base_header = BaseHeader {
        suite_id: options.suite_id,
        object_id,
        chunk_size: options.chunk_size,
        plaintext_length,
        aad_hash,
        signer_pk_hash,
        flags: 0,
    };
    let base_header_bytes = base_header.encode();

    let mut recipient_stanzas = Vec::with_capacity(recipient_public_keys.len());
    let mut recipient_stanza_bytes = Vec::with_capacity(recipient_public_keys.len());

    for (index, recipient_pk) in recipient_public_keys.iter().enumerate() {
        let recipient_pk_bytes = P::kem_public_key_bytes(recipient_pk);
        if recipient_pk_bytes.len() > MAX_PUBLIC_KEY_LEN {
            return Err(Zp1Error::LimitExceeded);
        }
        let recipient_pk_hash = hash1(DOMAIN_RECIPIENT_PK, recipient_pk_bytes);
        let (kem_ciphertext, ss_j) = provider.encapsulate(recipient_pk)?;
        if kem_ciphertext.len() > MAX_KEM_CT_LEN {
            return Err(Zp1Error::LimitExceeded);
        }
        let recipient_index = u32::try_from(index).map_err(|_| Zp1Error::LimitExceeded)?;
        let recipient_header = RecipientHeader {
            recipient_index,
            recipient_pk_hash,
            kem_ciphertext,
        };
        let recipient_header_bytes = recipient_header.encode();
        let wrap_salt = hash_many(
            DOMAIN_RECIPIENT_WRAP_SALT,
            &[&base_header_bytes, &recipient_header_bytes],
        );
        let prk_wrap =
            Zeroizing::new(extract(&wrap_salt, ss_j.as_slice()).map_err(|_| Zp1Error::Provider)?);
        let wrap_context = encode_context(&[&base_header_bytes, &recipient_header_bytes])
            .map_err(|_| Zp1Error::Provider)?;
        let k_wrap_secret = expand(&*prk_wrap, DOMAIN_WRAP_KEY, &wrap_context, AEAD_KEY_LEN)
            .map_err(|_| Zp1Error::Provider)?;
        let k_wrap = secret_to_key32(&k_wrap_secret).map_err(|_| Zp1Error::Provider)?;
        let mut wrap_aad =
            Vec::with_capacity(base_header_bytes.len() + recipient_header_bytes.len());
        wrap_aad.extend_from_slice(&base_header_bytes);
        wrap_aad.extend_from_slice(&recipient_header_bytes);
        let nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        let wrapped_content_secret =
            seal_aes256_gcm_siv(&k_wrap, &nonce, &wrap_aad, content_secret.as_slice())
                .map_err(|_| Zp1Error::Provider)?;
        let stanza = RecipientStanza {
            recipient_header,
            wrapped_content_secret,
        };
        let encoded = stanza.encode();
        recipient_stanza_bytes.push(encoded);
        recipient_stanzas.push(stanza);
    }

    let stanzas_parts = recipient_stanza_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let stanzas_hash = hash_many(DOMAIN_RECIPIENT_STANZAS, &stanzas_parts);

    let content_salt = hash_many(
        DOMAIN_CONTENT_SALT,
        &[&base_header_bytes, &stanzas_hash, &aad_hash],
    );
    let prk_content = Zeroizing::new(
        extract(&content_salt, content_secret.as_slice()).map_err(|_| Zp1Error::Provider)?,
    );
    let content_context =
        encode_context(&[&base_header_bytes, &stanzas_hash]).map_err(|_| Zp1Error::Provider)?;
    let k_aead_secret = expand(
        &*prk_content,
        DOMAIN_CHUNK_AEAD_KEY,
        &content_context,
        AEAD_KEY_LEN,
    )
    .map_err(|_| Zp1Error::Provider)?;
    let k_commit_secret = expand(
        &*prk_content,
        DOMAIN_KEY_COMMITMENT_KEY,
        &content_context,
        AEAD_KEY_LEN,
    )
    .map_err(|_| Zp1Error::Provider)?;
    let k_manifest_secret = expand(
        &*prk_content,
        DOMAIN_MANIFEST_MAC_KEY,
        &content_context,
        AEAD_KEY_LEN,
    )
    .map_err(|_| Zp1Error::Provider)?;
    let k_aead = secret_to_key32(&k_aead_secret).map_err(|_| Zp1Error::Provider)?;
    let k_commit = secret_to_key32(&k_commit_secret).map_err(|_| Zp1Error::Provider)?;
    let k_manifest = secret_to_key32(&k_manifest_secret).map_err(|_| Zp1Error::Provider)?;

    let key_commitment_data = hash_many_input(
        DOMAIN_CONTENT_KEY_COMMITMENT,
        &[&base_header_bytes, &stanzas_hash, &aad_hash],
    );
    let key_commitment =
        hmac_sha384(&*k_commit, &key_commitment_data).map_err(|_| Zp1Error::Provider)?;
    let _: [u8; KEY_COMMITMENT_LEN] = key_commitment;

    let base_header_hash = sha384(&base_header_bytes);
    let mut chunks = Vec::with_capacity(chunk_count_usize);
    let mut leaves = Vec::with_capacity(chunk_count_usize);
    let chunk_size = usize::try_from(options.chunk_size).map_err(|_| Zp1Error::LimitExceeded)?;

    for index in 0..chunk_count_usize {
        let start = index
            .checked_mul(chunk_size)
            .ok_or(Zp1Error::LimitExceeded)?;
        let chunk = if plaintext.is_empty() {
            &plaintext[0..0]
        } else {
            let end = core::cmp::min(
                start
                    .checked_add(chunk_size)
                    .ok_or(Zp1Error::LimitExceeded)?,
                plaintext.len(),
            );
            &plaintext[start..end]
        };
        let index_u64 = u64::try_from(index).map_err(|_| Zp1Error::LimitExceeded)?;
        let nonce = chunk_nonce(index_u64);
        let chunk_len_u64 = u64::try_from(chunk.len()).map_err(|_| Zp1Error::LimitExceeded)?;
        let chunk_aad = encode_chunk_aad(ChunkAadInput {
            base_header_hash: &base_header_hash,
            stanzas_hash: &stanzas_hash,
            key_commitment: &key_commitment,
            aad_hash: &aad_hash,
            index: index_u64,
            chunk_count,
            plaintext_length,
            chunk_length: chunk_len_u64,
        });
        let ciphertext = seal_aes256_gcm_siv(&k_aead, &nonce, &chunk_aad, chunk)
            .map_err(|_| Zp1Error::Provider)?;
        let leaf = merkle_leaf(index_u64, chunk_len_u64, &nonce, &ciphertext, &chunk_aad);
        leaves.push(leaf);
        chunks.push(ciphertext);
    }

    let merkle_root = merkle_root(&leaves).ok_or(Zp1Error::Provider)?;
    let public_manifest = PublicManifest {
        base_header_hash,
        stanzas_hash,
        key_commitment,
        chunk_count,
        chunk_size: options.chunk_size,
        plaintext_length,
        merkle_root,
        aad_hash,
        signer_pk_hash,
    };
    let public_manifest_bytes = public_manifest.encode();

    let manifest_tag_data = hash_many_input(DOMAIN_MANIFEST_TAG, &[&public_manifest_bytes]);
    let manifest_tag =
        hmac_sha384(&*k_manifest, &manifest_tag_data).map_err(|_| Zp1Error::Provider)?;

    let mut sig_parts = Vec::with_capacity(3 + recipient_stanza_bytes.len());
    sig_parts.push(base_header_bytes.as_slice());
    for stanza in &recipient_stanza_bytes {
        sig_parts.push(stanza.as_slice());
    }
    sig_parts.push(public_manifest_bytes.as_slice());
    sig_parts.push(manifest_tag.as_slice());
    let sig_input_hash = hash_many(DOMAIN_SIGNATURE_INPUT, &sig_parts);
    let mldsa_signature = provider.sign_mldsa87(signer_secret_key, &sig_input_hash)?;
    if mldsa_signature.len() > MAX_SIGNATURE_LEN {
        return Err(Zp1Error::LimitExceeded);
    }

    let signature_block = SignatureBlock {
        signer_public_key: signer_public_key_bytes.to_vec(),
        mldsa_signature,
        archive: None,
    };
    let object = Zp1Object {
        suite_id: options.suite_id,
        base_header,
        recipient_stanzas,
        public_manifest,
        chunks,
        manifest_tag,
        signature_block,
    };

    content_secret.zeroize();
    Ok(object.encode())
}

pub(crate) fn chunk_nonce(index: u64) -> [u8; AES_GCM_SIV_NONCE_LEN] {
    let mut nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

pub(crate) fn seal_aes256_gcm_siv(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AES_GCM_SIV_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, InternalCryptoError> {
    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| InternalCryptoError)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| InternalCryptoError)
}

pub(crate) fn open_aes256_gcm_siv(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AES_GCM_SIV_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, InternalCryptoError> {
    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| InternalCryptoError)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| InternalCryptoError)
}
