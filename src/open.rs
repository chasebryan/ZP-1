//! ZP-1 opening API.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::constants::{
    AES_GCM_SIV_TAG_LEN, CONTENT_SECRET_LEN, DOMAIN_AAD, DOMAIN_CHUNK_AEAD_KEY,
    DOMAIN_CONTENT_KEY_COMMITMENT, DOMAIN_CONTENT_SALT, DOMAIN_KEY_COMMITMENT_KEY,
    DOMAIN_MANIFEST_MAC_KEY, DOMAIN_MANIFEST_TAG, DOMAIN_RECIPIENT_STANZAS,
    DOMAIN_RECIPIENT_WRAP_SALT, DOMAIN_SIGNATURE_INPUT, DOMAIN_SIGNER_PK, DOMAIN_WRAP_KEY,
    MAX_AAD_LEN, MAX_CHUNKS, MAX_CHUNK_SIZE, MAX_PLAINTEXT_LEN, MIN_CHUNK_SIZE,
};
use crate::error::Zp1Error;
use crate::hash::{hash1, hash_many, hash_many_input, sha384};
use crate::kdf::{encode_context, expand, extract, hmac_sha384, secret_to_key32};
use crate::merkle::{merkle_leaf, merkle_root};
use crate::object::{encode_chunk_aad, ChunkAadInput, SuiteId, Zp1Object};
use crate::provider::{SecretBytes, Zp1Provider};
use crate::seal::{chunk_nonce, open_aes256_gcm_siv};

/// Open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenOptions {
    /// Require the optional archive signature.
    pub require_archive_signature: bool,
}

/// Open a ZP-1 object.
pub fn open<P>(
    provider: &mut P,
    recipient_secret_key: &P::KemSecretKey,
    expected_signer_public_key: &P::SignaturePublicKey,
    aad: &[u8],
    object_bytes: &[u8],
    options: OpenOptions,
) -> Result<Vec<u8>, Zp1Error>
where
    P: Zp1Provider,
{
    let object = Zp1Object::decode(object_bytes).map_err(|_| Zp1Error::Auth)?;
    if object.suite_id == SuiteId::Zp1Archive {
        return Err(Zp1Error::UnsupportedSuite);
    }
    if options.require_archive_signature {
        if object.signature_block.archive.is_none() {
            return Err(Zp1Error::Auth);
        }
        return Err(Zp1Error::UnsupportedSuite);
    }
    validate_open_limits(&object, aad.len()).map_err(|_| Zp1Error::Auth)?;

    let aad_hash = hash1(DOMAIN_AAD, aad);
    require_ct_eq(&aad_hash, &object.base_header.aad_hash)?;
    require_ct_eq(&aad_hash, &object.public_manifest.aad_hash)?;
    require_ct_eq(
        &object.base_header.aad_hash,
        &object.public_manifest.aad_hash,
    )?;
    require_ct_eq(
        &object.base_header.signer_pk_hash,
        &object.public_manifest.signer_pk_hash,
    )?;

    let base_header_bytes = object.base_header.encode();
    let base_header_hash = sha384(&base_header_bytes);
    require_ct_eq(&object.public_manifest.base_header_hash, &base_header_hash)?;
    if object.public_manifest.chunk_count
        != u64::try_from(object.chunks.len()).map_err(|_| Zp1Error::Auth)?
        || object.public_manifest.chunk_size != object.base_header.chunk_size
        || object.public_manifest.plaintext_length != object.base_header.plaintext_length
    {
        return Err(Zp1Error::Auth);
    }

    let recipient_stanza_bytes = object
        .recipient_stanzas
        .iter()
        .map(|stanza| stanza.encode())
        .collect::<Vec<_>>();
    let stanza_parts = recipient_stanza_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let stanzas_hash = hash_many(DOMAIN_RECIPIENT_STANZAS, &stanza_parts);
    require_ct_eq(&stanzas_hash, &object.public_manifest.stanzas_hash)?;

    let signer_pk_hash = hash1(DOMAIN_SIGNER_PK, &object.signature_block.signer_public_key);
    require_ct_eq(&signer_pk_hash, &object.public_manifest.signer_pk_hash)?;
    let expected_signer_public_key_bytes =
        P::signature_public_key_bytes(expected_signer_public_key);
    require_ct_eq(
        &object.signature_block.signer_public_key,
        expected_signer_public_key_bytes,
    )?;

    let public_manifest_bytes = object.public_manifest.encode();
    let mut sig_parts = Vec::with_capacity(3 + recipient_stanza_bytes.len());
    sig_parts.push(base_header_bytes.as_slice());
    for stanza in &recipient_stanza_bytes {
        sig_parts.push(stanza.as_slice());
    }
    sig_parts.push(public_manifest_bytes.as_slice());
    sig_parts.push(object.manifest_tag.as_slice());
    let sig_input_hash = hash_many(DOMAIN_SIGNATURE_INPUT, &sig_parts);

    let signature_ok = provider
        .verify_mldsa87(
            expected_signer_public_key,
            &sig_input_hash,
            &object.signature_block.mldsa_signature,
        )
        .map_err(|_| Zp1Error::Auth)?;
    if !signature_ok {
        return Err(Zp1Error::Auth);
    }

    let recipient_sk_public_hash = provider
        .derive_public_key_hash_from_secret(recipient_secret_key)
        .map_err(|_| Zp1Error::Auth)?;
    let mut found_index = None;
    for (index, stanza) in object.recipient_stanzas.iter().enumerate() {
        if ct_eq(
            &stanza.recipient_header.recipient_pk_hash,
            &recipient_sk_public_hash,
        ) {
            if found_index.is_some() {
                return Err(Zp1Error::Auth);
            }
            found_index = Some(index);
        }
    }
    let found_index = found_index.ok_or(Zp1Error::Auth)?;
    let stanza = &object.recipient_stanzas[found_index];
    let recipient_header_bytes = stanza.recipient_header.encode();

    let ss_j = provider
        .decapsulate(
            recipient_secret_key,
            &stanza.recipient_header.kem_ciphertext,
        )
        .map_err(|_| Zp1Error::Auth)?;
    let wrap_salt = hash_many(
        DOMAIN_RECIPIENT_WRAP_SALT,
        &[&base_header_bytes, &recipient_header_bytes],
    );
    let prk_wrap =
        Zeroizing::new(extract(&wrap_salt, ss_j.as_slice()).map_err(|_| Zp1Error::Auth)?);
    let wrap_context = encode_context(&[&base_header_bytes, &recipient_header_bytes])
        .map_err(|_| Zp1Error::Auth)?;
    let k_wrap_secret =
        expand(&*prk_wrap, DOMAIN_WRAP_KEY, &wrap_context, 32).map_err(|_| Zp1Error::Auth)?;
    let k_wrap = secret_to_key32(&k_wrap_secret).map_err(|_| Zp1Error::Auth)?;
    let mut wrap_aad = Vec::with_capacity(base_header_bytes.len() + recipient_header_bytes.len());
    wrap_aad.extend_from_slice(&base_header_bytes);
    wrap_aad.extend_from_slice(&recipient_header_bytes);
    let nonce = [0u8; 12];
    let content_secret_plaintext =
        open_aes256_gcm_siv(&k_wrap, &nonce, &wrap_aad, &stanza.wrapped_content_secret)
            .map_err(|_| Zp1Error::Auth)?;
    if content_secret_plaintext.len() != CONTENT_SECRET_LEN {
        return Err(Zp1Error::Auth);
    }
    let mut content_secret = SecretBytes::new(content_secret_plaintext);

    let content_salt = hash_many(
        DOMAIN_CONTENT_SALT,
        &[&base_header_bytes, &stanzas_hash, &aad_hash],
    );
    let prk_content = Zeroizing::new(
        extract(&content_salt, content_secret.as_slice()).map_err(|_| Zp1Error::Auth)?,
    );
    let content_context =
        encode_context(&[&base_header_bytes, &stanzas_hash]).map_err(|_| Zp1Error::Auth)?;
    let k_aead_secret = expand(&*prk_content, DOMAIN_CHUNK_AEAD_KEY, &content_context, 32)
        .map_err(|_| Zp1Error::Auth)?;
    let k_commit_secret = expand(
        &*prk_content,
        DOMAIN_KEY_COMMITMENT_KEY,
        &content_context,
        32,
    )
    .map_err(|_| Zp1Error::Auth)?;
    let k_manifest_secret = expand(&*prk_content, DOMAIN_MANIFEST_MAC_KEY, &content_context, 32)
        .map_err(|_| Zp1Error::Auth)?;
    let k_aead = secret_to_key32(&k_aead_secret).map_err(|_| Zp1Error::Auth)?;
    let k_commit = secret_to_key32(&k_commit_secret).map_err(|_| Zp1Error::Auth)?;
    let k_manifest = secret_to_key32(&k_manifest_secret).map_err(|_| Zp1Error::Auth)?;

    let key_commitment_data = hash_many_input(
        DOMAIN_CONTENT_KEY_COMMITMENT,
        &[&base_header_bytes, &stanzas_hash, &aad_hash],
    );
    let key_commitment =
        hmac_sha384(&*k_commit, &key_commitment_data).map_err(|_| Zp1Error::Auth)?;
    require_ct_eq(&key_commitment, &object.public_manifest.key_commitment)?;

    let manifest_tag_data = hash_many_input(DOMAIN_MANIFEST_TAG, &[&public_manifest_bytes]);
    let manifest_tag = hmac_sha384(&*k_manifest, &manifest_tag_data).map_err(|_| Zp1Error::Auth)?;
    require_ct_eq(&manifest_tag, &object.manifest_tag)?;

    let chunk_count = object.public_manifest.chunk_count;
    let expected_chunk_count = expected_chunk_count(
        object.public_manifest.plaintext_length,
        object.public_manifest.chunk_size,
    )
    .ok_or(Zp1Error::Auth)?;
    if chunk_count != expected_chunk_count {
        return Err(Zp1Error::Auth);
    }

    let mut leaves = Vec::with_capacity(object.chunks.len());
    let mut chunk_aads = Vec::with_capacity(object.chunks.len());
    for (index, ciphertext) in object.chunks.iter().enumerate() {
        let index_u64 = u64::try_from(index).map_err(|_| Zp1Error::Auth)?;
        let plaintext_chunk_len = expected_plaintext_chunk_len(
            index_u64,
            chunk_count,
            object.public_manifest.chunk_size,
            object.public_manifest.plaintext_length,
        )
        .ok_or(Zp1Error::Auth)?;
        let expected_ciphertext_len = plaintext_chunk_len
            .checked_add(AES_GCM_SIV_TAG_LEN)
            .ok_or(Zp1Error::Auth)?;
        if u64::try_from(ciphertext.len()).map_err(|_| Zp1Error::Auth)? != expected_ciphertext_len {
            return Err(Zp1Error::Auth);
        }
        let nonce = chunk_nonce(index_u64);
        let chunk_aad = encode_chunk_aad(ChunkAadInput {
            base_header_hash: &base_header_hash,
            stanzas_hash: &stanzas_hash,
            key_commitment: &object.public_manifest.key_commitment,
            aad_hash: &aad_hash,
            index: index_u64,
            chunk_count,
            plaintext_length: object.public_manifest.plaintext_length,
            chunk_length: plaintext_chunk_len,
        });
        let leaf = merkle_leaf(
            index_u64,
            plaintext_chunk_len,
            &nonce,
            ciphertext,
            &chunk_aad,
        );
        leaves.push(leaf);
        chunk_aads.push(chunk_aad);
    }
    let merkle_root = merkle_root(&leaves).ok_or(Zp1Error::Auth)?;
    require_ct_eq(&merkle_root, &object.public_manifest.merkle_root)?;

    let plaintext_capacity =
        usize::try_from(object.public_manifest.plaintext_length).map_err(|_| Zp1Error::Auth)?;
    let mut plaintext = Vec::with_capacity(plaintext_capacity);
    for (index, ciphertext) in object.chunks.iter().enumerate() {
        let index_u64 = u64::try_from(index).map_err(|_| Zp1Error::Auth)?;
        let nonce = chunk_nonce(index_u64);
        let chunk = open_aes256_gcm_siv(&k_aead, &nonce, &chunk_aads[index], ciphertext)
            .map_err(|_| Zp1Error::Auth)?;
        plaintext.extend_from_slice(&chunk);
    }
    if u64::try_from(plaintext.len()).map_err(|_| Zp1Error::Auth)?
        != object.base_header.plaintext_length
    {
        return Err(Zp1Error::Auth);
    }

    content_secret.zeroize();
    Ok(plaintext)
}

fn validate_open_limits(object: &Zp1Object, aad_len: usize) -> Result<(), Zp1Error> {
    if object.suite_id != SuiteId::Zp1Core || object.base_header.suite_id != object.suite_id {
        return Err(Zp1Error::Auth);
    }
    if u64::try_from(aad_len).map_err(|_| Zp1Error::Auth)? > MAX_AAD_LEN {
        return Err(Zp1Error::Auth);
    }
    if object.base_header.plaintext_length > MAX_PLAINTEXT_LEN {
        return Err(Zp1Error::Auth);
    }
    if object.public_manifest.chunk_count == 0 || object.public_manifest.chunk_count > MAX_CHUNKS {
        return Err(Zp1Error::Auth);
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&object.base_header.chunk_size) {
        return Err(Zp1Error::Auth);
    }
    Ok(())
}

fn expected_chunk_count(plaintext_length: u64, chunk_size: u32) -> Option<u64> {
    if chunk_size == 0 {
        return None;
    }
    if plaintext_length == 0 {
        Some(1)
    } else {
        plaintext_length
            .checked_add(u64::from(chunk_size) - 1)
            .map(|value| value / u64::from(chunk_size))
    }
}

fn expected_plaintext_chunk_len(
    index: u64,
    chunk_count: u64,
    chunk_size: u32,
    plaintext_length: u64,
) -> Option<u64> {
    if chunk_count == 0 || index >= chunk_count {
        return None;
    }
    if plaintext_length == 0 {
        return if chunk_count == 1 && index == 0 {
            Some(0)
        } else {
            None
        };
    }
    if index + 1 < chunk_count {
        Some(u64::from(chunk_size))
    } else {
        let consumed = u64::from(chunk_size).checked_mul(chunk_count.checked_sub(1)?)?;
        plaintext_length.checked_sub(consumed)
    }
}

fn require_ct_eq(left: &[u8], right: &[u8]) -> Result<(), Zp1Error> {
    if ct_eq(left, right) {
        Ok(())
    } else {
        Err(Zp1Error::Auth)
    }
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}
