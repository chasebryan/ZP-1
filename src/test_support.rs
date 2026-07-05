//! NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.
//!
//! Test-only helpers for vector inspection and precise byte mutation.

use std::ops::Range;

use subtle::ConstantTimeEq;

use crate::constants::{
    DOMAIN_CHUNK_AAD, DOMAIN_CONTENT_KEY_COMMITMENT, DOMAIN_CONTENT_SALT,
    DOMAIN_KEY_COMMITMENT_KEY, DOMAIN_MANIFEST_MAC_KEY, DOMAIN_MANIFEST_TAG,
    DOMAIN_RECIPIENT_STANZAS, DOMAIN_RECIPIENT_WRAP_SALT, DOMAIN_SIGNATURE_INPUT, DOMAIN_WRAP_KEY,
    HASH_LEN,
};
use crate::error::InternalParseError;
use crate::hash::{hash_many, hash_many_input, sha384};
use crate::kdf::{encode_context, expand, extract, hmac_sha384};
use crate::merkle::{merkle_leaf, merkle_root};
use crate::object::Zp1Object;
use crate::provider::test_utils::{InsecureTestProvider, TestKemSecretKey};
use crate::provider::KemProvider;
use crate::seal::{chunk_nonce, open_aes256_gcm_siv};

/// Byte spans for a canonical top-level ZP-1 object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSpans {
    pub magic: Range<usize>,
    pub version: Range<usize>,
    pub suite_id: Range<usize>,
    pub base_header_len: Range<usize>,
    pub base_header: Range<usize>,
    pub recipient_count: Range<usize>,
    pub recipient_stanza_lens: Vec<Range<usize>>,
    pub recipient_stanzas: Vec<Range<usize>>,
    pub public_manifest_len: Range<usize>,
    pub public_manifest: Range<usize>,
    pub chunk_count: Range<usize>,
    pub chunk_lens: Vec<Range<usize>>,
    pub chunks: Vec<Range<usize>>,
    pub manifest_tag_len: Range<usize>,
    pub manifest_tag: Range<usize>,
    pub signature_block_len: Range<usize>,
    pub signature_block: Range<usize>,
}

/// Recomputed transcript values for a ZP-1 test vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorInspection {
    pub base_header_hash: [u8; HASH_LEN],
    pub stanzas_hash: [u8; HASH_LEN],
    pub key_commitment: [u8; HASH_LEN],
    pub merkle_root: [u8; HASH_LEN],
    pub manifest_tag: [u8; HASH_LEN],
    pub signature_input_hash: [u8; HASH_LEN],
}

/// Return byte spans for a syntactically well-framed top-level object.
pub fn object_spans(input: &[u8]) -> Result<ObjectSpans, InternalParseError> {
    let mut pos = 0usize;
    let magic = take(&mut pos, 4, input.len())?;
    let version = take(&mut pos, 2, input.len())?;
    let suite_id = take(&mut pos, 2, input.len())?;

    let base_header_len = take(&mut pos, 4, input.len())?;
    let base_header_size = read_u32(input, base_header_len.start)?;
    let base_header = take(&mut pos, base_header_size, input.len())?;

    let recipient_count = take(&mut pos, 2, input.len())?;
    let recipient_total = usize::from(read_u16(input, recipient_count.start)?);
    let mut recipient_stanza_lens = Vec::with_capacity(recipient_total);
    let mut recipient_stanzas = Vec::with_capacity(recipient_total);
    for _ in 0..recipient_total {
        let stanza_len = take(&mut pos, 4, input.len())?;
        let stanza_size = read_u32(input, stanza_len.start)?;
        let stanza = take(&mut pos, stanza_size, input.len())?;
        recipient_stanza_lens.push(stanza_len);
        recipient_stanzas.push(stanza);
    }

    let public_manifest_len = take(&mut pos, 4, input.len())?;
    let public_manifest_size = read_u32(input, public_manifest_len.start)?;
    let public_manifest = take(&mut pos, public_manifest_size, input.len())?;

    let chunk_count = take(&mut pos, 8, input.len())?;
    let chunk_total =
        usize::try_from(read_u64(input, chunk_count.start)?).map_err(|_| InternalParseError)?;
    let mut chunk_lens = Vec::with_capacity(chunk_total.min(1024));
    let mut chunks = Vec::with_capacity(chunk_total.min(1024));
    for _ in 0..chunk_total {
        let chunk_len = take(&mut pos, 4, input.len())?;
        let chunk_size = read_u32(input, chunk_len.start)?;
        let chunk = take(&mut pos, chunk_size, input.len())?;
        chunk_lens.push(chunk_len);
        chunks.push(chunk);
    }

    let manifest_tag_len = take(&mut pos, 2, input.len())?;
    let manifest_tag_size = usize::from(read_u16(input, manifest_tag_len.start)?);
    let manifest_tag = take(&mut pos, manifest_tag_size, input.len())?;

    let signature_block_len = take(&mut pos, 4, input.len())?;
    let signature_block_size = read_u32(input, signature_block_len.start)?;
    let signature_block = take(&mut pos, signature_block_size, input.len())?;

    if pos != input.len() {
        return Err(InternalParseError);
    }

    Ok(ObjectSpans {
        magic,
        version,
        suite_id,
        base_header_len,
        base_header,
        recipient_count,
        recipient_stanza_lens,
        recipient_stanzas,
        public_manifest_len,
        public_manifest,
        chunk_count,
        chunk_lens,
        chunks,
        manifest_tag_len,
        manifest_tag,
        signature_block_len,
        signature_block,
    })
}

/// Return the `archive_present` byte offset inside a signature block.
pub fn archive_present_offset(
    input: &[u8],
    spans: &ObjectSpans,
) -> Result<usize, InternalParseError> {
    let mut pos = spans.signature_block.start;
    let domain_len = usize::from(read_u16(input, pos)?);
    pos = pos
        .checked_add(2)
        .and_then(|value| value.checked_add(domain_len))
        .ok_or(InternalParseError)?;
    let signer_pk_len = read_u32(input, pos)?;
    pos = pos
        .checked_add(4)
        .and_then(|value| value.checked_add(signer_pk_len))
        .ok_or(InternalParseError)?;
    let sig_len = read_u32(input, pos)?;
    pos = pos
        .checked_add(4)
        .and_then(|value| value.checked_add(sig_len))
        .ok_or(InternalParseError)?;
    if pos >= spans.signature_block.end {
        return Err(InternalParseError);
    }
    Ok(pos)
}

/// Recompute vector transcript values from an opened test-provider object.
pub fn inspect_vector_object(
    provider: &mut InsecureTestProvider,
    recipient_sk: &TestKemSecretKey,
    object: &Zp1Object,
) -> Result<VectorInspection, InternalParseError> {
    let base_header_bytes = object.base_header.encode();
    let base_header_hash = sha384(&base_header_bytes);

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

    let stanza = object.recipient_stanzas.first().ok_or(InternalParseError)?;
    let recipient_header_bytes = stanza.recipient_header.encode();
    let ss = provider
        .decapsulate(recipient_sk, &stanza.recipient_header.kem_ciphertext)
        .map_err(|_| InternalParseError)?;
    let wrap_salt = hash_many(
        DOMAIN_RECIPIENT_WRAP_SALT,
        &[&base_header_bytes, &recipient_header_bytes],
    );
    let prk_wrap = extract(&wrap_salt, ss.as_slice()).map_err(|_| InternalParseError)?;
    let wrap_context = encode_context(&[&base_header_bytes, &recipient_header_bytes])
        .map_err(|_| InternalParseError)?;
    let k_wrap =
        expand(&prk_wrap, DOMAIN_WRAP_KEY, &wrap_context, 32).map_err(|_| InternalParseError)?;
    let mut wrap_aad = Vec::new();
    wrap_aad.extend_from_slice(&base_header_bytes);
    wrap_aad.extend_from_slice(&recipient_header_bytes);
    let content_secret = open_aes256_gcm_siv(
        key32(k_wrap.as_slice())?,
        &[0u8; 12],
        &wrap_aad,
        &stanza.wrapped_content_secret,
    )
    .map_err(|_| InternalParseError)?;

    let content_salt = hash_many(
        DOMAIN_CONTENT_SALT,
        &[
            &base_header_bytes,
            &stanzas_hash,
            &object.public_manifest.aad_hash,
        ],
    );
    let prk_content = extract(&content_salt, &content_secret).map_err(|_| InternalParseError)?;
    let content_context =
        encode_context(&[&base_header_bytes, &stanzas_hash]).map_err(|_| InternalParseError)?;
    let k_commit = expand(
        &prk_content,
        DOMAIN_KEY_COMMITMENT_KEY,
        &content_context,
        32,
    )
    .map_err(|_| InternalParseError)?;
    let k_manifest = expand(&prk_content, DOMAIN_MANIFEST_MAC_KEY, &content_context, 32)
        .map_err(|_| InternalParseError)?;

    let key_commitment_data = hash_many_input(
        DOMAIN_CONTENT_KEY_COMMITMENT,
        &[
            &base_header_bytes,
            &stanzas_hash,
            &object.public_manifest.aad_hash,
        ],
    );
    let key_commitment =
        hmac_sha384(k_commit.as_slice(), &key_commitment_data).map_err(|_| InternalParseError)?;

    let mut leaves = Vec::new();
    for (index, ciphertext) in object.chunks.iter().enumerate() {
        let index = u64::try_from(index).map_err(|_| InternalParseError)?;
        let chunk_len = expected_plaintext_chunk_len(
            index,
            object.public_manifest.chunk_count,
            object.public_manifest.chunk_size,
            object.public_manifest.plaintext_length,
        )
        .ok_or(InternalParseError)?;
        let nonce = chunk_nonce(index);
        let chunk_aad = encode_chunk_aad(ChunkAadParts {
            base_header_hash: &base_header_hash,
            stanzas_hash: &stanzas_hash,
            key_commitment: &object.public_manifest.key_commitment,
            aad_hash: &object.public_manifest.aad_hash,
            index,
            chunk_count: object.public_manifest.chunk_count,
            plaintext_length: object.public_manifest.plaintext_length,
            chunk_length: chunk_len,
        });
        leaves.push(merkle_leaf(
            index, chunk_len, &nonce, ciphertext, &chunk_aad,
        ));
    }
    let merkle_root = merkle_root(&leaves).ok_or(InternalParseError)?;

    let public_manifest_bytes = object.public_manifest.encode();
    let manifest_tag_data = hash_many_input(DOMAIN_MANIFEST_TAG, &[&public_manifest_bytes]);
    let manifest_tag =
        hmac_sha384(k_manifest.as_slice(), &manifest_tag_data).map_err(|_| InternalParseError)?;

    let mut sig_parts = Vec::new();
    sig_parts.push(base_header_bytes.as_slice());
    for stanza in &recipient_stanza_bytes {
        sig_parts.push(stanza.as_slice());
    }
    sig_parts.push(public_manifest_bytes.as_slice());
    sig_parts.push(object.manifest_tag.as_slice());
    let signature_input_hash = hash_many(DOMAIN_SIGNATURE_INPUT, &sig_parts);

    Ok(VectorInspection {
        base_header_hash,
        stanzas_hash,
        key_commitment,
        merkle_root,
        manifest_tag,
        signature_input_hash,
    })
}

/// Constant-time equality helper for tests.
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn take(pos: &mut usize, len: usize, total: usize) -> Result<Range<usize>, InternalParseError> {
    let start = *pos;
    let end = start.checked_add(len).ok_or(InternalParseError)?;
    if end > total {
        return Err(InternalParseError);
    }
    *pos = end;
    Ok(start..end)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, InternalParseError> {
    let bytes = input.get(offset..offset + 2).ok_or(InternalParseError)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<usize, InternalParseError> {
    let bytes = input.get(offset..offset + 4).ok_or(InternalParseError)?;
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    usize::try_from(value).map_err(|_| InternalParseError)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, InternalParseError> {
    let bytes = input.get(offset..offset + 8).ok_or(InternalParseError)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn key32(input: &[u8]) -> Result<&[u8; 32], InternalParseError> {
    input.try_into().map_err(|_| InternalParseError)
}

struct ChunkAadParts<'a> {
    base_header_hash: &'a [u8; HASH_LEN],
    stanzas_hash: &'a [u8; HASH_LEN],
    key_commitment: &'a [u8; HASH_LEN],
    aad_hash: &'a [u8; HASH_LEN],
    index: u64,
    chunk_count: u64,
    plaintext_length: u64,
    chunk_length: u64,
}

fn encode_chunk_aad(parts: ChunkAadParts<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u16::try_from(DOMAIN_CHUNK_AAD.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    out.extend_from_slice(DOMAIN_CHUNK_AAD);
    out.extend_from_slice(parts.base_header_hash);
    out.extend_from_slice(parts.stanzas_hash);
    out.extend_from_slice(parts.key_commitment);
    out.extend_from_slice(parts.aad_hash);
    out.extend_from_slice(&parts.index.to_be_bytes());
    out.extend_from_slice(&parts.chunk_count.to_be_bytes());
    out.extend_from_slice(&parts.plaintext_length.to_be_bytes());
    out.extend_from_slice(&parts.chunk_length.to_be_bytes());
    out
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
