//! HMAC-SHA384 extract/expand KDF helpers.

use hmac::{Hmac, Mac};
use sha2::Sha384;
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{put_u16, put_u32, put_u64};
use crate::constants::{AEAD_KEY_LEN, DOMAIN_KDF, HASH_LEN};
use crate::provider::SecretBytes;

type HmacSha384 = Hmac<Sha384>;

/// KDF failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfError;

/// HMAC-SHA384 extract.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; HASH_LEN], KdfError> {
    hmac_sha384(salt, ikm)
}

/// HMAC-SHA384 expand.
pub fn expand(
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Result<SecretBytes, KdfError> {
    let label_len = u16::try_from(label.len()).map_err(|_| KdfError)?;
    let context_len = u32::try_from(context.len()).map_err(|_| KdfError)?;
    let out_bits = out_len.checked_mul(8).ok_or(KdfError)?;
    let out_bits = u32::try_from(out_bits).map_err(|_| KdfError)?;
    let block_count = if out_len == 0 {
        0usize
    } else {
        out_len.checked_add(HASH_LEN - 1).ok_or(KdfError)? / HASH_LEN
    };
    let block_count_u32 = u32::try_from(block_count).map_err(|_| KdfError)?;

    let mut previous_t: Vec<u8> = Vec::new();
    let mut okm = Vec::with_capacity(out_len);

    for counter in 1..=block_count_u32 {
        let mut data = Vec::new();
        data.extend_from_slice(&previous_t);
        put_u32(&mut data, counter);
        let kdf_len = u16::try_from(DOMAIN_KDF.len()).map_err(|_| KdfError)?;
        put_u16(&mut data, kdf_len);
        data.extend_from_slice(DOMAIN_KDF);
        put_u16(&mut data, label_len);
        data.extend_from_slice(label);
        put_u32(&mut data, context_len);
        data.extend_from_slice(context);
        put_u32(&mut data, out_bits);

        previous_t.zeroize();
        previous_t = hmac_sha384(prk, &data)?.to_vec();
        data.zeroize();
        okm.extend_from_slice(&previous_t);
    }

    okm.truncate(out_len);
    previous_t.zeroize();
    Ok(SecretBytes::new(okm))
}

pub(crate) fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; HASH_LEN], KdfError> {
    let mut mac = HmacSha384::new_from_slice(key).map_err(|_| KdfError)?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn encode_context(parts: &[&[u8]]) -> Result<Vec<u8>, KdfError> {
    let mut out = Vec::new();
    for part in parts {
        let len = u64::try_from(part.len()).map_err(|_| KdfError)?;
        put_u64(&mut out, len);
        out.extend_from_slice(part);
    }
    Ok(out)
}

pub(crate) fn secret_to_key32(
    secret: &SecretBytes,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, KdfError> {
    if secret.len() != AEAD_KEY_LEN {
        return Err(KdfError);
    }
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    key.copy_from_slice(secret.as_slice());
    Ok(key)
}
