//! SHA-384 and domain-separated hash helpers.

use sha2::{Digest, Sha384};

use crate::codec::{put_u16, put_u64};
use crate::constants::HASH_LEN;

/// Compute SHA-384 over `data`.
pub fn sha384(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha384::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compute a domain-separated single-part hash.
pub fn hash1(domain: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    hash_many(domain, &[data])
}

/// Compute a domain-separated length-prefixed hash over many byte parts.
pub fn hash_many(domain: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    sha384(&hash_many_input(domain, parts))
}

pub(crate) fn hash_many_input(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut input = Vec::new();
    let domain_len = u16::try_from(domain.len()).unwrap_or(u16::MAX);
    put_u16(&mut input, domain_len);
    input.extend_from_slice(domain);
    for part in parts {
        let part_len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        put_u64(&mut input, part_len);
        input.extend_from_slice(part);
    }
    input
}
