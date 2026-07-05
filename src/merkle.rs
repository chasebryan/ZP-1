//! Domain-separated SHA-384 Merkle tree.

use crate::constants::{DOMAIN_MERKLE_LEAF, DOMAIN_MERKLE_NODE, DOMAIN_MERKLE_ROOT, HASH_LEN};
use crate::hash::{hash_many, sha384};

/// Compute a ZP-1 Merkle leaf.
pub fn merkle_leaf(
    index: u64,
    plaintext_chunk_len: u64,
    nonce: &[u8],
    ciphertext: &[u8],
    chunk_aad: &[u8],
) -> [u8; HASH_LEN] {
    let index_bytes = index.to_be_bytes();
    let len_bytes = plaintext_chunk_len.to_be_bytes();
    let aad_hash = sha384(chunk_aad);
    hash_many(
        DOMAIN_MERKLE_LEAF,
        &[&index_bytes, &len_bytes, nonce, ciphertext, &aad_hash],
    )
}

/// Compute a ZP-1 Merkle root over a non-empty leaf list.
pub fn merkle_root(leaves: &[[u8; HASH_LEN]]) -> Option<[u8; HASH_LEN]> {
    if leaves.is_empty() {
        return None;
    }

    let original_leaf_count = u64::try_from(leaves.len()).ok()?;
    let mut level = leaves.to_vec();
    let mut level_index = 0u64;

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair_index in 0..level.len().div_ceil(2) {
            let left = level[2 * pair_index];
            let right = if 2 * pair_index + 1 < level.len() {
                level[2 * pair_index + 1]
            } else {
                left
            };
            let level_index_bytes = level_index.to_be_bytes();
            let pair_index_u64 = u64::try_from(pair_index).ok()?;
            let pair_index_bytes = pair_index_u64.to_be_bytes();
            let parent = hash_many(
                DOMAIN_MERKLE_NODE,
                &[&level_index_bytes, &pair_index_bytes, &left, &right],
            );
            next.push(parent);
        }
        level = next;
        level_index = level_index.checked_add(1)?;
    }

    let original_leaf_count_bytes = original_leaf_count.to_be_bytes();
    Some(hash_many(
        DOMAIN_MERKLE_ROOT,
        &[&original_leaf_count_bytes, &level[0]],
    ))
}
