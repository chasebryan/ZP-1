use zp1::constants::{
    AES_GCM_SIV_NONCE_LEN, DOMAIN_AAD, DOMAIN_BASE_HEADER, DOMAIN_CHUNK_AAD, DOMAIN_CHUNK_AEAD_KEY,
    DOMAIN_CONTENT_KEY_COMMITMENT, DOMAIN_CONTENT_SALT, DOMAIN_KDF, DOMAIN_KEY_COMMITMENT_KEY,
    DOMAIN_MANIFEST_MAC_KEY, DOMAIN_MANIFEST_TAG, DOMAIN_MERKLE_LEAF, DOMAIN_MERKLE_NODE,
    DOMAIN_MERKLE_ROOT, DOMAIN_PUBLIC_MANIFEST, DOMAIN_RECIPIENT_HEADER, DOMAIN_RECIPIENT_PK,
    DOMAIN_RECIPIENT_STANZAS, DOMAIN_RECIPIENT_WRAP_SALT, DOMAIN_SIGNATURE_BLOCK,
    DOMAIN_SIGNATURE_INPUT, DOMAIN_SIGNER_PK, DOMAIN_WRAP_KEY, HASH_LEN, KEY_COMMITMENT_LEN, MAGIC,
    MANIFEST_TAG_LEN, VERSION,
};
use zp1::hash::sha384;
use zp1::SuiteId;

#[test]
fn fixed_wire_values_do_not_drift() {
    assert_eq!(MAGIC, b"ZP1\0");
    assert_eq!(VERSION, 1);
    assert_eq!(SuiteId::Zp1Core.to_u16(), 0x0001);
    assert_eq!(SuiteId::Zp1Archive.to_u16(), 0x0002);

    assert_eq!(DOMAIN_AAD, b"ZP1 aad");
    assert_eq!(DOMAIN_SIGNER_PK, b"ZP1 signer-pk");
    assert_eq!(DOMAIN_RECIPIENT_PK, b"ZP1 recipient-pk");
    assert_eq!(DOMAIN_RECIPIENT_STANZAS, b"ZP1 recipient-stanzas");
    assert_eq!(DOMAIN_RECIPIENT_WRAP_SALT, b"ZP1 recipient wrap salt");
    assert_eq!(DOMAIN_WRAP_KEY, b"ZP1 wrap key");
    assert_eq!(DOMAIN_CONTENT_SALT, b"ZP1 content salt");
    assert_eq!(DOMAIN_CHUNK_AEAD_KEY, b"ZP1 chunk AEAD key");
    assert_eq!(DOMAIN_KEY_COMMITMENT_KEY, b"ZP1 key commitment key");
    assert_eq!(DOMAIN_MANIFEST_MAC_KEY, b"ZP1 manifest MAC key");
    assert_eq!(DOMAIN_CONTENT_KEY_COMMITMENT, b"ZP1 content key commitment");
    assert_eq!(DOMAIN_CHUNK_AAD, b"ZP1 chunk aad");
    assert_eq!(DOMAIN_MERKLE_LEAF, b"ZP1 merkle leaf");
    assert_eq!(DOMAIN_MERKLE_NODE, b"ZP1 merkle node");
    assert_eq!(DOMAIN_MERKLE_ROOT, b"ZP1 merkle root");
    assert_eq!(DOMAIN_MANIFEST_TAG, b"ZP1 manifest tag");
    assert_eq!(DOMAIN_SIGNATURE_INPUT, b"ZP1 signature input");
    assert_eq!(DOMAIN_KDF, b"ZP1-KDF-v1");
    assert_eq!(DOMAIN_BASE_HEADER, b"ZP1 base header");
    assert_eq!(DOMAIN_RECIPIENT_HEADER, b"ZP1 recipient header");
    assert_eq!(DOMAIN_PUBLIC_MANIFEST, b"ZP1 public manifest");
    assert_eq!(DOMAIN_SIGNATURE_BLOCK, b"ZP1 signature block");

    assert_eq!(MANIFEST_TAG_LEN, 48);
    assert_eq!(KEY_COMMITMENT_LEN, 48);
    assert_eq!(HASH_LEN, 48);
    assert_eq!(sha384(b"").len(), 48);
    assert_eq!(AES_GCM_SIV_NONCE_LEN, 12);
}
