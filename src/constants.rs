//! Protocol constants and domain labels.

pub const MAGIC: &[u8; 4] = b"ZP1\0";
pub const VERSION: u16 = 1;

pub const HASH_LEN: usize = 48;
pub const CONTENT_SECRET_LEN: usize = 48;
pub const OBJECT_ID_LEN: usize = 16;
pub const AEAD_KEY_LEN: usize = 32;
pub const AES_GCM_SIV_NONCE_LEN: usize = 12;
pub const MANIFEST_TAG_LEN: usize = 48;
pub const KEY_COMMITMENT_LEN: usize = 48;

pub const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;
pub const MIN_CHUNK_SIZE: u32 = 1;
pub const MAX_CHUNK_SIZE: u32 = 16_777_216;

pub const MAX_RECIPIENTS: usize = 1024;
pub const MAX_CHUNKS: u64 = 4_294_967_295;
pub const MAX_PLAINTEXT_LEN: u64 = 17_592_186_040_320;
pub const MAX_AAD_LEN: u64 = 1_073_741_824;
pub const MAX_KEM_CT_LEN: usize = 16_384;
pub const MAX_SIGNATURE_LEN: usize = 65_536;
pub const MAX_PUBLIC_KEY_LEN: usize = 65_536;
pub const MAX_OBJECT_LEN: u64 = u64::MAX;

pub const DOMAIN_AAD: &[u8] = b"ZP1 aad";
pub const DOMAIN_SIGNER_PK: &[u8] = b"ZP1 signer-pk";
pub const DOMAIN_RECIPIENT_PK: &[u8] = b"ZP1 recipient-pk";
pub const DOMAIN_RECIPIENT_STANZAS: &[u8] = b"ZP1 recipient-stanzas";
pub const DOMAIN_RECIPIENT_WRAP_SALT: &[u8] = b"ZP1 recipient wrap salt";
pub const DOMAIN_WRAP_KEY: &[u8] = b"ZP1 wrap key";
pub const DOMAIN_CONTENT_SALT: &[u8] = b"ZP1 content salt";
pub const DOMAIN_CHUNK_AEAD_KEY: &[u8] = b"ZP1 chunk AEAD key";
pub const DOMAIN_KEY_COMMITMENT_KEY: &[u8] = b"ZP1 key commitment key";
pub const DOMAIN_MANIFEST_MAC_KEY: &[u8] = b"ZP1 manifest MAC key";
pub const DOMAIN_CONTENT_KEY_COMMITMENT: &[u8] = b"ZP1 content key commitment";
pub const DOMAIN_CHUNK_AAD: &[u8] = b"ZP1 chunk aad";
pub const DOMAIN_MERKLE_LEAF: &[u8] = b"ZP1 merkle leaf";
pub const DOMAIN_MERKLE_NODE: &[u8] = b"ZP1 merkle node";
pub const DOMAIN_MERKLE_ROOT: &[u8] = b"ZP1 merkle root";
pub const DOMAIN_MANIFEST_TAG: &[u8] = b"ZP1 manifest tag";
pub const DOMAIN_SIGNATURE_INPUT: &[u8] = b"ZP1 signature input";
pub const DOMAIN_KDF: &[u8] = b"ZP1-KDF-v1";

pub const DOMAIN_BASE_HEADER: &[u8] = b"ZP1 base header";
pub const DOMAIN_RECIPIENT_HEADER: &[u8] = b"ZP1 recipient header";
pub const DOMAIN_PUBLIC_MANIFEST: &[u8] = b"ZP1 public manifest";
pub const DOMAIN_SIGNATURE_BLOCK: &[u8] = b"ZP1 signature block";

pub const AES_GCM_SIV_TAG_LEN: u64 = 16;
