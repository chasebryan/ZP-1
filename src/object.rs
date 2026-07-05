//! Strongly typed ZP-1 object model and canonical encoding.

use crate::codec::{
    put_domain, put_u16, put_u32, put_u64, put_u8, put_usize_as_u16, put_usize_as_u32, read_domain,
    Reader,
};
use crate::constants::{
    DOMAIN_BASE_HEADER, DOMAIN_CHUNK_AAD, DOMAIN_PUBLIC_MANIFEST, DOMAIN_RECIPIENT_HEADER,
    DOMAIN_SIGNATURE_BLOCK, HASH_LEN, MAGIC, MANIFEST_TAG_LEN, MAX_CHUNKS, MAX_KEM_CT_LEN,
    MAX_PUBLIC_KEY_LEN, MAX_RECIPIENTS, MAX_SIGNATURE_LEN, VERSION,
};
use crate::error::InternalParseError;

/// Supported ZP-1 suite IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteId {
    /// ZP-1 Core: ML-KEM-1024, ML-DSA-87, SHA-384, HMAC-SHA384, AES-256-GCM-SIV.
    Zp1Core,
    /// ZP-1 Archive: Core plus SLH-DSA level-5 co-signature.
    Zp1Archive,
}

impl SuiteId {
    /// Convert from the wire `u16` representation.
    pub fn from_u16(value: u16) -> Result<Self, InternalParseError> {
        match value {
            0x0001 => Ok(Self::Zp1Core),
            0x0002 => Ok(Self::Zp1Archive),
            _ => Err(InternalParseError),
        }
    }

    /// Convert to the wire `u16` representation.
    pub fn to_u16(self) -> u16 {
        match self {
            Self::Zp1Core => 0x0001,
            Self::Zp1Archive => 0x0002,
        }
    }
}

/// Base header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseHeader {
    pub suite_id: SuiteId,
    pub object_id: [u8; 16],
    pub chunk_size: u32,
    pub plaintext_length: u64,
    pub aad_hash: [u8; HASH_LEN],
    pub signer_pk_hash: [u8; HASH_LEN],
    pub flags: u32,
}

impl BaseHeader {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, DOMAIN_BASE_HEADER);
        put_u16(&mut out, self.suite_id.to_u16());
        out.extend_from_slice(&self.object_id);
        put_u32(&mut out, self.chunk_size);
        put_u64(&mut out, self.plaintext_length);
        out.extend_from_slice(&self.aad_hash);
        out.extend_from_slice(&self.signer_pk_hash);
        put_u32(&mut out, self.flags);
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        read_domain(&mut reader, DOMAIN_BASE_HEADER)?;
        let suite_id = SuiteId::from_u16(reader.read_u16()?)?;
        let object_id = reader.read_array::<16>()?;
        let chunk_size = reader.read_u32()?;
        let plaintext_length = reader.read_u64()?;
        let aad_hash = reader.read_array::<HASH_LEN>()?;
        let signer_pk_hash = reader.read_array::<HASH_LEN>()?;
        let flags = reader.read_u32()?;
        if flags != 0 {
            return Err(InternalParseError);
        }
        reader.finish()?;
        Ok(Self {
            suite_id,
            object_id,
            chunk_size,
            plaintext_length,
            aad_hash,
            signer_pk_hash,
            flags,
        })
    }
}

/// Recipient header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientHeader {
    pub recipient_index: u32,
    pub recipient_pk_hash: [u8; HASH_LEN],
    pub kem_ciphertext: Vec<u8>,
}

impl RecipientHeader {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, DOMAIN_RECIPIENT_HEADER);
        put_u32(&mut out, self.recipient_index);
        out.extend_from_slice(&self.recipient_pk_hash);
        put_usize_as_u32(&mut out, self.kem_ciphertext.len());
        out.extend_from_slice(&self.kem_ciphertext);
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        read_domain(&mut reader, DOMAIN_RECIPIENT_HEADER)?;
        let recipient_index = reader.read_u32()?;
        let recipient_pk_hash = reader.read_array::<HASH_LEN>()?;
        let kem_ciphertext = reader.read_vec_u32(MAX_KEM_CT_LEN)?;
        reader.finish()?;
        Ok(Self {
            recipient_index,
            recipient_pk_hash,
            kem_ciphertext,
        })
    }
}

/// Recipient stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStanza {
    pub recipient_header: RecipientHeader,
    pub wrapped_content_secret: Vec<u8>,
}

impl RecipientStanza {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let recipient_header = self.recipient_header.encode();
        let mut out = Vec::new();
        put_usize_as_u32(&mut out, recipient_header.len());
        out.extend_from_slice(&recipient_header);
        put_usize_as_u32(&mut out, self.wrapped_content_secret.len());
        out.extend_from_slice(&self.wrapped_content_secret);
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        let header_len = usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
        if header_len > reader.remaining() {
            return Err(InternalParseError);
        }
        let recipient_header = RecipientHeader::decode(reader.read_exact(header_len)?)?;
        let wrapped_len = usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
        if wrapped_len > reader.remaining() {
            return Err(InternalParseError);
        }
        let wrapped_content_secret = reader.read_exact(wrapped_len)?.to_vec();
        reader.finish()?;
        Ok(Self {
            recipient_header,
            wrapped_content_secret,
        })
    }
}

/// Public manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicManifest {
    pub base_header_hash: [u8; HASH_LEN],
    pub stanzas_hash: [u8; HASH_LEN],
    pub key_commitment: [u8; HASH_LEN],
    pub chunk_count: u64,
    pub chunk_size: u32,
    pub plaintext_length: u64,
    pub merkle_root: [u8; HASH_LEN],
    pub aad_hash: [u8; HASH_LEN],
    pub signer_pk_hash: [u8; HASH_LEN],
}

impl PublicManifest {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, DOMAIN_PUBLIC_MANIFEST);
        out.extend_from_slice(&self.base_header_hash);
        out.extend_from_slice(&self.stanzas_hash);
        out.extend_from_slice(&self.key_commitment);
        put_u64(&mut out, self.chunk_count);
        put_u32(&mut out, self.chunk_size);
        put_u64(&mut out, self.plaintext_length);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.aad_hash);
        out.extend_from_slice(&self.signer_pk_hash);
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        read_domain(&mut reader, DOMAIN_PUBLIC_MANIFEST)?;
        let base_header_hash = reader.read_array::<HASH_LEN>()?;
        let stanzas_hash = reader.read_array::<HASH_LEN>()?;
        let key_commitment = reader.read_array::<HASH_LEN>()?;
        let chunk_count = reader.read_u64()?;
        let chunk_size = reader.read_u32()?;
        let plaintext_length = reader.read_u64()?;
        let merkle_root = reader.read_array::<HASH_LEN>()?;
        let aad_hash = reader.read_array::<HASH_LEN>()?;
        let signer_pk_hash = reader.read_array::<HASH_LEN>()?;
        reader.finish()?;
        Ok(Self {
            base_header_hash,
            stanzas_hash,
            key_commitment,
            chunk_count,
            chunk_size,
            plaintext_length,
            merkle_root,
            aad_hash,
            signer_pk_hash,
        })
    }
}

/// Optional archive signature fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSignature {
    pub archive_public_key: Vec<u8>,
    pub slhdsa_signature: Vec<u8>,
}

/// Signature block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBlock {
    pub signer_public_key: Vec<u8>,
    pub mldsa_signature: Vec<u8>,
    pub archive: Option<ArchiveSignature>,
}

impl SignatureBlock {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, DOMAIN_SIGNATURE_BLOCK);
        put_usize_as_u32(&mut out, self.signer_public_key.len());
        out.extend_from_slice(&self.signer_public_key);
        put_usize_as_u32(&mut out, self.mldsa_signature.len());
        out.extend_from_slice(&self.mldsa_signature);
        if let Some(archive) = &self.archive {
            put_u8(&mut out, 1);
            put_usize_as_u32(&mut out, archive.archive_public_key.len());
            out.extend_from_slice(&archive.archive_public_key);
            put_usize_as_u32(&mut out, archive.slhdsa_signature.len());
            out.extend_from_slice(&archive.slhdsa_signature);
        } else {
            put_u8(&mut out, 0);
        }
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        read_domain(&mut reader, DOMAIN_SIGNATURE_BLOCK)?;
        let signer_public_key = reader.read_vec_u32(MAX_PUBLIC_KEY_LEN)?;
        let mldsa_signature = reader.read_vec_u32(MAX_SIGNATURE_LEN)?;
        let archive_present = reader.read_u8()?;
        let archive = match archive_present {
            0 => None,
            1 => {
                let archive_public_key = reader.read_vec_u32(MAX_PUBLIC_KEY_LEN)?;
                let slhdsa_signature = reader.read_vec_u32(MAX_SIGNATURE_LEN)?;
                Some(ArchiveSignature {
                    archive_public_key,
                    slhdsa_signature,
                })
            }
            _ => return Err(InternalParseError),
        };
        reader.finish()?;
        Ok(Self {
            signer_public_key,
            mldsa_signature,
            archive,
        })
    }
}

/// Complete ZP-1 object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zp1Object {
    pub suite_id: SuiteId,
    pub base_header: BaseHeader,
    pub recipient_stanzas: Vec<RecipientStanza>,
    pub public_manifest: PublicManifest,
    pub chunks: Vec<Vec<u8>>,
    pub manifest_tag: [u8; MANIFEST_TAG_LEN],
    pub signature_block: SignatureBlock,
}

impl Zp1Object {
    /// Encode canonically.
    pub fn encode(&self) -> Vec<u8> {
        let base_header = self.base_header.encode();
        let public_manifest = self.public_manifest.encode();
        let signature_block = self.signature_block.encode();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, VERSION);
        put_u16(&mut out, self.suite_id.to_u16());
        put_usize_as_u32(&mut out, base_header.len());
        out.extend_from_slice(&base_header);
        put_usize_as_u16(&mut out, self.recipient_stanzas.len());
        for stanza in &self.recipient_stanzas {
            let encoded = stanza.encode();
            put_usize_as_u32(&mut out, encoded.len());
            out.extend_from_slice(&encoded);
        }
        put_usize_as_u32(&mut out, public_manifest.len());
        out.extend_from_slice(&public_manifest);
        let chunk_count = u64::try_from(self.chunks.len()).unwrap_or(u64::MAX);
        put_u64(&mut out, chunk_count);
        for chunk in &self.chunks {
            put_usize_as_u32(&mut out, chunk.len());
            out.extend_from_slice(chunk);
        }
        put_usize_as_u16(&mut out, self.manifest_tag.len());
        out.extend_from_slice(&self.manifest_tag);
        put_usize_as_u32(&mut out, signature_block.len());
        out.extend_from_slice(&signature_block);
        out
    }

    /// Decode canonically.
    pub fn decode(input: &[u8]) -> Result<Self, InternalParseError> {
        let mut reader = Reader::new(input);
        if reader.read_exact(4)? != MAGIC {
            return Err(InternalParseError);
        }
        if reader.read_u16()? != VERSION {
            return Err(InternalParseError);
        }
        let suite_id = SuiteId::from_u16(reader.read_u16()?)?;
        let base_header_len =
            usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
        if base_header_len > reader.remaining() {
            return Err(InternalParseError);
        }
        let base_header = BaseHeader::decode(reader.read_exact(base_header_len)?)?;
        if base_header.suite_id != suite_id {
            return Err(InternalParseError);
        }

        let recipient_count = usize::from(reader.read_u16()?);
        if recipient_count == 0 || recipient_count > MAX_RECIPIENTS {
            return Err(InternalParseError);
        }
        let mut recipient_stanzas = Vec::with_capacity(recipient_count);
        for expected_index in 0..recipient_count {
            let stanza_len = usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
            if stanza_len > reader.remaining() {
                return Err(InternalParseError);
            }
            let stanza = RecipientStanza::decode(reader.read_exact(stanza_len)?)?;
            let expected_index = u32::try_from(expected_index).map_err(|_| InternalParseError)?;
            if stanza.recipient_header.recipient_index != expected_index {
                return Err(InternalParseError);
            }
            recipient_stanzas.push(stanza);
        }

        let public_manifest_len =
            usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
        if public_manifest_len > reader.remaining() {
            return Err(InternalParseError);
        }
        let public_manifest = PublicManifest::decode(reader.read_exact(public_manifest_len)?)?;

        let chunk_count = reader.read_u64()?;
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(InternalParseError);
        }
        let min_chunk_prefix_bytes = chunk_count.checked_mul(4).ok_or(InternalParseError)?;
        let remaining = u64::try_from(reader.remaining()).map_err(|_| InternalParseError)?;
        if min_chunk_prefix_bytes > remaining {
            return Err(InternalParseError);
        }
        let chunk_count_usize = usize::try_from(chunk_count).map_err(|_| InternalParseError)?;
        let mut chunks = Vec::with_capacity(chunk_count_usize);
        for _ in 0..chunk_count_usize {
            let chunk_len = usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
            if chunk_len > reader.remaining() {
                return Err(InternalParseError);
            }
            chunks.push(reader.read_exact(chunk_len)?.to_vec());
        }

        let manifest_tag_len = usize::from(reader.read_u16()?);
        if manifest_tag_len != MANIFEST_TAG_LEN {
            return Err(InternalParseError);
        }
        let manifest_tag = reader.read_array::<MANIFEST_TAG_LEN>()?;

        let signature_block_len =
            usize::try_from(reader.read_u32()?).map_err(|_| InternalParseError)?;
        if signature_block_len > reader.remaining() {
            return Err(InternalParseError);
        }
        let signature_block = SignatureBlock::decode(reader.read_exact(signature_block_len)?)?;
        reader.finish()?;

        Ok(Self {
            suite_id,
            base_header,
            recipient_stanzas,
            public_manifest,
            chunks,
            manifest_tag,
            signature_block,
        })
    }
}

pub(crate) struct ChunkAadInput<'a> {
    pub base_header_hash: &'a [u8; HASH_LEN],
    pub stanzas_hash: &'a [u8; HASH_LEN],
    pub key_commitment: &'a [u8; HASH_LEN],
    pub aad_hash: &'a [u8; HASH_LEN],
    pub index: u64,
    pub chunk_count: u64,
    pub plaintext_length: u64,
    pub chunk_length: u64,
}

pub(crate) fn encode_chunk_aad(input: ChunkAadInput<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    put_domain(&mut out, DOMAIN_CHUNK_AAD);
    out.extend_from_slice(input.base_header_hash);
    out.extend_from_slice(input.stanzas_hash);
    out.extend_from_slice(input.key_commitment);
    out.extend_from_slice(input.aad_hash);
    put_u64(&mut out, input.index);
    put_u64(&mut out, input.chunk_count);
    put_u64(&mut out, input.plaintext_length);
    put_u64(&mut out, input.chunk_length);
    out
}
