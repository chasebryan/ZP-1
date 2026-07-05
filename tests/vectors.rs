mod common;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use common::InsecureTestProvider;
use hmac::{Hmac, Mac};
use sha2::Sha384;
use subtle::ConstantTimeEq;
use zp1::constants::{
    DOMAIN_CHUNK_AAD, DOMAIN_CONTENT_KEY_COMMITMENT, DOMAIN_CONTENT_SALT,
    DOMAIN_KEY_COMMITMENT_KEY, DOMAIN_MANIFEST_MAC_KEY, DOMAIN_MANIFEST_TAG,
    DOMAIN_RECIPIENT_STANZAS, DOMAIN_RECIPIENT_WRAP_SALT, DOMAIN_SIGNATURE_INPUT, DOMAIN_WRAP_KEY,
};
use zp1::hash::{hash_many, sha384};
use zp1::kdf::{expand, extract};
use zp1::merkle::{merkle_leaf, merkle_root};
use zp1::object::Zp1Object;
use zp1::open::{open, OpenOptions};
use zp1::provider::KemProvider;
use zp1::SuiteId;

const VECTOR_JSON: &str = include_str!("../test-vectors/zp1-core-insecure-test-provider-v0.json");

#[test]
fn zp1_core_insecure_test_provider_vector_verifies() {
    let vector = Vector::parse(VECTOR_JSON);
    assert_eq!(
        vector.warning,
        "NOT CRYPTOGRAPHICALLY SECURE. TEST VECTOR FOR WIRE FORMAT AND TRANSCRIPT STABILITY ONLY."
    );
    assert_eq!(vector.suite_id, "Zp1Core");
    assert_eq!(vector.chunk_size, 16);

    let seed = hex_decode(&vector.provider_seed_hex);
    let recipient_label = hex_decode(&vector.recipient_label_hex);
    let signer_label = hex_decode(&vector.signer_label_hex);
    let aad = hex_decode(&vector.aad_hex);
    let plaintext = hex_decode(&vector.plaintext_hex);
    let sealed_object = hex_decode(&vector.sealed_object_hex);

    let mut provider = InsecureTestProvider::new(&seed);
    let (recipient_pk, recipient_sk) = provider.generate_kem_keypair(&recipient_label);
    let (signer_pk, _) = provider.generate_signature_keypair(&signer_label);

    assert_eq!(
        hex_encode(recipient_pk.as_ref()),
        vector.recipient_public_key_hex
    );
    assert_eq!(hex_encode(signer_pk.as_ref()), vector.signer_public_key_hex);

    let opened = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &aad,
        &sealed_object,
        OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(opened, plaintext);

    let object = Zp1Object::decode(&sealed_object).unwrap();
    assert_eq!(object.suite_id, SuiteId::Zp1Core);
    assert_eq!(object.encode(), sealed_object);

    let inspection = inspect_vector_object(&mut provider, &recipient_sk, &object);
    assert_eq!(
        hex_encode(&inspection.base_header_hash),
        vector.base_header_hash_hex
    );
    assert_eq!(
        hex_encode(&inspection.stanzas_hash),
        vector.stanzas_hash_hex
    );
    assert_eq!(
        hex_encode(&inspection.key_commitment),
        vector.key_commitment_hex
    );
    assert_eq!(hex_encode(&inspection.merkle_root), vector.merkle_root_hex);
    assert_eq!(
        hex_encode(&inspection.manifest_tag),
        vector.manifest_tag_hex
    );
    assert_eq!(
        hex_encode(&inspection.signature_input_hash),
        vector.signature_input_hash_hex
    );

    assert!(bool::from(
        inspection
            .key_commitment
            .ct_eq(&object.public_manifest.key_commitment)
    ));
    assert!(bool::from(
        inspection.manifest_tag.ct_eq(&object.manifest_tag)
    ));

    assert_eq!(vector.chunk_size, 16);
}

struct Vector {
    warning: String,
    suite_id: String,
    chunk_size: u32,
    provider_seed_hex: String,
    recipient_label_hex: String,
    signer_label_hex: String,
    plaintext_hex: String,
    aad_hex: String,
    signer_public_key_hex: String,
    recipient_public_key_hex: String,
    sealed_object_hex: String,
    base_header_hash_hex: String,
    stanzas_hash_hex: String,
    key_commitment_hex: String,
    merkle_root_hex: String,
    manifest_tag_hex: String,
    signature_input_hash_hex: String,
}

impl Vector {
    fn parse(input: &str) -> Self {
        Self {
            warning: json_string(input, "warning"),
            suite_id: json_string(input, "suite_id"),
            chunk_size: json_u32(input, "chunk_size"),
            provider_seed_hex: json_string(input, "provider_seed_hex"),
            recipient_label_hex: json_string(input, "recipient_label_hex"),
            signer_label_hex: json_string(input, "signer_label_hex"),
            plaintext_hex: json_string(input, "plaintext_hex"),
            aad_hex: json_string(input, "aad_hex"),
            signer_public_key_hex: json_string(input, "signer_public_key_hex"),
            recipient_public_key_hex: json_string(input, "recipient_public_key_hex"),
            sealed_object_hex: json_string(input, "sealed_object_hex"),
            base_header_hash_hex: json_string(input, "base_header_hash_hex"),
            stanzas_hash_hex: json_string(input, "stanzas_hash_hex"),
            key_commitment_hex: json_string(input, "key_commitment_hex"),
            merkle_root_hex: json_string(input, "merkle_root_hex"),
            manifest_tag_hex: json_string(input, "manifest_tag_hex"),
            signature_input_hash_hex: json_string(input, "signature_input_hash_hex"),
        }
    }
}

struct Inspection {
    base_header_hash: [u8; 48],
    stanzas_hash: [u8; 48],
    key_commitment: [u8; 48],
    merkle_root: [u8; 48],
    manifest_tag: [u8; 48],
    signature_input_hash: [u8; 48],
}

fn inspect_vector_object(
    provider: &mut InsecureTestProvider,
    recipient_sk: &<InsecureTestProvider as KemProvider>::KemSecretKey,
    object: &Zp1Object,
) -> Inspection {
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

    let stanza = &object.recipient_stanzas[0];
    let recipient_header_bytes = stanza.recipient_header.encode();
    let ss = provider
        .decapsulate(recipient_sk, &stanza.recipient_header.kem_ciphertext)
        .unwrap();
    let wrap_salt = hash_many(
        DOMAIN_RECIPIENT_WRAP_SALT,
        &[&base_header_bytes, &recipient_header_bytes],
    );
    let prk_wrap = extract(&wrap_salt, ss.as_slice()).unwrap();
    let wrap_context = encode_context(&[&base_header_bytes, &recipient_header_bytes]);
    let k_wrap = expand(&prk_wrap, DOMAIN_WRAP_KEY, &wrap_context, 32).unwrap();
    let mut wrap_aad = Vec::new();
    wrap_aad.extend_from_slice(&base_header_bytes);
    wrap_aad.extend_from_slice(&recipient_header_bytes);
    let content_secret = aes_gcm_siv_open(
        k_wrap.as_slice(),
        &[0u8; 12],
        &wrap_aad,
        &stanza.wrapped_content_secret,
    );

    let content_salt = hash_many(
        DOMAIN_CONTENT_SALT,
        &[
            &base_header_bytes,
            &stanzas_hash,
            &object.public_manifest.aad_hash,
        ],
    );
    let prk_content = extract(&content_salt, &content_secret).unwrap();
    let content_context = encode_context(&[&base_header_bytes, &stanzas_hash]);
    let k_commit = expand(
        &prk_content,
        DOMAIN_KEY_COMMITMENT_KEY,
        &content_context,
        32,
    )
    .unwrap();
    let k_manifest = expand(&prk_content, DOMAIN_MANIFEST_MAC_KEY, &content_context, 32).unwrap();

    let key_commitment_data = hash_many_input(
        DOMAIN_CONTENT_KEY_COMMITMENT,
        &[
            &base_header_bytes,
            &stanzas_hash,
            &object.public_manifest.aad_hash,
        ],
    );
    let key_commitment = hmac_sha384(k_commit.as_slice(), &key_commitment_data);

    let mut leaves = Vec::new();
    for (index, ciphertext) in object.chunks.iter().enumerate() {
        let index = u64::try_from(index).unwrap();
        let chunk_len = expected_plaintext_chunk_len(
            index,
            object.public_manifest.chunk_count,
            object.public_manifest.chunk_size,
            object.public_manifest.plaintext_length,
        );
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
    let merkle_root = merkle_root(&leaves).unwrap();

    let public_manifest_bytes = object.public_manifest.encode();
    let manifest_tag_data = hash_many_input(DOMAIN_MANIFEST_TAG, &[&public_manifest_bytes]);
    let manifest_tag = hmac_sha384(k_manifest.as_slice(), &manifest_tag_data);

    let mut sig_parts = Vec::new();
    sig_parts.push(base_header_bytes.as_slice());
    for stanza in &recipient_stanza_bytes {
        sig_parts.push(stanza.as_slice());
    }
    sig_parts.push(public_manifest_bytes.as_slice());
    sig_parts.push(object.manifest_tag.as_slice());
    let signature_input_hash = hash_many(DOMAIN_SIGNATURE_INPUT, &sig_parts);

    Inspection {
        base_header_hash,
        stanzas_hash,
        key_commitment,
        merkle_root,
        manifest_tag,
        signature_input_hash,
    }
}

fn encode_context(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&u64::try_from(part.len()).unwrap().to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn hash_many_input(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&u16::try_from(domain.len()).unwrap().to_be_bytes());
    input.extend_from_slice(domain);
    for part in parts {
        input.extend_from_slice(&u64::try_from(part.len()).unwrap().to_be_bytes());
        input.extend_from_slice(part);
    }
    input
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    out
}

fn aes_gcm_siv_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .unwrap()
}

fn chunk_nonce(index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

struct ChunkAadParts<'a> {
    base_header_hash: &'a [u8; 48],
    stanzas_hash: &'a [u8; 48],
    key_commitment: &'a [u8; 48],
    aad_hash: &'a [u8; 48],
    index: u64,
    chunk_count: u64,
    plaintext_length: u64,
    chunk_length: u64,
}

fn encode_chunk_aad(parts: ChunkAadParts<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16::try_from(DOMAIN_CHUNK_AAD.len()).unwrap().to_be_bytes());
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
) -> u64 {
    if plaintext_length == 0 {
        return 0;
    }
    if index + 1 < chunk_count {
        u64::from(chunk_size)
    } else {
        plaintext_length - u64::from(chunk_size) * (chunk_count - 1)
    }
}

fn json_string(input: &str, key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let start = input.find(&needle).unwrap() + needle.len();
    let rest = &input[start..];
    let end = rest.find('"').unwrap();
    rest[..end].to_string()
}

fn json_u32(input: &str, key: &str) -> u32 {
    let needle = format!("\"{key}\": ");
    let start = input.find(&needle).unwrap() + needle.len();
    let rest = &input[start..];
    let end = rest
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().unwrap()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte"),
    }
}
