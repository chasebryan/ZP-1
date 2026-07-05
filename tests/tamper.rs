mod common;

use common::{assert_auth, decoded, locate_object_parts, sealed_fixture};

const AAD: &[u8] = b"tamper aad";
const PLAINTEXT: &[u8] = b"tamper tests need enough bytes for multiple chunks";

fn valid_object() -> (common::Fixture, Vec<u8>) {
    sealed_fixture(b"tamper", 1, 16, AAD, PLAINTEXT)
}

fn assert_tampered_auth(mut object: Vec<u8>) {
    let (mut fx, _) = valid_object();
    assert_auth(
        &mut fx.provider,
        &fx.recipient_sks[0],
        &fx.signer_pk,
        AAD,
        &object,
    );
    object.fill(0);
}

#[test]
fn tamper_magic_fails() {
    let (_, mut object) = valid_object();
    object[0] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_version_fails() {
    let (_, mut object) = valid_object();
    object[5] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_base_header_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.base_header_start + 8] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_recipient_stanza_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.recipient_stanzas[0]
        .recipient_header
        .recipient_pk_hash[0] ^= 1;
    assert_tampered_auth(decoded.encode());
}

#[test]
fn tamper_wrapped_content_secret_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.recipient_stanzas[0].wrapped_content_secret[0] ^= 1;
    assert_tampered_auth(decoded.encode());
}

#[test]
fn tamper_manifest_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.public_manifest_start + 10] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_manifest_tag_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.manifest_tag_start] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_signature_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    let last = object.len() - 1;
    assert!(parts.signature_block_start < last);
    object[last] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn tamper_chunk_ciphertext_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.chunk_starts[0]] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn reorder_chunks_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.chunks.swap(0, 1);
    assert_tampered_auth(decoded.encode());
}

#[test]
fn drop_chunk_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.chunks.pop();
    assert_tampered_auth(decoded.encode());
}

#[test]
fn append_trailing_byte_fails() {
    let (_, mut object) = valid_object();
    object.push(0);
    assert_tampered_auth(object);
}

#[test]
fn wrong_aad_fails() {
    let (mut fx, object) = valid_object();
    assert_auth(
        &mut fx.provider,
        &fx.recipient_sks[0],
        &fx.signer_pk,
        b"wrong aad",
        &object,
    );
}

#[test]
fn modified_chunk_count_fails() {
    let (_, mut object) = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.chunk_count_offset + 7] ^= 1;
    assert_tampered_auth(object);
}

#[test]
fn modified_plaintext_length_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.public_manifest.plaintext_length += 1;
    assert_tampered_auth(decoded.encode());
}

#[test]
fn modified_chunk_size_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.base_header.chunk_size += 1;
    assert_tampered_auth(decoded.encode());
}

#[test]
fn modified_key_commitment_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.public_manifest.key_commitment[0] ^= 1;
    assert_tampered_auth(decoded.encode());
}

#[test]
fn modified_merkle_root_fails() {
    let (_, object) = valid_object();
    let mut decoded = decoded(&object);
    decoded.public_manifest.merkle_root[0] ^= 1;
    assert_tampered_auth(decoded.encode());
}
