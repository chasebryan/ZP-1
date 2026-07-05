mod common;

use common::{archive_present_offset, decoded, locate_object_parts, sealed_fixture};
use zp1::constants::{MAX_CHUNKS, MAX_RECIPIENTS};
use zp1::object::Zp1Object;

fn valid_object() -> Vec<u8> {
    let (_, object) = sealed_fixture(b"canonical", 1, 16, b"aad", b"canonical plaintext");
    object
}

#[test]
fn decode_rejects_trailing_bytes() {
    let mut object = valid_object();
    object.push(0);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn decode_rejects_zero_recipients() {
    let object = valid_object();
    let mut decoded = decoded(&object);
    decoded.recipient_stanzas.clear();
    assert!(Zp1Object::decode(&decoded.encode()).is_err());
}

#[test]
fn decode_rejects_zero_chunks() {
    let object = valid_object();
    let mut decoded = decoded(&object);
    decoded.chunks.clear();
    assert!(Zp1Object::decode(&decoded.encode()).is_err());
}

#[test]
fn decode_rejects_unknown_suite() {
    let mut object = valid_object();
    object[6] = 0xff;
    object[7] = 0xff;
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn decode_rejects_unknown_flags() {
    let object = valid_object();
    let mut decoded = decoded(&object);
    decoded.base_header.flags = 1;
    assert!(Zp1Object::decode(&decoded.encode()).is_err());
}

#[test]
fn decode_rejects_bad_manifest_tag_len() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    object[parts.manifest_tag_len_offset] = 0;
    object[parts.manifest_tag_len_offset + 1] = 47;
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn decode_rejects_bad_archive_present_value() {
    let mut object = valid_object();
    let offset = archive_present_offset(&object);
    object[offset] = 2;
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn decode_rejects_length_overflow() {
    let mut object = valid_object();
    object[8] = 0xff;
    object[9] = 0xff;
    object[10] = 0xff;
    object[11] = 0xff;
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn length_prefix_larger_than_remaining_input_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.chunk_len_offsets[0], u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn base_header_len_overflow_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.base_header_len_offset, u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn recipient_stanza_len_overflow_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.recipient_stanza_len_offsets[0], u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn public_manifest_len_overflow_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.public_manifest_len_offset, u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn chunk_len_overflow_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.chunk_len_offsets[0], u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn signature_block_len_overflow_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.signature_block_len_offset, u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn huge_recipient_count_rejected_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u16(&mut object, parts.recipient_count_offset, u16::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn huge_chunk_count_rejected_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u64(&mut object, parts.chunk_count_offset, u64::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn manifest_tag_len_must_be_48() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u16(&mut object, parts.manifest_tag_len_offset, 49);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn top_level_base_header_len_exactly_remaining_plus_one_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    let remaining_after_prefix = object.len() - (parts.base_header_len_offset + 4);
    put_u32(
        &mut object,
        parts.base_header_len_offset,
        u32::try_from(remaining_after_prefix + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn recipient_stanza_len_exactly_remaining_plus_one_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    let offset = parts.recipient_stanza_len_offsets[0];
    let remaining_after_prefix = object.len() - (offset + 4);
    put_u32(
        &mut object,
        offset,
        u32::try_from(remaining_after_prefix + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn public_manifest_len_exactly_remaining_plus_one_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    let remaining_after_prefix = object.len() - (parts.public_manifest_len_offset + 4);
    put_u32(
        &mut object,
        parts.public_manifest_len_offset,
        u32::try_from(remaining_after_prefix + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn chunk_len_exactly_remaining_plus_one_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    let offset = parts.chunk_len_offsets[0];
    let remaining_after_prefix = object.len() - (offset + 4);
    put_u32(
        &mut object,
        offset,
        u32::try_from(remaining_after_prefix + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn signature_block_len_exactly_remaining_plus_one_fails() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    let remaining_after_prefix = object.len() - (parts.signature_block_len_offset + 4);
    put_u32(
        &mut object,
        parts.signature_block_len_offset,
        u32::try_from(remaining_after_prefix + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn u32_max_length_prefix_fails_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u32(&mut object, parts.public_manifest_len_offset, u32::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn u64_max_chunk_count_fails_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u64(&mut object, parts.chunk_count_offset, u64::MAX);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn recipient_count_max_plus_one_fails_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u16(
        &mut object,
        parts.recipient_count_offset,
        u16::try_from(MAX_RECIPIENTS + 1).unwrap(),
    );
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn chunk_count_max_plus_one_fails_before_allocation() {
    let mut object = valid_object();
    let parts = locate_object_parts(&object);
    put_u64(&mut object, parts.chunk_count_offset, MAX_CHUNKS + 1);
    assert!(Zp1Object::decode(&object).is_err());
}

#[test]
fn encode_decode_encode_is_stable() {
    let object = valid_object();
    let decoded = Zp1Object::decode(&object).unwrap();
    assert_eq!(decoded.encode(), object);
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
