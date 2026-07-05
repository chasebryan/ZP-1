mod common;

use common::{fixture, open_ok, sealed_fixture};
use zp1::open::{open, OpenOptions};
use zp1::seal::{seal, SealOptions};
use zp1::{SuiteId, Zp1Error};

#[test]
fn roundtrip_empty_plaintext_empty_aad() {
    let (mut fx, object) = sealed_fixture(b"rt-empty", 1, 8, b"", b"");
    assert_eq!(open_ok(&mut fx, 0, b"", &object), b"");
}

#[test]
fn roundtrip_small_plaintext() {
    let plaintext = b"hello zp1";
    let aad = b"metadata";
    let (mut fx, object) = sealed_fixture(b"rt-small", 1, 64, aad, plaintext);
    assert_eq!(open_ok(&mut fx, 0, aad, &object), plaintext);
}

#[test]
fn roundtrip_exactly_one_chunk() {
    let plaintext = vec![7u8; 32];
    let aad = b"one chunk";
    let (mut fx, object) = sealed_fixture(b"rt-one", 1, 32, aad, &plaintext);
    assert_eq!(open_ok(&mut fx, 0, aad, &object), plaintext);
}

#[test]
fn roundtrip_two_chunks() {
    let plaintext = vec![9u8; 33];
    let aad = b"two chunks";
    let (mut fx, object) = sealed_fixture(b"rt-two", 1, 32, aad, &plaintext);
    assert_eq!(open_ok(&mut fx, 0, aad, &object), plaintext);
}

#[test]
fn roundtrip_three_chunks() {
    let plaintext = vec![11u8; 65];
    let aad = b"three chunks";
    let (mut fx, object) = sealed_fixture(b"rt-three", 1, 32, aad, &plaintext);
    assert_eq!(open_ok(&mut fx, 0, aad, &object), plaintext);
}

#[test]
fn roundtrip_multiple_recipients_recipient_0() {
    let plaintext = b"recipient zero";
    let aad = b"multi";
    let (mut fx, object) = sealed_fixture(b"rt-multi-0", 2, 16, aad, plaintext);
    assert_eq!(open_ok(&mut fx, 0, aad, &object), plaintext);
}

#[test]
fn roundtrip_multiple_recipients_recipient_1() {
    let plaintext = b"recipient one";
    let aad = b"multi";
    let (mut fx, object) = sealed_fixture(b"rt-multi-1", 2, 16, aad, plaintext);
    assert_eq!(open_ok(&mut fx, 1, aad, &object), plaintext);
}

#[test]
fn wrong_recipient_fails() {
    let aad = b"aad";
    let plaintext = b"wrong recipient";
    let (mut fx, object) = sealed_fixture(b"rt-wrong-recipient", 1, 32, aad, plaintext);
    let (_, wrong_sk) = fx.provider.generate_kem_keypair(b"wrong-recipient");
    let err = open(
        &mut fx.provider,
        &wrong_sk,
        &fx.signer_pk,
        aad,
        &object,
        OpenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::Auth);
}

#[test]
fn wrong_signer_fails() {
    let aad = b"aad";
    let plaintext = b"wrong signer";
    let (mut fx, object) = sealed_fixture(b"rt-wrong-signer", 1, 32, aad, plaintext);
    let (wrong_pk, _) = fx.provider.generate_signature_keypair(b"wrong-signer");
    let err = open(
        &mut fx.provider,
        &fx.recipient_sks[0],
        &wrong_pk,
        aad,
        &object,
        OpenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::Auth);
}

#[test]
fn archive_suite_is_not_sealed_in_v01() {
    let mut fx = fixture(b"archive", 1);
    let err = seal(
        &mut fx.provider,
        &fx.recipient_pks,
        &fx.signer_sk,
        &fx.signer_pk,
        b"",
        b"",
        SealOptions {
            chunk_size: 1,
            suite_id: SuiteId::Zp1Archive,
        },
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::UnsupportedSuite);
}
