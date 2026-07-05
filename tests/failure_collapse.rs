#![cfg(feature = "test-utils")]

mod common;

use common::{positive_vector, vector_provider_and_keys};
use zp1::object::Zp1Object;
use zp1::open::{open, OpenOptions};
use zp1::test_support::{archive_present_offset, object_spans};
use zp1::Zp1Error;

#[test]
fn malformed_and_tampered_open_inputs_collapse_to_auth() {
    let vector = positive_vector();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);
    let aad = vector.aad();
    let object = vector.sealed_object();
    let spans = object_spans(&object).unwrap();

    let mut cases: Vec<(&str, Vec<u8>, Vec<u8>)> = Vec::new();
    cases.push((
        "parse failure",
        {
            let mut bytes = object.clone();
            bytes[0] ^= 1;
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "bad signature",
        {
            let mut decoded = Zp1Object::decode(&object).unwrap();
            decoded.signature_block.mldsa_signature[0] ^= 1;
            decoded.encode()
        },
        aad.clone(),
    ));
    cases.push(("bad aad", object.clone(), b"wrong aad".to_vec()));
    cases.push(("bad recipient", object.clone(), aad.clone()));
    cases.push((
        "bad wrapped content secret",
        {
            let mut decoded = Zp1Object::decode(&object).unwrap();
            decoded.recipient_stanzas[0].wrapped_content_secret[0] ^= 1;
            decoded.encode()
        },
        aad.clone(),
    ));
    cases.push((
        "bad key commitment",
        {
            let mut decoded = Zp1Object::decode(&object).unwrap();
            decoded.public_manifest.key_commitment[0] ^= 1;
            decoded.encode()
        },
        aad.clone(),
    ));
    cases.push((
        "bad manifest tag",
        {
            let mut bytes = object.clone();
            bytes[spans.manifest_tag.start] ^= 1;
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "bad merkle root",
        {
            let mut decoded = Zp1Object::decode(&object).unwrap();
            decoded.public_manifest.merkle_root[0] ^= 1;
            decoded.encode()
        },
        aad.clone(),
    ));
    cases.push((
        "bad chunk tag",
        {
            let mut bytes = object.clone();
            bytes[spans.chunks[0].start] ^= 1;
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "trailing bytes",
        {
            let mut bytes = object.clone();
            bytes.push(0);
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "unknown flags",
        {
            let mut bytes = object.clone();
            bytes[spans.base_header.end - 1] ^= 1;
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "malformed lengths",
        {
            let mut bytes = object.clone();
            bytes[spans.public_manifest_len.start..spans.public_manifest_len.end]
                .copy_from_slice(&u32::MAX.to_be_bytes());
            bytes
        },
        aad.clone(),
    ));
    cases.push((
        "invalid archive_present",
        {
            let mut bytes = object.clone();
            let offset = archive_present_offset(&bytes, &spans).unwrap();
            bytes[offset] = 2;
            bytes
        },
        aad.clone(),
    ));

    let (_, wrong_recipient_sk) = provider.generate_kem_keypair(b"wrong recipient");

    for (name, bytes, case_aad) in cases {
        let recipient = if name == "bad recipient" {
            &wrong_recipient_sk
        } else {
            &recipient_sk
        };
        let result = open(
            &mut provider,
            recipient,
            &signer_pk,
            &case_aad,
            &bytes,
            OpenOptions::default(),
        );
        assert_eq!(result, Err(Zp1Error::Auth), "{name}");
    }
}

#[test]
fn unsupported_archive_suite_is_documented_exception() {
    let vector = positive_vector();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);
    let object = vector.sealed_object();
    let err = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &vector.aad(),
        &object,
        OpenOptions {
            require_archive_signature: true,
        },
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::Auth);

    let mut decoded = Zp1Object::decode(&object).unwrap();
    decoded.suite_id = zp1::SuiteId::Zp1Archive;
    decoded.base_header.suite_id = zp1::SuiteId::Zp1Archive;
    let err = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &vector.aad(),
        &decoded.encode(),
        OpenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::UnsupportedSuite);
}
