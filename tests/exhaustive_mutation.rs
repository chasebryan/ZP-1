#![cfg(feature = "test-utils")]

mod common;

use common::{positive_vector, vector_provider_and_keys};
use zp1::open::{open, OpenOptions};
use zp1::Zp1Error;

#[test]
fn single_byte_flip_every_position_returns_auth() {
    let vector = positive_vector();
    let object = vector.sealed_object();
    let aad = vector.aad();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);

    for offset in 0..object.len() {
        let mut mutated = object.clone();
        mutated[offset] ^= 0x01;
        let result = open(
            &mut provider,
            &recipient_sk,
            &signer_pk,
            &aad,
            &mutated,
            OpenOptions::default(),
        );
        assert_eq!(result, Err(Zp1Error::Auth), "offset {offset}");
    }
}

#[test]
fn truncate_at_every_position_returns_auth() {
    let vector = positive_vector();
    let object = vector.sealed_object();
    let aad = vector.aad();
    let plaintext = vector.plaintext();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);

    let opened = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &aad,
        &object,
        OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(opened, plaintext);

    for len in 0..object.len() {
        let truncated = &object[..len];
        let result = open(
            &mut provider,
            &recipient_sk,
            &signer_pk,
            &aad,
            truncated,
            OpenOptions::default(),
        );
        assert_eq!(result, Err(Zp1Error::Auth), "truncation length {len}");
    }
}

#[test]
fn append_small_suffixes_return_auth() {
    let vector = positive_vector();
    let object = vector.sealed_object();
    let aad = vector.aad();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);

    for suffix_len in 1..=32 {
        let mut mutated = object.clone();
        for index in 0..suffix_len {
            mutated.push(u8::try_from(index + 1).unwrap());
        }
        let result = open(
            &mut provider,
            &recipient_sk,
            &signer_pk,
            &aad,
            &mutated,
            OpenOptions::default(),
        );
        assert_eq!(result, Err(Zp1Error::Auth), "suffix length {suffix_len}");
    }
}

#[test]
#[ignore]
fn bit_flip_every_position_ignored_long_test() {
    let vector = positive_vector();
    let object = vector.sealed_object();
    let aad = vector.aad();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);

    for offset in 0..object.len() {
        for bit in 0..8 {
            let mut mutated = object.clone();
            mutated[offset] ^= 1u8 << bit;
            let result = open(
                &mut provider,
                &recipient_sk,
                &signer_pk,
                &aad,
                &mutated,
                OpenOptions::default(),
            );
            assert_eq!(result, Err(Zp1Error::Auth), "offset {offset}, bit {bit}");
        }
    }
}
