mod common;

use common::{fixture, TestKemPublicKey};
use zp1::constants::{DEFAULT_CHUNK_SIZE, MAX_AAD_LEN, MAX_CHUNK_SIZE, MAX_RECIPIENTS};
use zp1::seal::{seal, validate_seal_limits, SealOptions};
use zp1::{SuiteId, Zp1Error};

#[test]
fn seal_rejects_zero_recipients() {
    let mut fx = fixture(b"limit-zero-recipient", 1);
    let recipients: Vec<TestKemPublicKey> = Vec::new();
    let err = seal(
        &mut fx.provider,
        &recipients,
        &fx.signer_sk,
        &fx.signer_pk,
        b"",
        b"",
        SealOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::LimitExceeded);
}

#[test]
fn seal_rejects_too_many_recipients() {
    let mut fx = fixture(b"limit-many-recipient", 1);
    let recipients = vec![fx.recipient_pks[0].clone(); MAX_RECIPIENTS + 1];
    let err = seal(
        &mut fx.provider,
        &recipients,
        &fx.signer_sk,
        &fx.signer_pk,
        b"",
        b"",
        SealOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::LimitExceeded);
}

#[test]
fn seal_rejects_chunk_size_zero() {
    let mut fx = fixture(b"limit-chunk-zero", 1);
    let err = seal(
        &mut fx.provider,
        &fx.recipient_pks,
        &fx.signer_sk,
        &fx.signer_pk,
        b"",
        b"",
        SealOptions {
            chunk_size: 0,
            suite_id: SuiteId::Zp1Core,
        },
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::LimitExceeded);
}

#[test]
fn seal_rejects_chunk_size_too_large() {
    let mut fx = fixture(b"limit-chunk-large", 1);
    let err = seal(
        &mut fx.provider,
        &fx.recipient_pks,
        &fx.signer_sk,
        &fx.signer_pk,
        b"",
        b"",
        SealOptions {
            chunk_size: MAX_CHUNK_SIZE + 1,
            suite_id: SuiteId::Zp1Core,
        },
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::LimitExceeded);
}

#[test]
fn seal_rejects_aad_too_large_without_allocating_huge_memory_if_possible() {
    let err = validate_seal_limits(
        1,
        usize::try_from(MAX_AAD_LEN).unwrap() + 1,
        0,
        DEFAULT_CHUNK_SIZE,
        SuiteId::Zp1Core,
    )
    .unwrap_err();
    assert_eq!(err, Zp1Error::LimitExceeded);
}
