#![cfg(feature = "test-utils")]

mod common;

use common::{hex_encode, positive_vector, vector_provider_and_keys};
use subtle::ConstantTimeEq;
use zp1::object::Zp1Object;
use zp1::open::{open, OpenOptions};
use zp1::test_support::inspect_vector_object;
use zp1::SuiteId;

#[test]
fn zp1_core_insecure_test_provider_vector_verifies() {
    let vector = positive_vector();
    assert_eq!(
        vector.warning,
        "NOT CRYPTOGRAPHICALLY SECURE. TEST VECTOR FOR WIRE FORMAT AND TRANSCRIPT STABILITY ONLY."
    );
    assert_eq!(vector.suite_id, "Zp1Core");
    assert_eq!(vector.chunk_size, 16);

    let aad = vector.aad();
    let plaintext = vector.plaintext();
    let sealed_object = vector.sealed_object();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);

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

    let inspection = inspect_vector_object(&mut provider, &recipient_sk, &object).unwrap();
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
}
