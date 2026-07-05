#![cfg(feature = "test-utils")]

mod common;

use common::{hex_encode, positive_vector, vector_provider_and_keys};
use zp1::object::Zp1Object;
use zp1::test_support::inspect_vector_object;

const DRIFT_MESSAGE: &str =
    "Protocol bytes changed. Update SPEC.md and test vectors only if this was intentional.";

#[test]
fn frozen_positive_vector_transcript_does_not_drift() {
    let vector = positive_vector();
    let sealed_object = vector.sealed_object();
    assert_eq!(
        hex_encode(&sealed_object),
        vector.sealed_object_hex,
        "{DRIFT_MESSAGE}"
    );

    let (mut provider, recipient_sk, _) = vector_provider_and_keys(&vector);
    let object = Zp1Object::decode(&sealed_object).expect(DRIFT_MESSAGE);
    let inspection =
        inspect_vector_object(&mut provider, &recipient_sk, &object).expect(DRIFT_MESSAGE);

    assert_eq!(
        hex_encode(&inspection.base_header_hash),
        vector.base_header_hash_hex,
        "{DRIFT_MESSAGE}"
    );
    assert_eq!(
        hex_encode(&inspection.stanzas_hash),
        vector.stanzas_hash_hex,
        "{DRIFT_MESSAGE}"
    );
    assert_eq!(
        hex_encode(&inspection.key_commitment),
        vector.key_commitment_hex,
        "{DRIFT_MESSAGE}"
    );
    assert_eq!(
        hex_encode(&inspection.merkle_root),
        vector.merkle_root_hex,
        "{DRIFT_MESSAGE}"
    );
    assert_eq!(
        hex_encode(&inspection.manifest_tag),
        vector.manifest_tag_hex,
        "{DRIFT_MESSAGE}"
    );
    assert_eq!(
        hex_encode(&inspection.signature_input_hash),
        vector.signature_input_hash_hex,
        "{DRIFT_MESSAGE}"
    );
}
