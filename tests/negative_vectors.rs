#![cfg(feature = "test-utils")]

mod common;

use std::fs;
use std::path::Path;

use common::{hex_decode, positive_vector, vector_provider_and_keys, NegativeVector};
use zp1::open::{open, OpenOptions};
use zp1::Zp1Error;

#[test]
fn negative_corpus_vectors_fail_with_auth() {
    let vector = positive_vector();
    let (mut provider, recipient_sk, signer_pk) = vector_provider_and_keys(&vector);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/negative");
    let mut entries = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    entries.sort();
    assert!(entries.len() >= 26);

    for path in entries {
        let input = fs::read_to_string(&path).unwrap();
        let negative = NegativeVector::parse(&input);
        assert_eq!(
            negative.warning,
            "NOT CRYPTOGRAPHICALLY SECURE. NEGATIVE TEST VECTOR FOR PARSING AND AUTHENTICATION FAILURE BEHAVIOR ONLY."
        );
        assert_eq!(
            negative.source_positive_vector,
            "test-vectors/zp1-core-insecure-test-provider-v0.json"
        );
        assert_eq!(negative.expected_error, "Auth");
        assert!(!negative.description.is_empty());
        assert!(!negative.mutation.is_empty());

        let aad = hex_decode(&negative.aad_hex);
        let sealed_object = hex_decode(&negative.sealed_object_hex);
        let result = open(
            &mut provider,
            &recipient_sk,
            &signer_pk,
            &aad,
            &sealed_object,
            OpenOptions::default(),
        );
        assert_eq!(result, Err(Zp1Error::Auth), "{}", negative.name);
    }
}
