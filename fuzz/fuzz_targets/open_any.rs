#![no_main]

use libfuzzer_sys::fuzz_target;
use zp1::open::{open, OpenOptions};
use zp1::provider::test_utils::InsecureTestProvider;

fuzz_target!(|data: &[u8]| {
    let provider = InsecureTestProvider::new(b"fuzz open_any seed");
    let (_, recipient_sk) = provider.generate_kem_keypair(b"recipient");
    let (signer_pk, _) = provider.generate_signature_keypair(b"signer");
    let mut provider = provider;
    let _ = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        b"fuzz aad",
        data,
        OpenOptions::default(),
    );
});
