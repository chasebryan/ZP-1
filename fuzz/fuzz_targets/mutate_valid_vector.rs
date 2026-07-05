#![no_main]

use libfuzzer_sys::fuzz_target;
use zp1::open::{open, OpenOptions};
use zp1::provider::test_utils::InsecureTestProvider;

const VECTOR_JSON: &str =
    include_str!("../../test-vectors/zp1-core-insecure-test-provider-v0.json");

fuzz_target!(|data: &[u8]| {
    let original = hex_decode(&json_string(VECTOR_JSON, "sealed_object_hex"));
    let aad = hex_decode(&json_string(VECTOR_JSON, "aad_hex"));
    let seed = hex_decode(&json_string(VECTOR_JSON, "provider_seed_hex"));
    let recipient_label = hex_decode(&json_string(VECTOR_JSON, "recipient_label_hex"));
    let signer_label = hex_decode(&json_string(VECTOR_JSON, "signer_label_hex"));

    let mut mutated = original.clone();
    apply_mutation(data, &mut mutated);

    let provider = InsecureTestProvider::new(&seed);
    let (_, recipient_sk) = provider.generate_kem_keypair(&recipient_label);
    let (signer_pk, _) = provider.generate_signature_keypair(&signer_label);
    let mut provider = provider;
    let result = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &aad,
        &mutated,
        OpenOptions::default(),
    );

    if data.is_empty() {
        assert!(result.is_ok());
    } else if result.is_ok() && mutated != original {
        panic!("mutated object opened successfully");
    }
});

fn apply_mutation(data: &[u8], bytes: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    match data[0] % 4 {
        0 => {
            for pair in data[1..].chunks(2) {
                if pair.len() == 2 && !bytes.is_empty() {
                    let index = usize::from(pair[0]) % bytes.len();
                    bytes[index] ^= pair[1];
                }
            }
        }
        1 => {
            let new_len = usize::from(data.get(1).copied().unwrap_or(0)) % bytes.len().max(1);
            bytes.truncate(new_len);
        }
        2 => {
            bytes.extend_from_slice(&data[1..]);
        }
        _ => {
            if bytes.len() > 2 {
                let first = usize::from(data.get(1).copied().unwrap_or(0)) % bytes.len();
                let second = usize::from(data.get(2).copied().unwrap_or(0)) % bytes.len();
                bytes.swap(first, second);
            }
        }
    }
}

fn json_string(input: &str, key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let start = input.find(&needle).unwrap_or(0) + needle.len();
    let rest = &input[start..];
    let end = rest.find('"').unwrap_or(0);
    rest[..end].to_string()
}

fn hex_decode(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}
