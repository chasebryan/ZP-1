#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::Path;

use zp1::object::Zp1Object;
use zp1::provider::test_utils::InsecureTestProvider;
use zp1::seal::{seal, SealOptions};
use zp1::test_support::{archive_present_offset, inspect_vector_object, object_spans};
use zp1::SuiteId;

const WARNING: &str =
    "NOT CRYPTOGRAPHICALLY SECURE. TEST VECTOR FOR WIRE FORMAT AND TRANSCRIPT STABILITY ONLY.";
const NEGATIVE_WARNING: &str =
    "NOT CRYPTOGRAPHICALLY SECURE. NEGATIVE TEST VECTOR FOR PARSING AND AUTHENTICATION FAILURE BEHAVIOR ONLY.";
const SOURCE_VECTOR: &str = "test-vectors/zp1-core-insecure-test-provider-v0.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let write = env::args().skip(1).any(|arg| arg == "--write");
    eprintln!("WARNING: InsecureTestProvider is not cryptographic. TESTS ONLY.");

    let positive = build_positive()?;
    if write {
        fs::create_dir_all("test-vectors/negative")?;
        fs::create_dir_all("fuzz/corpus")?;
        fs::write(SOURCE_VECTOR, positive.json.as_bytes())?;
        for negative in build_negative_vectors(&positive.object_bytes)? {
            fs::write(
                format!("test-vectors/negative/{}.json", negative.name),
                negative.json().as_bytes(),
            )?;
        }
        fs::write("fuzz/corpus/zp1-core-valid.bin", &positive.object_bytes)?;
    } else {
        print!("{}", positive.json);
    }

    Ok(())
}

struct PositiveOutput {
    json: String,
    object_bytes: Vec<u8>,
}

fn build_positive() -> Result<PositiveOutput, Box<dyn std::error::Error>> {
    let seed = b"ZP-1 phase 2 vector seed";
    let recipient_label = b"recipient-0";
    let signer_label = b"signer";
    let aad = b"ZP-1 phase 2 vector aad";
    let plaintext = b"ZP-1 phase 2 deterministic vector plaintext";
    let chunk_size = 16;

    let mut provider = InsecureTestProvider::new(seed);
    let (recipient_pk, recipient_sk) = provider.generate_kem_keypair(recipient_label);
    let (signer_pk, signer_sk) = provider.generate_signature_keypair(signer_label);
    let object_bytes = seal(
        &mut provider,
        std::slice::from_ref(&recipient_pk),
        &signer_sk,
        &signer_pk,
        aad,
        plaintext,
        SealOptions {
            chunk_size,
            suite_id: SuiteId::Zp1Core,
        },
    )?;

    let object = Zp1Object::decode(&object_bytes).map_err(|_| "generated object did not decode")?;
    let inspection = inspect_vector_object(&mut provider, &recipient_sk, &object)
        .map_err(|_| "generated object could not be inspected")?;

    let json = format!(
        concat!(
            "{{\n",
            "  \"warning\": \"{}\",\n",
            "  \"suite_id\": \"Zp1Core\",\n",
            "  \"chunk_size\": {},\n",
            "  \"provider_seed_hex\": \"{}\",\n",
            "  \"recipient_label_hex\": \"{}\",\n",
            "  \"signer_label_hex\": \"{}\",\n",
            "  \"plaintext_hex\": \"{}\",\n",
            "  \"aad_hex\": \"{}\",\n",
            "  \"signer_public_key_hex\": \"{}\",\n",
            "  \"recipient_public_key_hex\": \"{}\",\n",
            "  \"sealed_object_hex\": \"{}\",\n",
            "  \"base_header_hash_hex\": \"{}\",\n",
            "  \"stanzas_hash_hex\": \"{}\",\n",
            "  \"key_commitment_hex\": \"{}\",\n",
            "  \"merkle_root_hex\": \"{}\",\n",
            "  \"manifest_tag_hex\": \"{}\",\n",
            "  \"signature_input_hash_hex\": \"{}\"\n",
            "}}\n"
        ),
        WARNING,
        chunk_size,
        hex(seed),
        hex(recipient_label),
        hex(signer_label),
        hex(plaintext),
        hex(aad),
        hex(signer_pk.as_ref()),
        hex(recipient_pk.as_ref()),
        hex(&object_bytes),
        hex(&inspection.base_header_hash),
        hex(&inspection.stanzas_hash),
        hex(&inspection.key_commitment),
        hex(&inspection.merkle_root),
        hex(&inspection.manifest_tag),
        hex(&inspection.signature_input_hash),
    );

    Ok(PositiveOutput { json, object_bytes })
}

struct NegativeOutput {
    name: &'static str,
    description: &'static str,
    mutation: &'static str,
    aad_hex: String,
    sealed_object_hex: String,
}

impl NegativeOutput {
    fn json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"warning\": \"{}\",\n",
                "  \"name\": \"{}\",\n",
                "  \"description\": \"{}\",\n",
                "  \"source_positive_vector\": \"{}\",\n",
                "  \"mutation\": \"{}\",\n",
                "  \"aad_hex\": \"{}\",\n",
                "  \"expected_error\": \"Auth\",\n",
                "  \"sealed_object_hex\": \"{}\"\n",
                "}}\n"
            ),
            NEGATIVE_WARNING,
            self.name,
            self.description,
            SOURCE_VECTOR,
            self.mutation,
            self.aad_hex,
            self.sealed_object_hex
        )
    }
}

fn build_negative_vectors(
    positive: &[u8],
) -> Result<Vec<NegativeOutput>, Box<dyn std::error::Error>> {
    let aad_hex = hex(b"ZP-1 phase 2 vector aad");
    let mut vectors = Vec::new();
    let spans = object_spans(positive).map_err(|_| "positive object spans failed")?;

    push_mutation(
        &mut vectors,
        "tamper_magic",
        "Mutate the magic bytes.",
        "flip byte 0",
        &aad_hex,
        positive,
        |bytes| bytes[0] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_version",
        "Mutate the version field.",
        "flip version byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.version.start + 1] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_suite_id",
        "Mutate the suite id to an unknown suite.",
        "set suite id to 0xffff",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.suite_id.start..spans.suite_id.end]
                .copy_from_slice(&0xffffu16.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_base_header_length",
        "Inflate the base header length prefix.",
        "set base_header_len to u32::MAX",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.base_header_len.start..spans.base_header_len.end]
                .copy_from_slice(&u32::MAX.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_base_header_body",
        "Mutate the base header body.",
        "flip first object_id byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.base_header.start + 19] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_unknown_flags",
        "Set non-zero base header flags.",
        "set final flags byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.base_header.end - 1] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_recipient_count_zero",
        "Set recipient count to zero.",
        "recipient_count = 0",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.recipient_count.start..spans.recipient_count.end]
                .copy_from_slice(&0u16.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_recipient_stanza_length",
        "Inflate the first recipient stanza length.",
        "set stanza length to u32::MAX",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.recipient_stanza_lens[0].start..spans.recipient_stanza_lens[0].end]
                .copy_from_slice(&u32::MAX.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_recipient_header_body",
        "Mutate the recipient header body.",
        "flip recipient header byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.recipient_stanzas[0].start + 12] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_wrapped_content_secret",
        "Mutate the wrapped content secret.",
        "flip wrapped content secret byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.recipient_stanzas[0].end - 1] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_public_manifest_length",
        "Inflate the public manifest length.",
        "set public_manifest_len to u32::MAX",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.public_manifest_len.start..spans.public_manifest_len.end]
                .copy_from_slice(&u32::MAX.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_public_manifest_body",
        "Mutate the public manifest body.",
        "flip manifest byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.public_manifest.start + 10] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_manifest_tag_length",
        "Change the manifest tag length.",
        "manifest_tag_len = 47",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.manifest_tag_len.start..spans.manifest_tag_len.end]
                .copy_from_slice(&47u16.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_manifest_tag_body",
        "Mutate the manifest tag body.",
        "flip manifest tag byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.manifest_tag.start] ^= 0x01,
    );
    push_mutation(
        &mut vectors,
        "tamper_signature_block_length",
        "Inflate the signature block length.",
        "set signature_block_len to u32::MAX",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.signature_block_len.start..spans.signature_block_len.end]
                .copy_from_slice(&u32::MAX.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_signature_body",
        "Mutate the ML-DSA signature body.",
        "flip signature byte",
        &aad_hex,
        positive,
        |bytes| {
            let offset =
                spans.signature_block.start + 2 + b"ZP1 signature block".len() + 4 + 48 + 4;
            bytes[offset] ^= 0x01;
        },
    );
    let archive_offset =
        archive_present_offset(positive, &spans).map_err(|_| "archive offset failed")?;
    push_mutation(
        &mut vectors,
        "tamper_archive_present_invalid",
        "Set archive_present to an invalid value.",
        "archive_present = 2",
        &aad_hex,
        positive,
        |bytes| bytes[archive_offset] = 2,
    );
    push_mutation(
        &mut vectors,
        "tamper_chunk_count_zero",
        "Set chunk count to zero.",
        "chunk_count = 0",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.chunk_count.start..spans.chunk_count.end]
                .copy_from_slice(&0u64.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_chunk_length",
        "Inflate the first chunk length.",
        "set first chunk length to u32::MAX",
        &aad_hex,
        positive,
        |bytes| {
            bytes[spans.chunk_lens[0].start..spans.chunk_lens[0].end]
                .copy_from_slice(&u32::MAX.to_be_bytes())
        },
    );
    push_mutation(
        &mut vectors,
        "tamper_chunk_ciphertext",
        "Mutate a chunk ciphertext byte.",
        "flip first chunk ciphertext byte",
        &aad_hex,
        positive,
        |bytes| bytes[spans.chunks[0].start] ^= 0x01,
    );

    let mut truncated = positive.to_vec();
    truncated.truncate(truncated.len().saturating_sub(1));
    vectors.push(NegativeOutput {
        name: "truncate_object",
        description: "Drop the final byte of the object.",
        mutation: "truncate final byte",
        aad_hex: aad_hex.clone(),
        sealed_object_hex: hex(&truncated),
    });

    let mut appended = positive.to_vec();
    appended.push(0);
    vectors.push(NegativeOutput {
        name: "append_trailing_byte",
        description: "Append one trailing byte to the object.",
        mutation: "append 00",
        aad_hex: aad_hex.clone(),
        sealed_object_hex: hex(&appended),
    });

    vectors.push(NegativeOutput {
        name: "wrong_aad",
        description: "Use valid object bytes with the wrong AAD.",
        mutation: "aad changed, object unchanged",
        aad_hex: hex(b"wrong aad"),
        sealed_object_hex: hex(positive),
    });

    let mut duplicated = Zp1Object::decode(positive).map_err(|_| "decode positive failed")?;
    let mut clone = duplicated.recipient_stanzas[0].clone();
    clone.recipient_header.recipient_index = 1;
    duplicated.recipient_stanzas.push(clone);
    vectors.push(NegativeOutput {
        name: "duplicate_matching_recipient_hash_if_constructible",
        description: "Add a second stanza with the same recipient hash.",
        mutation: "append duplicate recipient stanza with index 1",
        aad_hex: aad_hex.clone(),
        sealed_object_hex: hex(&duplicated.encode()),
    });

    let mut reordered = Zp1Object::decode(positive).map_err(|_| "decode positive failed")?;
    reordered.chunks.swap(0, 1);
    vectors.push(NegativeOutput {
        name: "reorder_chunks_if_constructible",
        description: "Swap the first two chunk ciphertexts.",
        mutation: "swap chunk 0 and chunk 1",
        aad_hex: aad_hex.clone(),
        sealed_object_hex: hex(&reordered.encode()),
    });

    let mut dropped = Zp1Object::decode(positive).map_err(|_| "decode positive failed")?;
    dropped.chunks.pop();
    vectors.push(NegativeOutput {
        name: "drop_chunk_if_constructible",
        description: "Drop the final chunk ciphertext.",
        mutation: "remove final chunk",
        aad_hex,
        sealed_object_hex: hex(&dropped.encode()),
    });

    Ok(vectors)
}

fn push_mutation(
    out: &mut Vec<NegativeOutput>,
    name: &'static str,
    description: &'static str,
    mutation: &'static str,
    aad_hex: &str,
    positive: &[u8],
    mutate: impl FnOnce(&mut Vec<u8>),
) {
    let mut bytes = positive.to_vec();
    mutate(&mut bytes);
    out.push(NegativeOutput {
        name,
        description,
        mutation,
        aad_hex: aad_hex.to_string(),
        sealed_object_hex: hex(&bytes),
    });
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[allow(dead_code)]
fn ensure_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
