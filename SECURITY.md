# Security Policy

ZP-1 is experimental and unaudited. Do not use this crate for production secrets yet.

The test provider is not cryptographic. It is deterministic fake crypto for protocol tests only and must not be used for production data.

Fuzzing does not prove security. It is parser and failure-behavior hardening only.

Production use is not recommended yet.

Report vulnerabilities through GitHub issues until a private reporting process exists.

Side-channel resistance depends on provider implementations for ML-KEM-1024, ML-DSA-87, SLH-DSA, AES-256-GCM-SIV, SHA-384, and HMAC-SHA384.

No warranty is provided.
