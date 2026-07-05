# Security Policy

ZP-1 is experimental and unaudited. Do not use this crate for production secrets.

The test provider is not cryptographic. It is deterministic fake crypto for protocol tests only and must not be used for production data.

Fuzzing and tests do not prove cryptographic security. They provide parser, mutation, transcript-drift, and failure-behavior regression evidence only.

`VALIDATION.md` records test and workflow status but does not constitute a security audit.

Production use is not recommended yet.

Report vulnerabilities through GitHub issues until a private reporting process exists.

Side-channel resistance depends on provider implementations for ML-KEM-1024, ML-DSA-87, SLH-DSA, AES-256-GCM-SIV, SHA-384, and HMAC-SHA384.

No warranty is provided.
