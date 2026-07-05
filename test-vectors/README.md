# ZP-1 Test Vectors

The vectors in this directory are generated with `InsecureTestProvider`.

NOT CRYPTOGRAPHICALLY SECURE. TEST VECTOR FOR WIRE FORMAT AND TRANSCRIPT STABILITY ONLY.

These vectors freeze ZP-1 protocol mechanics: canonical encoding, transcript hashing, KDF labels, Merkle binding, manifest tagging, and Open behavior. They are not cryptographic assurance vectors and must not be used to validate ML-KEM-1024, ML-DSA-87, SLH-DSA, or production randomness.

Production-provider vectors should be added only after provider canonicalization and review status are documented.
