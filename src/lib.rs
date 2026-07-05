#![forbid(unsafe_code)]

//! ZP-1 post-quantum signed encryption envelope reference implementation.
//!
//! This crate is experimental and unaudited. Do not use it for production
//! secrets.
//!
//! The default build contains no production post-quantum provider. Production
//! use requires a real provider for ML-KEM-1024, ML-DSA-87, and, for Archive
//! mode, SLH-DSA level 5.
//!
//! The `test-utils` feature exposes `InsecureTestProvider`. That provider is
//! NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY. It exists for deterministic wire
//! format, transcript, parser, and failure-behavior tests.
//!
//! Public Open failures intentionally collapse parser, authentication, binding,
//! and integrity failures to [`Zp1Error::Auth`]. The public error surface must
//! not reveal whether a hostile object failed signature, AAD, recipient,
//! commitment, manifest tag, Merkle, chunk tag, or parse checks.

pub mod codec;
pub mod constants;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod merkle;
pub mod object;
pub mod open;
pub mod provider;
pub mod seal;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_support;

pub use error::Zp1Error;
pub use object::SuiteId;
