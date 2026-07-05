#![forbid(unsafe_code)]

//! ZP-1 post-quantum signed encryption envelope reference implementation.
//!
//! This crate is experimental and unaudited. It does not ship a production
//! post-quantum provider by default.

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

pub use error::Zp1Error;
pub use object::SuiteId;
