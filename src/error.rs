//! Public and internal error types.

use thiserror::Error;

use crate::provider::ProviderError;

/// Public ZP-1 error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Zp1Error {
    /// Authentication, parsing, binding, or integrity failure.
    #[error("ZP-1 authentication failure")]
    Auth,
    /// The requested suite is not supported by this implementation.
    #[error("unsupported ZP-1 suite")]
    UnsupportedSuite,
    /// A caller-supplied input exceeds implementation limits.
    #[error("ZP-1 limit exceeded")]
    LimitExceeded,
    /// The cryptographic provider failed.
    #[error("ZP-1 provider failure")]
    Provider,
    /// An I/O operation failed.
    #[error("ZP-1 I/O failure")]
    Io,
}

impl From<ProviderError> for Zp1Error {
    fn from(_: ProviderError) -> Self {
        Self::Provider
    }
}

/// Internal parse failure. Public Open APIs collapse this to `Zp1Error::Auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalParseError;

/// Internal cryptographic construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InternalCryptoError;
