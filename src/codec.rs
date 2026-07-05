//! Canonical binary reader and writer helpers.

use crate::error::InternalParseError;

/// Bounds-checked reader for canonical ZP-1 binary encoding.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Return remaining unread bytes.
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Read exactly `len` bytes.
    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8], InternalParseError> {
        let end = self.pos.checked_add(len).ok_or(InternalParseError)?;
        if end > self.input.len() {
            return Err(InternalParseError);
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8, InternalParseError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    /// Read a big-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, InternalParseError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, InternalParseError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, InternalParseError> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a fixed-size byte array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], InternalParseError> {
        let bytes = self.read_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a `u32` length-prefixed vector after validating `max_len`.
    pub fn read_vec_u32(&mut self, max_len: usize) -> Result<Vec<u8>, InternalParseError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| InternalParseError)?;
        if len > max_len || len > self.remaining() {
            return Err(InternalParseError);
        }
        Ok(self.read_exact(len)?.to_vec())
    }

    /// Reject trailing bytes.
    pub fn finish(&self) -> Result<(), InternalParseError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(InternalParseError)
        }
    }
}

pub(crate) fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_usize_as_u16(out: &mut Vec<u8>, len: usize) {
    let value = u16::try_from(len).unwrap_or(u16::MAX);
    put_u16(out, value);
}

pub(crate) fn put_usize_as_u32(out: &mut Vec<u8>, len: usize) {
    let value = u32::try_from(len).unwrap_or(u32::MAX);
    put_u32(out, value);
}

pub(crate) fn put_domain(out: &mut Vec<u8>, domain: &[u8]) {
    put_usize_as_u16(out, domain.len());
    out.extend_from_slice(domain);
}

pub(crate) fn read_domain(
    reader: &mut Reader<'_>,
    expected: &[u8],
) -> Result<(), InternalParseError> {
    let len = usize::from(reader.read_u16()?);
    let domain = reader.read_exact(len)?;
    if domain == expected {
        Ok(())
    } else {
        Err(InternalParseError)
    }
}
