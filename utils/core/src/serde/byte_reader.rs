use super::{DeserializationError, ToString};

// BYTE READER TRAIT
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
pub trait ByteReader {
    /// Returns a single byte read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;

    /// Returns a u16 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_u16(&mut self) -> Result<u16, DeserializationError>;

    /// Returns a u32 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u32 value could not be read from `self`.
    fn read_u32(&mut self) -> Result<u32, DeserializationError>;

    /// Returns a u64 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u64 value could not be read from `self`.
    fn read_u64(&mut self) -> Result<u64, DeserializationError>;

    /// Returns a u128 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u128 value could not be read from `self`.
    fn read_u128(&mut self) -> Result<u128, DeserializationError>;

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_u8_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError>;

    /// Returns a byte array of length `N` reade from `self`.
    fn read_u8_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError>;

    /// Returns true if there are more bytes left to be read from `self`.
    fn has_more_bytes(&self) -> bool;
}

// SLICE READER
// ================================================================================================

/// Implements [ByteReader] trait for a slice of bytes.
pub struct SliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    /// Creates a new slice reader from the specified slice.
    pub fn new(source: &'a [u8]) -> Self {
        SliceReader { source, pos: 0 }
    }
}

impl<'a> ByteReader for SliceReader<'a> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        if self.pos >= self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos];

        self.pos += 1;
        Ok(result)
    }

    fn read_u16(&mut self) -> Result<u16, DeserializationError> {
        let end_pos = self.pos + 2;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u16::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{err}")))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u32(&mut self) -> Result<u32, DeserializationError> {
        let end_pos = self.pos + 4;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u32::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{err}")))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u64(&mut self) -> Result<u64, DeserializationError> {
        let end_pos = self.pos + 8;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u64::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{err}")))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u128(&mut self) -> Result<u128, DeserializationError> {
        let end_pos = self.pos + 16;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u128::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{err}")))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u8_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let end_pos = self.pos + len;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos..end_pos].to_vec();
        self.pos = end_pos;
        Ok(result)
    }

    fn read_u8_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let end_pos = self.pos + N;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos..end_pos].try_into().map_err(|_| {
            DeserializationError::UnknownError("failed to convert slide into an array".to_string())
        })?;
        self.pos = end_pos;
        Ok(result)
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}
