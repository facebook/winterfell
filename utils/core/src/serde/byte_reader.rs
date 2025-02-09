// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
#[cfg(feature = "std")]
use core::cell::{Ref, RefCell};
#[cfg(feature = "std")]
use std::io::BufRead;

use super::{Deserializable, DeserializationError};

// BYTE READER TRAIT
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
///
/// Whenever data is read from the reader using any of the `read_*` functions, the reader advances
/// to the next unread byte. If the error occurs, the reader is not rolled back to the state prior
/// to calling any of the function.
pub trait ByteReader {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a single byte read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;

    /// Returns the next byte to be read from `self` without advancing the reader to the next byte.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn peek_u8(&self) -> Result<u8, DeserializationError>;

    /// Returns a slice of bytes of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a slice of the specified length could not be read
    /// from `self`.
    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError>;

    /// Returns a byte array of length `N` read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if an array of the specified length could not be read
    /// from `self`.
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError>;

    /// Checks if it is possible to read at least `num_bytes` bytes from this ByteReader
    ///
    /// # Errors
    /// Returns an error if, when reading the requested number of bytes, we go beyond the
    /// the data available in the reader.
    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError>;

    /// Returns true if there are more bytes left to be read from `self`.
    fn has_more_bytes(&self) -> bool;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a boolean value read from `self` consuming 1 byte from the reader.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_bool(&mut self) -> Result<bool, DeserializationError> {
        let byte = self.read_u8()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DeserializationError::InvalidValue(format!("{byte} is not a boolean value"))),
        }
    }

    /// Returns a u16 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_u16(&mut self) -> Result<u16, DeserializationError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Returns a u32 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u32 value could not be read from `self`.
    fn read_u32(&mut self) -> Result<u32, DeserializationError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Returns a u64 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u64 value could not be read from `self`.
    fn read_u64(&mut self) -> Result<u64, DeserializationError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Returns a u128 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u128 value could not be read from `self`.
    fn read_u128(&mut self) -> Result<u128, DeserializationError> {
        let bytes = self.read_array::<16>()?;
        Ok(u128::from_le_bytes(bytes))
    }

    /// Returns a usize value read from `self` in [vint64](https://docs.rs/vint64/latest/vint64/)
    /// format.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if:
    /// * usize value could not be read from `self`.
    /// * encoded value is greater than `usize` maximum value on a given platform.
    fn read_usize(&mut self) -> Result<usize, DeserializationError> {
        let first_byte = self.peek_u8()?;
        let length = first_byte.trailing_zeros() as usize + 1;

        let result = if length == 9 {
            // 9-byte special case
            self.read_u8()?;
            let value = self.read_array::<8>()?;
            u64::from_le_bytes(value)
        } else {
            let mut encoded = [0u8; 8];
            let value = self.read_slice(length)?;
            encoded[..length].copy_from_slice(value);
            u64::from_le_bytes(encoded) >> length
        };

        // check if the result value is within acceptable bounds for `usize` on a given platform
        if result > usize::MAX as u64 {
            return Err(DeserializationError::InvalidValue(format!(
                "Encoded value must be less than {}, but {} was provided",
                usize::MAX,
                result
            )));
        }

        Ok(result as usize)
    }

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let data = self.read_slice(len)?;
        Ok(data.to_vec())
    }

    /// Returns a String of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a String of the specified length could not be read
    /// from `self`.
    fn read_string(&mut self, num_bytes: usize) -> Result<String, DeserializationError> {
        let data = self.read_vec(num_bytes)?;
        String::from_utf8(data).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }

    /// Reads a deserializable value from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if the specified value could not be read from `self`.
    fn read<D>(&mut self) -> Result<D, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        D::read_from(self)
    }

    /// Reads a sequence of bytes from `self`, attempts to deserialize these bytes into a vector
    /// with the specified number of `D` elements, and returns the result.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if the specified number elements could not be read from
    /// `self`.
    fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        let mut result = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            let element = D::read_from(self)?;
            result.push(element)
        }
        Ok(result)
    }
}

// STANDARD LIBRARY ADAPTER
// ================================================================================================

/// An adapter of [ByteReader] to any type that implements [std::io::Read]
///
/// In particular, this covers things like [std::fs::File], standard input, etc.
#[cfg(feature = "std")]
pub struct ReadAdapter<'a> {
    // NOTE: The [ByteReader] trait does not currently support reader implementations that require
    // mutation during `peek_u8`, `has_more_bytes`, and `check_eor`. These (or equivalent)
    // operations on the standard library [std::io::BufRead] trait require a mutable reference, as
    // it may be necessary to read from the underlying input to implement them.
    //
    // To handle this, we wrap the underlying reader in an [RefCell], this allows us to mutate the
    // reader if necessary during a call to one of the above-mentioned trait methods, without
    // sacrificing safety - at the cost of enforcing Rust's borrowing semantics dynamically.
    //
    // This should not be a problem in practice, except in the case where `read_slice` is called,
    // and the reference returned is from `reader` directly, rather than `buf`. If a call to one
    // of the above-mentioned methods is made while that reference is live, and we attempt to read
    // from `reader`, a panic will occur.
    //
    // Ultimately, this should be addressed by making the [ByteReader] trait align with the
    // standard library I/O traits, so this is a temporary solution.
    reader: RefCell<std::io::BufReader<&'a mut dyn std::io::Read>>,
    // A temporary buffer to store chunks read from `reader` that are larger than what is required
    // for the higher-level [ByteReader] APIs.
    //
    // By default we attempt to satisfy reads from `reader` directly, but that is not always
    // possible.
    buf: alloc::vec::Vec<u8>,
    // The position in `buf` at which we should start reading the next byte, when `buf` is
    // non-empty.
    pos: usize,
    // This is set when we attempt to read from `reader` and get an empty buffer. This indicates
    // that once we exhaust `buf`, we have truly reached end-of-file.
    //
    // We will use this to more accurately handle functions like `has_more_bytes` when this is set.
    guaranteed_eof: bool,
}

#[cfg(feature = "std")]
impl<'a> ReadAdapter<'a> {
    /// Create a new [ByteReader] adapter for the given implementation of [std::io::Read]
    pub fn new(reader: &'a mut dyn std::io::Read) -> Self {
        Self {
            reader: RefCell::new(std::io::BufReader::with_capacity(256, reader)),
            buf: Default::default(),
            pos: 0,
            guaranteed_eof: false,
        }
    }

    /// Get the internal adapter buffer as a (possibly empty) slice of bytes
    #[inline(always)]
    fn buffer(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Get the internal adapter buffer as a slice of bytes, or `None` if the buffer is empty
    #[inline(always)]
    fn non_empty_buffer(&self) -> Option<&[u8]> {
        self.buf.get(self.pos..).filter(|b| !b.is_empty())
    }

    /// Return the current reader buffer as a (possibly empty) slice of bytes.
    ///
    /// This buffer being empty _does not_ mean we're at EOF, you must call
    /// [non_empty_reader_buffer_mut] first.
    #[inline(always)]
    fn reader_buffer(&self) -> Ref<'_, [u8]> {
        Ref::map(self.reader.borrow(), |r| r.buffer())
    }

    /// Return the current reader buffer, reading from the underlying reader
    /// if the buffer is empty.
    ///
    /// Returns `Ok` only if the buffer is non-empty, and no errors occurred
    /// while filling it (if filling was needed).
    fn non_empty_reader_buffer_mut(&mut self) -> Result<&[u8], DeserializationError> {
        use std::io::ErrorKind;
        let buf = self.reader.get_mut().fill_buf().map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => DeserializationError::UnexpectedEOF,
            e => DeserializationError::UnknownError(e.to_string()),
        })?;
        if buf.is_empty() {
            self.guaranteed_eof = true;
            Err(DeserializationError::UnexpectedEOF)
        } else {
            Ok(buf)
        }
    }

    /// Same as [non_empty_reader_buffer_mut], but with dynamically-enforced
    /// borrow check rules so that it can be called in functions like `peek_u8`.
    ///
    /// This comes with overhead for the dynamic checks, so you should prefer
    /// to call [non_empty_reader_buffer_mut] if you already have a mutable
    /// reference to `self`
    fn non_empty_reader_buffer(&self) -> Result<Ref<'_, [u8]>, DeserializationError> {
        use std::io::ErrorKind;
        let mut reader = self.reader.borrow_mut();
        let buf = reader.fill_buf().map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => DeserializationError::UnexpectedEOF,
            e => DeserializationError::UnknownError(e.to_string()),
        })?;
        if buf.is_empty() {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            // Re-borrow immutably
            drop(reader);
            Ok(self.reader_buffer())
        }
    }

    /// Returns true if there is sufficient capacity remaining in `buf` to hold `n` bytes
    #[inline]
    fn has_remaining_capacity(&self, n: usize) -> bool {
        let remaining = self.buf.capacity() - self.buffer().len();
        remaining >= n
    }

    /// Takes the next byte from the input, returning an error if the operation fails
    fn pop(&mut self) -> Result<u8, DeserializationError> {
        if let Some(byte) = self.non_empty_buffer().map(|b| b[0]) {
            self.pos += 1;
            return Ok(byte);
        }
        let result = self.non_empty_reader_buffer_mut().map(|b| b[0]);
        if result.is_ok() {
            self.reader.get_mut().consume(1);
        } else {
            self.guaranteed_eof = true;
        }
        result
    }

    /// Takes the next `N` bytes from the input as an array, returning an error if the operation
    /// fails
    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let buf = self.buffer();
        let mut output = [0; N];
        match buf.len() {
            0 => {
                let buf = self.non_empty_reader_buffer_mut()?;
                if buf.len() < N {
                    return Err(DeserializationError::UnexpectedEOF);
                }
                // SAFETY: This copy is guaranteed to be safe, as we have validated above
                // that `buf` has at least N bytes, and `output` is defined to be exactly
                // N bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), output.as_mut_ptr(), N);
                }
                self.reader.get_mut().consume(N);
            },
            n if n >= N => {
                // SAFETY: This copy is guaranteed to be safe, as we have validated above
                // that `buf` has at least N bytes, and `output` is defined to be exactly
                // N bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), output.as_mut_ptr(), N);
                }
                self.pos += N;
            },
            n => {
                // We have to fill from both the local and reader buffers
                self.non_empty_reader_buffer_mut()?;
                let reader_buf = self.reader_buffer();
                match reader_buf.len() {
                    #[cfg(debug_assertions)]
                    0 => unreachable!("expected reader buffer to be non-empty to reach here"),
                    #[cfg(not(debug_assertions))]
                    // SAFETY: The call to `non_empty_reader_buffer_mut` will return an error
                    // if `reader_buffer` is non-empty, as a result is is impossible to reach
                    // here with a length of 0.
                    0 => unsafe { core::hint::unreachable_unchecked() },
                    // We got enough in one request
                    m if m + n >= N => {
                        let needed = N - n;
                        let dst = output.as_mut_ptr();
                        // SAFETY: Both copies are guaranteed to be in-bounds:
                        //
                        // * `output` is defined to be exactly N bytes
                        // * `buf` is guaranteed to be < N bytes
                        // * `reader_buf` is guaranteed to have the remaining bytes needed,
                        // and we only copy exactly that many bytes
                        unsafe {
                            core::ptr::copy_nonoverlapping(self.buffer().as_ptr(), dst, n);
                            core::ptr::copy_nonoverlapping(reader_buf.as_ptr(), dst.add(n), needed);
                            drop(reader_buf);
                        }
                        self.pos += n;
                        self.reader.get_mut().consume(needed);
                    },
                    // We didn't get enough, but haven't necessarily reached eof yet, so fall back
                    // to filling `self.buf`
                    m => {
                        let needed = N - (m + n);
                        drop(reader_buf);
                        self.buffer_at_least(needed)?;
                        debug_assert!(self.buffer().len() >= N, "expected buffer to be at least {N} bytes after call to buffer_at_least");
                        // SAFETY: This is guaranteed to be an in-bounds copy
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                self.buffer().as_ptr(),
                                output.as_mut_ptr(),
                                N,
                            );
                        }
                        self.pos += N;
                        return Ok(output);
                    },
                }
            },
        }

        // Check if we should reset our internal buffer
        if self.buffer().is_empty() && self.pos > 0 {
            unsafe {
                self.buf.set_len(0);
            }
        }

        Ok(output)
    }

    /// Fill `self.buf` with `count` bytes
    ///
    /// This should only be called when we can't read from the reader directly
    fn buffer_at_least(&mut self, mut count: usize) -> Result<(), DeserializationError> {
        // Read until we have at least `count` bytes, or until we reach end-of-file,
        // which ever comes first.
        loop {
            // If we have succesfully read `count` bytes, we're done
            if count == 0 || self.buf.len() >= count {
                break Ok(());
            }

            // This operation will return an error if the underlying reader hits EOF
            self.non_empty_reader_buffer_mut()?;

            // Extend `self.buf` with the bytes read from the underlying reader.
            //
            // NOTE: We have to re-borrow the reader buffer here, since we can't get a mutable
            // reference to `self.buf` while holding an immutable reference to the reader buffer.
            let reader = self.reader.get_mut();
            let buf = reader.buffer();
            let consumed = buf.len();
            self.buf.extend_from_slice(buf);
            reader.consume(consumed);
            count = count.saturating_sub(consumed);
        }
    }
}

#[cfg(feature = "std")]
impl ByteReader for ReadAdapter<'_> {
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.pop()
    }

    /// NOTE: If we happen to not have any bytes buffered yet when this is called, then we will be
    /// forced to try and read from the underlying reader. This requires a mutable reference, which
    /// is obtained dynamically via [RefCell].
    ///
    /// <div class="warning">
    /// Callers must ensure that they do not hold any immutable references to the buffer of this
    /// reader when calling this function so as to avoid a situtation in which the dynamic borrow
    /// check fails. Specifically, you must not be holding a reference to the result of
    /// [Self::read_slice] when this function is called.
    /// </div>
    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        if let Some(byte) = self.buffer().first() {
            return Ok(*byte);
        }
        self.non_empty_reader_buffer().map(|b| b[0])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        // Edge case
        if len == 0 {
            return Ok(&[]);
        }

        // If we have unused buffer, and the consumed portion is
        // large enough, we will move the unused portion of the buffer
        // to the start, freeing up bytes at the end for more reads
        // before forcing a reallocation
        let should_optimize_storage = self.pos >= 16 && !self.has_remaining_capacity(len);
        if should_optimize_storage {
            // We're going to optimize storage first
            let buf = self.buffer();
            let src = buf.as_ptr();
            let count = buf.len();
            let dst = self.buf.as_mut_ptr();
            unsafe {
                core::ptr::copy(src, dst, count);
                self.buf.set_len(count);
                self.pos = 0;
            }
        }

        // Fill the buffer so we have at least `len` bytes available,
        // this will return an error if we hit EOF first
        self.buffer_at_least(len)?;

        let slice = &self.buf[self.pos..(self.pos + len)];
        self.pos += len;
        Ok(slice)
    }

    #[inline]
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        if N == 0 {
            return Ok([0; N]);
        }
        self.read_exact()
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        // Do we have sufficient data in the local buffer?
        let buffer_len = self.buffer().len();
        if buffer_len >= num_bytes {
            return Ok(());
        }

        // What about if we include what is in the local buffer and the reader's buffer?
        let reader_buffer_len = self.non_empty_reader_buffer().map(|b| b.len())?;
        let buffer_len = buffer_len + reader_buffer_len;
        if buffer_len >= num_bytes {
            return Ok(());
        }

        // We have no more input, thus can't fulfill a request of `num_bytes`
        if self.guaranteed_eof {
            return Err(DeserializationError::UnexpectedEOF);
        }

        // Because this function is read-only, we must optimistically assume we can read `num_bytes`
        // from the input, and fail later if that does not hold. We know we're not at EOF yet, but
        // that's all we can say without buffering more from the reader. We could make use of
        // `buffer_at_least`, which would guarantee a correct result, but it would also impose
        // additional restrictions on the use of this function, e.g. not using it while holding a
        // reference returned from `read_slice`. Since it is not a memory safety violation to return
        // an optimistic result here, it makes for a better tradeoff.
        Ok(())
    }

    #[inline]
    fn has_more_bytes(&self) -> bool {
        !self.buffer().is_empty() || self.non_empty_reader_buffer().is_ok()
    }
}

// CURSOR
// ================================================================================================

#[cfg(feature = "std")]
macro_rules! cursor_remaining_buf {
    ($cursor:ident) => {{
        let buf = $cursor.get_ref().as_ref();
        let start = $cursor.position().min(buf.len() as u64) as usize;
        &buf[start..]
    }};
}

#[cfg(feature = "std")]
impl<T: AsRef<[u8]>> ByteReader for std::io::Cursor<T> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let buf = cursor_remaining_buf!(self);
        if buf.is_empty() {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            let byte = buf[0];
            self.set_position(self.position() + 1);
            Ok(byte)
        }
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        cursor_remaining_buf!(self)
            .first()
            .copied()
            .ok_or(DeserializationError::UnexpectedEOF)
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        let pos = self.position();
        let size = self.get_ref().as_ref().len() as u64;
        if size.saturating_sub(pos) < len as u64 {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            self.set_position(pos + len as u64);
            let start = pos.min(size) as usize;
            Ok(&self.get_ref().as_ref()[start..(start + len)])
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.read_slice(N).map(|bytes| {
            let mut result = [0u8; N];
            result.copy_from_slice(bytes);
            result
        })
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        if cursor_remaining_buf!(self).len() >= num_bytes {
            Ok(())
        } else {
            Err(DeserializationError::UnexpectedEOF)
        }
    }

    #[inline]
    fn has_more_bytes(&self) -> bool {
        let pos = self.position();
        let size = self.get_ref().as_ref().len() as u64;
        pos < size
    }
}

// SLICE READER
// ================================================================================================

/// Implements [ByteReader] trait for a slice of bytes.
///
/// NOTE: If you are building with the `std` feature, you should probably prefer [std::io::Cursor]
/// instead. However, [SliceReader] is still useful in no-std environments until stabilization of
/// the `core_io_borrowed_buf` feature.
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

impl ByteReader for SliceReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let result = self.source[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let result = &self.source[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(result)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        if self.pos + num_bytes > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        Ok(())
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::ByteWriter;

    #[test]
    fn read_adapter_empty() -> Result<(), DeserializationError> {
        let mut reader = std::io::empty();
        let mut adapter = ReadAdapter::new(&mut reader);
        assert!(!adapter.has_more_bytes());
        assert_eq!(adapter.check_eor(8), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.peek_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_slice(0), Ok([].as_slice()));
        assert_eq!(adapter.read_slice(1), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_array(), Ok([]));
        assert_eq!(adapter.read_array::<1>(), Err(DeserializationError::UnexpectedEOF));
        Ok(())
    }

    #[test]
    fn read_adapter_passthrough() -> Result<(), DeserializationError> {
        let mut reader = std::io::repeat(0b101);
        let mut adapter = ReadAdapter::new(&mut reader);
        assert!(adapter.has_more_bytes());
        assert_eq!(adapter.check_eor(8), Ok(()));
        assert_eq!(adapter.peek_u8(), Ok(0b101));
        assert_eq!(adapter.read_u8(), Ok(0b101));
        assert_eq!(adapter.read_slice(0), Ok([].as_slice()));
        assert_eq!(adapter.read_slice(4), Ok([0b101, 0b101, 0b101, 0b101].as_slice()));
        assert_eq!(adapter.read_array(), Ok([]));
        assert_eq!(adapter.read_array(), Ok([0b101, 0b101]));
        Ok(())
    }

    #[test]
    fn read_adapter_exact() {
        const VALUE: usize = 2048;
        let mut reader = Cursor::new(VALUE.to_le_bytes());
        let mut adapter = ReadAdapter::new(&mut reader);
        assert_eq!(usize::from_le_bytes(adapter.read_array().unwrap()), VALUE);
        assert!(!adapter.has_more_bytes());
        assert_eq!(adapter.peek_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_u8(), Err(DeserializationError::UnexpectedEOF));
    }

    #[test]
    fn read_adapter_roundtrip() {
        const VALUE: usize = 2048;

        // Write VALUE to storage
        let mut cursor = Cursor::new([0; core::mem::size_of::<usize>()]);
        cursor.write_usize(VALUE);

        // Read VALUE from storage
        cursor.set_position(0);
        let mut adapter = ReadAdapter::new(&mut cursor);

        assert_eq!(adapter.read_usize(), Ok(VALUE));
    }

    #[test]
    fn read_adapter_for_file() {
        use std::fs::File;

        use crate::ByteWriter;

        let path = std::env::temp_dir().join("read_adapter_for_file.bin");

        // Encode some data to a buffer, then write that buffer to a file
        {
            let mut buf = Vec::<u8>::with_capacity(256);
            buf.write_bytes(b"MAGIC\0");
            buf.write_bool(true);
            buf.write_u32(0xbeef);
            buf.write_usize(0xfeed);
            buf.write_u16(0x5);

            std::fs::write(&path, &buf).unwrap();
        }

        // Open the file, and try to decode the encoded items
        let mut file = File::open(&path).unwrap();
        let mut reader = ReadAdapter::new(&mut file);
        assert_eq!(reader.peek_u8().unwrap(), b'M');
        assert_eq!(reader.read_slice(6).unwrap(), b"MAGIC\0");
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_u32().unwrap(), 0xbeef);
        assert_eq!(reader.read_usize().unwrap(), 0xfeed);
        assert_eq!(reader.read_u16().unwrap(), 0x5);
        assert!(!reader.has_more_bytes(), "expected there to be no more data in the input");
    }
}
