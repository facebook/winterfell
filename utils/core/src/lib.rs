// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains utility traits, functions, and macros used by other crates of Winterfell
//! STARK prover and verifier.
#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod iterators;

use alloc::vec::Vec;
use core::{mem, slice};

mod serde;
#[cfg(feature = "std")]
pub use serde::ReadAdapter;
pub use serde::{ByteReader, ByteWriter, Deserializable, Serializable, SliceReader};

mod errors;
pub use errors::DeserializationError;

#[cfg(test)]
mod tests;

// FEATURE-BASED RE-EXPORTS
// ================================================================================================

#[cfg(feature = "concurrent")]
use iterators::*;
#[cfg(feature = "concurrent")]
pub use rayon;

// AS BYTES
// ================================================================================================

/// Defines a zero-copy representation of `Self` as a sequence of bytes.
pub trait AsBytes {
    /// Returns a byte representation of `self`.
    ///
    /// This method is intended to re-interpret the underlying memory as a sequence of bytes, and
    /// thus, should be zero-copy.
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize, const M: usize> AsBytes for [[u8; N]; M] {
    /// Flattens a two-dimensional array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = N * M;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> AsBytes for [[u8; N]] {
    /// Flattens a slice of byte arrays into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = self.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

// VECTOR FUNCTIONS
// ================================================================================================

/// Returns a vector of the specified length with un-initialized memory.
///
/// This is usually faster than requesting a vector with initialized memory and is useful when we
/// overwrite all contents of the vector immediately after memory allocation.
///
/// # Safety
/// Using values from the returned vector before initializing them will lead to undefined behavior.
#[allow(clippy::uninit_vec)]
pub unsafe fn uninit_vector<T>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    vector.set_len(length);
    vector
}

// GROUPING / UN-GROUPING FUNCTIONS
// ================================================================================================

/// Transmutes a slice of `n` elements into a slice of `n` / `N` elements, each of which is
/// an array of `N` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Panics
/// Panics if `n` is not divisible by `N`.
///
/// # Example
/// ```
/// # use winter_utils::group_slice_elements;
/// let a = [0_u32, 1, 2, 3, 4, 5, 6, 7];
/// let b: &[[u32; 2]] = group_slice_elements(&a);
///
/// assert_eq!(&[[0, 1], [2, 3], [4, 5], [6, 7]], b);
/// ```
pub fn group_slice_elements<T, const N: usize>(source: &[T]) -> &[[T; N]] {
    assert_eq!(source.len() % N, 0, "source length must be divisible by {N}");
    let p = source.as_ptr();
    let len = source.len() / N;
    unsafe { slice::from_raw_parts(p as *const [T; N], len) }
}

/// Transmutes a slice of `n` arrays each of length `N`, into a slice of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Example
/// ```
/// # use winter_utils::flatten_slice_elements;
/// let a = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
///
/// let b = flatten_slice_elements(&a);
/// assert_eq!(&[1, 2, 3, 4, 5, 6, 7, 8], b);
/// ```
pub fn flatten_slice_elements<T, const N: usize>(source: &[[T; N]]) -> &[T] {
    let p = source.as_ptr();
    let len = source.len() * N;
    unsafe { slice::from_raw_parts(p as *const T, len) }
}

/// Transmutes a vector of `n` arrays each of length `N`, into a vector of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Example
/// ```
/// # use winter_utils::flatten_vector_elements;
/// let a = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
///
/// let b = flatten_vector_elements(a);
/// assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8], b);
/// ```
pub fn flatten_vector_elements<T, const N: usize>(source: Vec<[T; N]>) -> Vec<T> {
    let v = mem::ManuallyDrop::new(source);
    let p = v.as_ptr();
    let len = v.len() * N;
    let cap = v.capacity() * N;
    unsafe { Vec::from_raw_parts(p as *mut T, len, cap) }
}

// TRANSPOSING
// ================================================================================================

/// Transposes a slice of `n` elements into a matrix with `N` columns and `n`/`N` rows.
///
/// When `concurrent` feature is enabled, the slice will be transposed using multiple threads.
///
/// # Panics
/// Panics if `n` is not divisible by `N`.
///
/// # Example
/// ```
/// # use winter_utils::transpose_slice;
/// let a = [0_u32, 1, 2, 3, 4, 5, 6, 7];
/// let b: Vec<[u32; 2]> = transpose_slice(&a);
///
/// assert_eq!(vec![[0, 4], [1, 5], [2, 6], [3, 7]], b);
/// ```
pub fn transpose_slice<T: Copy + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;
    assert_eq!(
        row_count * N,
        source.len(),
        "source length must be divisible by {}, but was {}",
        N,
        source.len()
    );

    let mut result: Vec<[T; N]> = unsafe { uninit_vector(row_count) };
    iter_mut!(result, 1024).enumerate().for_each(|(i, element)| {
        for j in 0..N {
            element[j] = source[i + j * row_count]
        }
    });
    result
}

// RANDOMNESS
// ================================================================================================

/// Defines how `Self` can be read from a sequence of random bytes.
pub trait Randomizable: Sized {
    /// Size of `Self` in bytes.
    ///
    /// This is used to determine how many bytes should be passed to the
    /// [from_random_bytes()](Self::from_random_bytes) function.
    const VALUE_SIZE: usize;

    /// Returns `Self` if the set of bytes forms a valid value, otherwise returns None.
    fn from_random_bytes(source: &[u8]) -> Option<Self>;
}

impl Randomizable for u128 {
    const VALUE_SIZE: usize = 16;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u128::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u64 {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u32 {
    const VALUE_SIZE: usize = 4;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u16 {
    const VALUE_SIZE: usize = 2;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u8 {
    const VALUE_SIZE: usize = 1;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        Some(source[0])
    }
}
