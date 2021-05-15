// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{mem, slice};

#[cfg(test)]
mod tests;

// AS BYTES
// ================================================================================================

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize, const M: usize> AsBytes for [[u8; N]; M] {
    /// Flattens an array of array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = N * M;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> AsBytes for [[u8; N]] {
    /// Flattens a slice of array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = self.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

// VECTOR FUNCTIONS
// ================================================================================================

/// Returns a vector of the specified length with un-initialized memory. This is faster than
/// requesting a vector with initialized memory and is useful when we overwrite all contents of
/// the vector immediately after initialization. Otherwise, this will lead to undefined behavior.
pub fn uninit_vector<T>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    unsafe {
        vector.set_len(length);
    }
    vector
}

// GROUPING / UN-GROUPING FUNCTIONS
// ================================================================================================

/// Transmutes a vector of n elements into a vector of n / N elements, each of which is
/// an array of N elements.
/// Panics if n is not divisible by N.
pub fn group_vector_elements<T, const N: usize>(source: Vec<T>) -> Vec<[T; N]> {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}",
        N
    );
    let mut v = mem::ManuallyDrop::new(source);
    let p = v.as_mut_ptr();
    let len = v.len() / N;
    let cap = v.capacity() / N;
    unsafe { Vec::from_raw_parts(p as *mut [T; N], len, cap) }
}

/// Transmutes a slice of n elements into a slice of n / N elements, each of which is
/// an array of N elements.
/// Panics if n is not divisible by N.
pub fn group_slice_elements<T, const N: usize>(source: &[T]) -> &[[T; N]] {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}",
        N
    );
    let p = source.as_ptr();
    let len = source.len() / N;
    unsafe { slice::from_raw_parts(p as *const [T; N], len) }
}
