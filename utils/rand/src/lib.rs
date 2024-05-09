// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crates contains functions for generating random values.
//!
//! These functions are intended to be used in tests, benchmarks, and examples. When compiled to
//! WebAssembly target, all of the functions are omitted.

pub use internal::*;

#[cfg(not(target_family = "wasm"))]
mod internal {
    use core::fmt::Debug;

    use rand::prelude::*;
    use utils::Randomizable;

    // RANDOM VALUE GENERATION
    // ============================================================================================

    /// Returns a single random value of the specified type.
    ///
    /// # Panics
    /// Panics if:
    /// * A valid value requires over 32 bytes.
    /// * A valid value could not be generated after 1000 tries.
    pub fn rand_value<R: Randomizable>() -> R {
        for _ in 0..1000 {
            let bytes = rand::thread_rng().gen::<[u8; 32]>();
            if let Some(value) = R::from_random_bytes(&bytes[..R::VALUE_SIZE]) {
                return value;
            }
        }

        panic!("failed generate a random field element");
    }

    /// Returns a vector of random value of the specified type and the specified length.
    ///
    /// # Panics
    /// Panics if:
    /// * A valid value requires at over 32 bytes.
    /// * A valid value could not be generated after 1000 tries.
    pub fn rand_vector<R: Randomizable>(n: usize) -> Vec<R> {
        let mut result = Vec::with_capacity(n);
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let mut g = StdRng::from_seed(seed);
        for _ in 0..1000 * n {
            let bytes = g.gen::<[u8; 32]>();
            if let Some(element) = R::from_random_bytes(&bytes[..R::VALUE_SIZE]) {
                result.push(element);
                if result.len() == n {
                    return result;
                }
            }
        }

        panic!("failed to generate enough random field elements");
    }

    /// Returns an array of random value of the specified type and the specified length.
    ///
    /// # Panics
    /// Panics if:
    /// * A valid value requires at over 32 bytes.
    /// * A valid value could not be generated after 1000 tries.
    pub fn rand_array<R: Randomizable + Debug, const N: usize>() -> [R; N] {
        let elements = rand_vector(N);
        elements.try_into().expect("failed to convert vector to array")
    }

    /// Returns a vector of value of the specified type and the specified length generated
    /// pseudo-randomly from the specified `seed`.
    ///
    /// # Panics
    /// Panics if:
    /// * A valid value requires at over 32 bytes.
    /// * A valid value could not be generated after 1000 tries.
    pub fn prng_vector<R: Randomizable>(seed: [u8; 32], n: usize) -> Vec<R> {
        let mut result = Vec::with_capacity(n);
        let mut g = StdRng::from_seed(seed);
        for _ in 0..1000 * n {
            let bytes = g.gen::<[u8; 32]>();
            if let Some(element) = R::from_random_bytes(&bytes[..R::VALUE_SIZE]) {
                result.push(element);
                if result.len() == n {
                    return result;
                }
            }
        }

        panic!("failed to generate enough random field elements");
    }

    /// Returns an array of value of the specified type and the specified length generated
    /// pseudo-randomly from the specified `seed`.
    ///
    /// # Panics
    /// Panics if:
    /// * A valid value requires at over 32 bytes.
    /// * A valid value could not be generated after 1000 tries.
    pub fn prng_array<R: Randomizable + Debug, const N: usize>(seed: [u8; 32]) -> [R; N] {
        let elements = prng_vector(seed, N);
        elements.try_into().expect("failed to convert vector to array")
    }

    // SHUFFLING
    // ============================================================================================

    /// Randomly shuffles slice elements.
    pub fn shuffle<T>(values: &mut [T]) {
        values.shuffle(&mut thread_rng());
    }
}

#[cfg(target_family = "wasm")]
mod internal {}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{rand_array, rand_value};

    #[test]
    fn rand_primitives() {
        let a = rand_value::<u16>();
        let b = rand_value::<u16>();
        assert_ne!(a, b);

        let a = rand_value::<u32>();
        let b = rand_value::<u32>();
        assert_ne!(a, b);

        let a = rand_value::<u64>();
        let b = rand_value::<u64>();
        assert_ne!(a, b);

        let a = rand_value::<u128>();
        let b = rand_value::<u128>();
        assert_ne!(a, b);
    }

    #[test]
    fn rand_byte_array() {
        let a = rand_array::<u8, 30>();
        let b = rand_array::<u8, 30>();
        assert_ne!(a, b);

        let a = rand_array::<u8, 32>();
        let b = rand_array::<u8, 32>();
        assert_ne!(a, b);

        let a = rand_array::<u8, 34>();
        let b = rand_array::<u8, 34>();
        assert_ne!(a, b);
    }
}
