// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Hasher;
use core::{convert::TryInto, marker::PhantomData};
use math::{FieldElement, StarkField};

#[cfg(test)]
mod tests;

// PUBLIC COIN
// ================================================================================================

pub struct PublicCoin<B: StarkField, H: Hasher> {
    seed: H::Digest,
    counter: u64,
    _base_field: PhantomData<B>,
}

impl<B: StarkField, H: Hasher> PublicCoin<B, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new public coin instantiated with the provided `seed`.
    pub fn new(seed: &[u8]) -> Self {
        let seed = H::hash(seed);
        PublicCoin {
            seed,
            counter: 0,
            _base_field: PhantomData,
        }
    }

    // RESEEDING
    // --------------------------------------------------------------------------------------------

    /// Reseeds the coin with the specified data by setting the new seed to hash(seed || data).
    pub fn reseed(&mut self, data: H::Digest) {
        self.seed = H::merge(&[self.seed, data]);
        self.counter = 0;
    }

    /// Reseeds the coin with the specified value by setting the new seed to hash(seed || value).
    pub fn reseed_with_int(&mut self, value: u64) {
        self.seed = H::merge_with_int(self.seed, value);
        self.counter = 0;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of leading zeros in the seed if it is interpreted as an integer in
    /// big-endian byte order.
    pub fn leading_zeros(&self) -> u32 {
        let bytes = self.seed.as_ref();
        let seed_head = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        seed_head.trailing_zeros()
    }

    /// Computes hash(seed || value) and returns the number of leading zeros in the resulting
    /// value if it is interpreted as an integer in big-endian byte order.
    pub fn check_leading_zeros(&self, value: u64) -> u32 {
        let new_seed = H::merge_with_int(self.seed, value);
        let bytes = new_seed.as_ref();
        let seed_head = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        seed_head.trailing_zeros()
    }

    // DRAW METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the next pseudo-random field element.
    ///
    /// Panics if a valid field element could not be generated after 100 calls to PRNG;
    pub fn draw<E: FieldElement<BaseField = B>>(&mut self) -> E {
        for _ in 0..100 {
            // get the next pseudo-random value and take the first ELEMENT_BYTES from it
            let value = self.next();
            let bytes = &value.as_ref()[..E::ELEMENT_BYTES as usize];

            // check if the bytes can be converted into a valid field element; if they can,
            // return; otherwise try again
            if let Some(element) = E::from_random_bytes(bytes) {
                return element;
            }
        }

        panic!("failed to generate a valid field element after 100 tries");
    }

    /// Returns the next pair of pseudo-random field element.
    ///
    /// Panics if valid field elements could not be generated after 200 calls to PRNG;
    pub fn draw_pair<E: FieldElement<BaseField = B>>(&mut self) -> (E, E) {
        (self.draw(), self.draw())
    }

    /// Returns the next triple of pseudo-random field elements.
    ///
    /// Panics if valid field elements could not be generated after 300 calls to PRNG;
    pub fn draw_triple<E: FieldElement<BaseField = B>>(&mut self) -> (E, E, E) {
        (self.draw(), self.draw(), self.draw())
    }

    /// Returns a vector of unique integers selected from the range [0, domain_size).
    ///
    /// Panics if:
    /// - `domain_size` is not a power of two.
    /// - `num_values` is greater than or equal to `domain_size`.
    /// - the specified number of unique integers could not be generated after 1000 calls to PRNG.
    pub fn draw_integers(&mut self, num_values: usize, domain_size: usize) -> Vec<usize> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            num_values < domain_size,
            "number of values must be smaller than domain size"
        );

        // determine how many bits are needed to represent valid values in the domain
        let v_mask = (domain_size - 1) as u64;

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut values = Vec::new();
        for _ in 0..1000 {
            // get the next pseudo-random value and read the first 8 bytes from it
            let bytes: [u8; 8] = self.next().as_ref()[..8].try_into().unwrap();

            // convert to integer and limit the integer to the number of bits which can fit
            // into the specified domain
            let value = (u64::from_le_bytes(bytes) & v_mask) as usize;

            if values.contains(&value) {
                continue;
            }
            values.push(value);
            if values.len() == num_values {
                break;
            }
        }

        assert_eq!(
            values.len(),
            num_values,
            "needed to generate {} values, but generated only {}",
            num_values,
            values.len()
        );

        values
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Updates the state by incrementing the counter and returns hash(seed || counter)
    fn next(&mut self) -> H::Digest {
        self.counter += 1;
        H::merge_with_int(self.seed, self.counter)
    }
}

// RANDOM FIELD ELEMENT GENERATOR
// ================================================================================================

pub struct RandomElementGenerator<H: Hasher> {
    seed: H::Digest,
    counter: u64,
}

impl<H: Hasher> RandomElementGenerator<H> {
    /// Returns a new random element generator instantiated with the provided `seed` and `offset`.
    pub fn new(seed: H::Digest) -> Self {
        RandomElementGenerator { seed, counter: 0 }
    }

    /// Generates the next pseudo-random field element.
    pub fn draw<E: FieldElement>(&mut self) -> E {
        for _ in 0..100 {
            // updated the seed by incrementing its counter and then hash the result
            self.counter += 1;
            let result = H::merge_with_int(self.seed, self.counter);
            let bytes: &[u8] = result.as_ref();

            // take the first ELEMENT_BYTES from the hashed seed and check if they can be
            // converted into a valid field element; if the can, return; otherwise try again
            if let Some(element) = E::from_random_bytes(&bytes[..(E::ELEMENT_BYTES as usize)]) {
                return element;
            }
        }

        panic!("failed to generate a valid field element after 100 tries");
    }

    /// Generates the next pair of pseudo-random field element.
    pub fn draw_pair<E: FieldElement>(&mut self) -> (E, E) {
        (self.draw(), self.draw())
    }

    /// Generate the next triple of pseudo-random field elements.
    pub fn draw_triple<E: FieldElement>(&mut self) -> (E, E, E) {
        (self.draw(), self.draw(), self.draw())
    }
}
