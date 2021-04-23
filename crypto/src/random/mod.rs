// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Hasher;
use math::field::FieldElement;
use std::{convert::TryInto, marker::PhantomData};

// RANDOM FIELD ELEMENT GENERATOR TRAIT
// ================================================================================================

pub trait RandomElementGenerator {
    type Hasher: Hasher;

    /// Returns a new random element generator instantiated with the provided `seed` and `offset`.
    fn new(seed: [u8; 32], offset: u64) -> Self;

    /// Generates the next pseudo-random field element.
    fn draw<E: FieldElement>(&mut self) -> E;

    /// Generates the next pair of pseudo-random field element.
    fn draw_pair<E: FieldElement>(&mut self) -> (E, E) {
        (self.draw(), self.draw())
    }

    /// Generate the next triple of pseudo-random field elements.
    fn draw_triple<E: FieldElement>(&mut self) -> (E, E, E) {
        (self.draw(), self.draw(), self.draw())
    }
}

// DEFAULT GENERATOR
// ================================================================================================

pub struct DefaultRandomElementGenerator<H: Hasher> {
    seed: [u8; 64],
    _hasher: PhantomData<H>,
}

impl<H: Hasher> DefaultRandomElementGenerator<H> {
    /// Update the seed by incrementing the value in the last 8 bytes by 1.
    fn increment_counter(&mut self) {
        let mut counter = u64::from_le_bytes(self.seed[56..].try_into().unwrap());
        counter += 1;
        self.seed[56..].copy_from_slice(&counter.to_le_bytes());
    }
}

impl<H: Hasher> RandomElementGenerator for DefaultRandomElementGenerator<H> {
    type Hasher = H;

    fn new(seed: [u8; 32], offset: u64) -> Self {
        let mut generator = DefaultRandomElementGenerator {
            seed: [0u8; 64],
            _hasher: PhantomData,
        };
        generator.seed[..32].copy_from_slice(&seed);
        generator.seed[56..].copy_from_slice(&offset.to_le_bytes());
        generator
    }

    fn draw<E: FieldElement>(&mut self) -> E {
        let hash_fn = H::hash_fn();
        let mut result = [0u8; 32];
        loop {
            // updated the seed by incrementing its counter and then hash the result
            self.increment_counter();
            hash_fn(&self.seed, &mut result);

            // take the first ELEMENT_BYTES from the hashed seed and check if they can be converted
            // into a valid field element; if the can, return; otherwise try again
            if let Some(element) = E::from_random_bytes(&result[..(E::ELEMENT_BYTES as usize)]) {
                return element;
            }

            // TODO: abort after some number of retries
        }
    }
}
