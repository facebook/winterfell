// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Hasher;
use math::field::FieldElement;

// RANDOM FIELD ELEMENT GENERATOR
// ================================================================================================

pub struct RandomElementGenerator<H: Hasher> {
    seed: H::Digest,
    counter: u64,
}

impl<H: Hasher> RandomElementGenerator<H> {
    /// Returns a new random element generator instantiated with the provided `seed` and `offset`.
    pub fn new(seed: [u8; 32], offset: u64) -> Self {
        // TODO: remove when seed is changed into H::Digest
        let (seed_vec, _) = H::read_digests_into_vec(&seed, 1);
        RandomElementGenerator {
            seed: seed_vec[0],
            counter: offset,
        }
    }

    /// Generates the next pseudo-random field element.
    pub fn draw<E: FieldElement>(&mut self) -> E {
        loop {
            // updated the seed by incrementing its counter and then hash the result
            self.counter += 1;
            let result = H::hash_with_int(self.seed, self.counter);
            let bytes: &[u8] = result.as_ref();

            // take the first ELEMENT_BYTES from the hashed seed and check if they can be
            // converted into a valid field element; if the can, return; otherwise try again
            if let Some(element) = E::from_random_bytes(&bytes[..(E::ELEMENT_BYTES as usize)]) {
                return element;
            }

            // TODO: abort after some number of retries
        }
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
