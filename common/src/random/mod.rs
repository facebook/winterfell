// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ComputationContext;
use crypto::{Hasher, RandomElementGenerator};
use std::{convert::TryInto, mem::size_of};

#[cfg(test)]
mod tests;

// PUBLIC COIN
// ================================================================================================

pub trait PublicCoin {
    type Hasher: Hasher;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn context(&self) -> &ComputationContext;
    fn constraint_seed(&self) -> <<Self as PublicCoin>::Hasher as Hasher>::Digest;
    fn composition_seed(&self) -> <<Self as PublicCoin>::Hasher as Hasher>::Digest;
    fn query_seed(&self) -> <<Self as PublicCoin>::Hasher as Hasher>::Digest;

    // PRNG BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Returns PRNG for generating constraint composition coefficients.
    fn get_constraint_composition_prng(&self) -> RandomElementGenerator<Self::Hasher> {
        RandomElementGenerator::new(self.constraint_seed(), 0)
    }

    /// Returns PRNG for generating DEEP composition coefficients.
    fn get_deep_composition_prng(&self) -> RandomElementGenerator<Self::Hasher> {
        RandomElementGenerator::new(self.composition_seed(), 0)
    }

    // DRAW METHODS
    // --------------------------------------------------------------------------------------------

    /// Draws a set of unique query positions using PRNG seeded with query seed. The positions
    /// are selected from the range [0, lde_domain_size).
    fn draw_query_positions(&self) -> Vec<usize> {
        let num_queries = self.context().options().num_queries();

        // determine how many bits are needed to represent valid indexes in the domain
        let value_mask = self.context().lde_domain_size() - 1;
        let value_offset = size_of::<usize>();

        // initialize the seed for PRNG
        let seed = self.query_seed();

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut result = Vec::new();
        for i in 1u64..1000 {
            // update the seed with the new counter and hash the result
            let seed_hash = Self::Hasher::merge_with_int(seed, i);
            let value_bytes: &[u8] = seed_hash.as_ref();

            // read the required number of bits from the hashed value
            let value =
                usize::from_le_bytes(value_bytes[..value_offset].try_into().unwrap()) & value_mask;

            if result.contains(&value) {
                continue;
            }
            result.push(value);
            if result.len() >= num_queries {
                break;
            }
        }

        assert_eq!(
            result.len(),
            num_queries,
            "needed to generate {} query positions, but generated only {}",
            num_queries,
            result.len()
        );

        result
    }
}
