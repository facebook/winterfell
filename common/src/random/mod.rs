// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ComputationContext;
use crypto::{Hasher, RandomElementGenerator};
use math::field::FieldElement;
use std::{convert::TryInto, mem::size_of};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================
const TRANSITION_COEFF_OFFSET: u64 = 0;
const BOUNDARY_COEFF_OFFSET: u64 = u32::MAX as u64;
const DEEP_POINT_OFFSET: u64 = 0;
const COMPOSITION_COEFF_OFFSET: u64 = 1024;

// PUBLIC COIN
// ================================================================================================

pub trait PublicCoin: fri::PublicCoin {
    // ABSTRACT METHODS
    // --------------------------------------------------------------------------------------------

    fn context(&self) -> &ComputationContext;
    fn constraint_seed(&self) -> <<Self as fri::PublicCoin>::Hasher as Hasher>::Digest;
    fn composition_seed(&self) -> <<Self as fri::PublicCoin>::Hasher as Hasher>::Digest;
    fn query_seed(&self) -> <<Self as fri::PublicCoin>::Hasher as Hasher>::Digest;

    // PRNG BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Returns a PRNG for transition constraint coefficients.
    fn get_transition_coefficient_prng(&self) -> RandomElementGenerator<Self::Hasher> {
        RandomElementGenerator::new(self.constraint_seed(), TRANSITION_COEFF_OFFSET)
    }

    /// Returns a PRNG for boundary constraint coefficients.
    fn get_boundary_coefficient_prng(&self) -> RandomElementGenerator<Self::Hasher> {
        RandomElementGenerator::new(self.constraint_seed(), BOUNDARY_COEFF_OFFSET)
    }

    // DRAW METHODS
    // --------------------------------------------------------------------------------------------

    /// Draws a point from the entire field using PRNG seeded with composition seed.
    fn draw_deep_point<E: FieldElement>(&self) -> E {
        let mut generator =
            RandomElementGenerator::<Self::Hasher>::new(self.composition_seed(), DEEP_POINT_OFFSET);
        generator.draw()
    }

    /// Draws coefficients for building composition polynomial using PRNG seeded with
    /// composition seed.
    fn draw_composition_coefficients<E: FieldElement>(&self) -> CompositionCoefficients<E> {
        let generator = RandomElementGenerator::<Self::Hasher>::new(
            self.composition_seed(),
            COMPOSITION_COEFF_OFFSET,
        );
        CompositionCoefficients::new(generator, self.context().trace_width())
    }

    /// Draws a set of unique query positions using PRNG seeded with query seed. The positions
    /// are selected from the range [0, lde_domain_size).
    fn draw_query_positions(&self) -> Vec<usize> {
        let num_queries = self.context().options().num_queries();

        // determine how many bits are needed to represent valid indexes in the domain
        let value_mask = self.context().lde_domain_size() - 1;
        let value_offset = 32 - size_of::<usize>();

        // initialize the seed for PRNG
        let seed = self.query_seed();

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut result = Vec::new();
        for i in 0u64..1000 {
            // update the seed with the new counter and hash the result
            let seed_hash = Self::Hasher::merge_with_int(seed, i);
            let value_bytes: &[u8] = seed_hash.as_ref();

            // read the required number of bits from the hashed value
            let value =
                usize::from_le_bytes(value_bytes[value_offset..].try_into().unwrap()) & value_mask;

            if result.contains(&value) {
                continue;
            }
            result.push(value);
            if result.len() >= num_queries {
                break;
            }
        }

        assert!(
            result.len() == num_queries,
            "needed to generate {} query positions, but generated only {}",
            num_queries,
            result.len()
        );

        result
    }
}

// COMPOSITION COEFFICIENTS
// ================================================================================================

#[derive(Debug)]
pub struct CompositionCoefficients<E: FieldElement> {
    pub trace: Vec<(E, E, E)>,
    pub trace_degree: (E, E),
    pub constraints: E,
}

impl<E: FieldElement> CompositionCoefficients<E> {
    pub fn new<H: Hasher>(mut prng: RandomElementGenerator<H>, trace_width: usize) -> Self {
        CompositionCoefficients {
            trace: (0..trace_width).map(|_| prng.draw_triple()).collect(),
            trace_degree: prng.draw_pair(),
            constraints: prng.draw(),
        }
    }
}
