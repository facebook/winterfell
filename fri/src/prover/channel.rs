// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::Hasher;
use math::field::FieldElement;
use std::{convert::TryInto, marker::PhantomData, mem::size_of};

// PROVER CHANNEL TRAIT
// ================================================================================================

pub trait ProverChannel<E: FieldElement> {
    type Hasher: Hasher;

    fn commit_fri_layer(
        &mut self,
        layer_root: <<Self as ProverChannel<E>>::Hasher as Hasher>::Digest,
    );

    fn draw_fri_alpha(&mut self) -> E;
}

// DEFAULT PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

pub struct DefaultProverChannel<H: Hasher, E: FieldElement> {
    commitments: Vec<H::Digest>,
    domain_size: usize,
    num_queries: usize,
    _field_element: PhantomData<E>,
}

impl<H: Hasher, E: FieldElement> DefaultProverChannel<H, E> {
    pub fn new(domain_size: usize, num_queries: usize) -> Self {
        DefaultProverChannel {
            commitments: Vec::new(),
            domain_size,
            num_queries,
            _field_element: PhantomData,
        }
    }

    pub fn draw_query_positions(&self) -> Vec<usize> {
        // determine how many bits are needed to represent valid indexes in the domain
        let value_mask = self.domain_size - 1;
        let value_offset = 32 - size_of::<usize>();

        // initialize the seed for PRNG
        let seed = H::merge_many(&self.commitments);

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut result = Vec::new();
        for i in 0u64..1000 {
            // update the seed with the new counter and hash the result
            let seed_hash = H::merge_with_int(seed, i);
            let value_bytes: &[u8] = seed_hash.as_ref();

            // read the required number of bits from the hashed value
            let value =
                usize::from_le_bytes(value_bytes[value_offset..].try_into().unwrap()) & value_mask;

            if result.contains(&value) {
                continue;
            }
            result.push(value);
            if result.len() >= self.num_queries {
                break;
            }
        }

        assert_eq!(
            result.len(),
            self.num_queries,
            "needed to generate {} query positions, but generated only {}",
            self.num_queries,
            result.len()
        );

        result
    }

    pub fn fri_layer_commitments(&self) -> &[H::Digest] {
        &self.commitments
    }
}

impl<H: Hasher, E: FieldElement> ProverChannel<E> for DefaultProverChannel<H, E> {
    type Hasher = H;

    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.commitments.push(layer_root);
    }

    fn draw_fri_alpha(&mut self) -> E {
        unimplemented!()
    }
}
