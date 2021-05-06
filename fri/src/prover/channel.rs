// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::PublicCoin;
use crypto::Hasher;
use std::{convert::TryInto, mem::size_of};

// PROVER CHANNEL TRAIT
// ================================================================================================

pub trait ProverChannel: PublicCoin {
    fn commit_fri_layer(&mut self, layer_root: <<Self as PublicCoin>::Hasher as Hasher>::Digest);
}

// DEFAULT PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

pub struct DefaultProverChannel<H: Hasher> {
    commitments: Vec<H::Digest>,
    domain_size: usize,
    num_queries: usize,
}

impl<H: Hasher> DefaultProverChannel<H> {
    pub fn new(domain_size: usize, num_queries: usize) -> Self {
        DefaultProverChannel {
            commitments: Vec::new(),
            domain_size,
            num_queries,
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
}

impl<H: Hasher> ProverChannel for DefaultProverChannel<H> {
    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.commitments.push(layer_root);
    }
}

impl<H: Hasher> PublicCoin for DefaultProverChannel<H> {
    type Hasher = H;

    fn fri_layer_commitments(&self) -> &[H::Digest] {
        &self.commitments
    }
}
