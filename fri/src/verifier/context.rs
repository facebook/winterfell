// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::FriOptions;
use crypto::Hasher;
use math::{
    field::{FieldElement, StarkField},
    utils::log2,
};

pub struct VerifierContext<B: StarkField, E: FieldElement + From<B>, H: Hasher> {
    max_degree: usize,
    domain_size: usize,
    domain_generator: B,
    layer_commitments: Vec<H::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
}

impl<B: StarkField, E: FieldElement + From<B>, H: Hasher> VerifierContext<B, E, H> {
    pub fn new(
        domain_size: usize,
        max_degree: usize,
        layer_commitments: Vec<H::Digest>,
        layer_alphas: Vec<E>,
        num_partitions: usize,
        options: FriOptions,
    ) -> Self {
        let domain_generator = B::get_root_of_unity(log2(domain_size));
        VerifierContext {
            max_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
        }
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    pub fn domain_generator(&self) -> B {
        self.domain_generator
    }

    pub fn domain_offset(&self) -> B {
        self.options.domain_offset()
    }

    pub fn layer_commitments(&self) -> &[H::Digest] {
        &self.layer_commitments
    }

    pub fn layer_alphas(&self) -> &[E] {
        &self.layer_alphas
    }

    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    pub fn blowup_factor(&self) -> usize {
        self.options.blowup_factor()
    }

    pub fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    pub fn num_fri_layers(&self) -> usize {
        self.options.num_fri_layers(self.domain_size)
    }
}
