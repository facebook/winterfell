// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::FriOptions;
use math::{field::StarkField, utils::log2};

pub struct VerifierContext<B: StarkField> {
    max_degree: usize,
    domain_size: usize,
    domain_generator: B,
    options: FriOptions<B>,
    num_partitions: usize,
}

impl<B: StarkField> VerifierContext<B> {
    pub fn new(
        domain_size: usize,
        max_degree: usize,
        num_partitions: usize,
        options: FriOptions<B>,
    ) -> Self {
        let domain_generator = B::get_root_of_unity(log2(domain_size));
        VerifierContext {
            max_degree,
            domain_size,
            domain_generator,
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
