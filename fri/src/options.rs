// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::StarkField;

// FRI OPTIONS
// ================================================================================================

#[derive(Clone)]
pub struct FriOptions {
    folding_factor: usize,
    max_remainder_size: usize,
    blowup_factor: usize,
}

impl FriOptions {
    pub fn new(blowup_factor: usize, folding_factor: usize, max_remainder_size: usize) -> Self {
        assert!(
            folding_factor == 4 || folding_factor == 8 || folding_factor == 16,
            "folding factor {} is not supported",
            folding_factor
        );
        assert!(
            max_remainder_size >= folding_factor * 2,
            "expected max remainder size to be at least {}, but was {}",
            folding_factor * 2,
            max_remainder_size
        );
        FriOptions {
            folding_factor,
            max_remainder_size,
            blowup_factor,
        }
    }

    pub fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    pub fn folding_factor(&self) -> usize {
        self.folding_factor
    }

    pub fn max_remainder_size(&self) -> usize {
        self.max_remainder_size
    }

    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor
    }

    pub fn num_fri_layers(&self, mut domain_size: usize) -> usize {
        let mut result = 0;
        while domain_size > self.max_remainder_size {
            domain_size /= self.folding_factor;
            result += 1;
        }
        result
    }

    pub fn fri_remainder_size(&self, mut domain_size: usize) -> usize {
        while domain_size > self.max_remainder_size {
            domain_size /= self.folding_factor;
        }
        domain_size
    }
}
