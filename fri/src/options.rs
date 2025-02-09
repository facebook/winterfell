// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::StarkField;

// FRI OPTIONS
// ================================================================================================

/// FRI protocol config options for proof generation and verification.
#[derive(Clone, PartialEq, Eq)]
pub struct FriOptions {
    folding_factor: usize,
    remainder_max_degree: usize,
    blowup_factor: usize,
}

impl FriOptions {
    /// Returns a new [FriOptions] struct instantiated with the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// - `blowup_factor` is not a power of two.
    /// - `folding_factor` is not 2, 4, 8, or 16.
    pub fn new(blowup_factor: usize, folding_factor: usize, remainder_max_degree: usize) -> Self {
        // TODO: change panics to errors
        assert!(
            blowup_factor.is_power_of_two(),
            "blowup factor must be a power of two, but was {blowup_factor}"
        );
        assert!(
            folding_factor == 2
                || folding_factor == 4
                || folding_factor == 8
                || folding_factor == 16,
            "folding factor {folding_factor} is not supported"
        );
        FriOptions {
            folding_factor,
            remainder_max_degree,
            blowup_factor,
        }
    }

    /// Returns the offset by which the evaluation domain is shifted.
    ///
    /// The domain is shifted by multiplying every element in the domain by this offset.
    ///
    /// Currently, the offset is hard-coded to be the primitive element in the field specified by
    /// type parameter `B`.
    pub fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    /// Returns the factor by which the degree of a polynomial is reduced with each FRI layer.
    ///
    /// In combination with `remainder_max_degree_plus_1` this property defines how many FRI layers
    /// are needed for an evaluation domain of a given size.
    pub fn folding_factor(&self) -> usize {
        self.folding_factor
    }

    /// Returns maximum allowed remainder polynomial degree.
    ///
    /// In combination with `folding_factor` this property defines how many FRI layers are needed
    /// for an evaluation domain of a given size.
    pub fn remainder_max_degree(&self) -> usize {
        self.remainder_max_degree
    }

    /// Returns a blowup factor of the evaluation domain.
    ///
    /// Specifically, if the polynomial for which the FRI protocol is executed is of degree `d`
    /// where `d` is one less than a power of two, then the evaluation domain size will be
    /// equal to `(d + 1) * blowup_factor`.
    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor
    }

    /// Computes and return the number of FRI layers required for a domain of the specified size.
    ///
    /// The number of layers for a given domain size is defined by the `folding_factor` and
    /// `remainder_max_degree` and `blowup_factor` settings.
    pub fn num_fri_layers(&self, mut domain_size: usize) -> usize {
        let mut result = 0;
        let max_remainder_size = (self.remainder_max_degree + 1) * self.blowup_factor;
        while domain_size > max_remainder_size {
            domain_size /= self.folding_factor;
            result += 1;
        }
        result
    }
}
