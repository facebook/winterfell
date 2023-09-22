// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::fri_schedule::FoldingSchedule;
use math::StarkField;

// FRI OPTIONS
// ================================================================================================

/// FRI protocol config options for proof generation and verification.
#[derive(Clone, PartialEq, Eq)]
pub struct FriOptions {
    folding_schedule: FoldingSchedule,
    blowup_factor: usize,
}

impl FriOptions {
    /// Returns a new [FriOptions] struct instantiated with the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// - `blowup_factor` is not a power of two.
    /// - `folding_factor` is not 2, 4, 8, or 16.
    pub fn new(blowup_factor: usize, folding_schedule: FoldingSchedule) -> Self {
        // TODO: change panics to errors
        assert!(
            blowup_factor.is_power_of_two(),
            "blowup factor must be a power of two, but was {blowup_factor}"
        );

        match &folding_schedule {
            FoldingSchedule::Constant {
                fri_folding_factor,
                fri_remainder_max_degree: _,
            } => {
                assert!(
                    *fri_folding_factor == 2
                        || *fri_folding_factor == 4
                        || *fri_folding_factor == 8
                        || *fri_folding_factor == 16,
                    "folding factor {fri_folding_factor} is not supported"
                );
            }
            FoldingSchedule::Dynamic { schedule } => {
                assert!(
                    schedule.iter().all(|factor| factor.is_power_of_two()),
                    "FRI folding factors must be powers of 2"
                );
                assert!(!schedule.is_empty(), "FRI folding schedule cannot be empty");
            }
        }

        FriOptions {
            folding_schedule,
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
    /// In combination with `remainder_max_degree_plus_1` this property defines how many FRI layers are
    /// needed for an evaluation domain of a given size.
    pub fn folding_factor(&self) -> Option<usize> {
        self.folding_schedule
            .get_factor()
            .map(|factor| factor as usize)
    }

    /// Returns maximum allowed remainder polynomial degree.
    ///
    /// In combination with `folding_factor` this property defines how many FRI layers are needed
    /// for an evaluation domain of a given size.
    pub fn remainder_max_degree(&self) -> Option<usize> {
        self.folding_schedule
            .get_max_remainder_degree()
            .map(|degree| degree as usize)
    }

    /// Returns a blowup factor of the evaluation domain.
    ///
    /// Specifically, if the polynomial for which the FRI protocol is executed is of degree `d`
    /// where `d` is one less than a power of two, then the evaluation domain size will be
    /// equal to `(d + 1) * blowup_factor`.
    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor
    }

    pub fn get_schedule(&self) -> &FoldingSchedule {
        &self.folding_schedule
    }

    /// Computes and returns the number of FRI layers required for a domain of the specified size.
    ///
    /// The number of layers for a given domain size is determined based on the folding schedule:
    /// - For a `Constant` schedule, the number of layers is defined by the `fri_folding_factor`,
    ///   `fri_remainder_max_degree`, and `blowup_factor` settings.
    /// - For a `Dynamic` schedule, it's simply the length of the custom folding schedule.
    ///
    /// Note that for a `Constant` schedule, the domain size is progressively reduced by the folding
    /// factor until it is less than or equal to the threshold defined by
    /// `(fri_remainder_max_degree + 1) * blowup_factor`.
    pub fn num_fri_layers(&self, mut domain_size: usize) -> usize {
        match self.get_schedule() {
            FoldingSchedule::Constant {
                fri_folding_factor,
                fri_remainder_max_degree,
            } => {
                let mut result = 0;
                let max_remainder_size =
                    (*fri_remainder_max_degree as usize + 1) * self.blowup_factor();
                while domain_size > max_remainder_size {
                    domain_size /= *fri_folding_factor as usize;
                    result += 1;
                }
                result
            }
            FoldingSchedule::Dynamic { schedule } => schedule.len(),
        }
    }
}
