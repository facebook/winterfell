// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::cmp;

use super::{super::super::ProofOptions, MIN_CYCLE_LENGTH};

// TRANSITION CONSTRAINT DEGREE
// ================================================================================================
/// Degree descriptor of a transition constraint.
///
/// Describes constraint degree as a combination of multiplications of periodic and trace
/// columns. For example, degree of a constraint which requires multiplication of two trace
/// columns can be described as: `base: 2, cycles: []`. A constraint which requires
/// multiplication of 3 trace columns and a periodic column with a period of 32 steps can be
/// described as: `base: 3, cycles: [32]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionConstraintDegree {
    base: usize,
    cycles: Vec<usize>,
}

impl TransitionConstraintDegree {
    /// Creates a new transition constraint degree descriptor for constraints which involve
    /// multiplications of trace columns only.
    ///
    /// For example, if a constraint involves multiplication of two trace columns, `degree`
    /// should be set to 2. If a constraint involves multiplication of three trace columns,
    /// `degree` should be set to 3 etc.
    ///
    /// # Panics
    /// Panics if the provided `degree` is zero.
    pub fn new(degree: usize) -> Self {
        assert!(degree > 0, "transition constraint degree must be at least one, but was zero");
        TransitionConstraintDegree { base: degree, cycles: vec![] }
    }

    /// Creates a new transition degree descriptor for constraints which involve multiplication
    /// of trace columns and periodic columns.
    ///
    /// For example, if a constraint involves multiplication of two trace columns and one
    /// periodic column with a period length of 32 steps, `base_degree` should be set to 2,
    /// and `cycles` should be set to `vec![32]`.
    ///
    /// # Panics
    /// Panics if:
    /// * `base_degree` is zero.
    /// * Any of the values in the `cycles` vector is smaller than two or is not powers of two.
    pub fn with_cycles(base_degree: usize, cycles: Vec<usize>) -> Self {
        assert!(
            base_degree > 0,
            "transition constraint degree must be at least one, but was zero"
        );
        for (i, &cycle) in cycles.iter().enumerate() {
            assert!(
                cycle >= MIN_CYCLE_LENGTH,
                "cycle length must be at least {MIN_CYCLE_LENGTH}, but was {cycle} for cycle {i}"
            );
            assert!(
                cycle.is_power_of_two(),
                "cycle length must be a power of two, but was {cycle} for cycle {i}"
            );
        }
        TransitionConstraintDegree { base: base_degree, cycles }
    }

    /// Computes a degree to which this degree description expands in the context of execution
    /// trace of the specified length.
    ///
    /// The expanded degree is computed as follows:
    ///
    /// $$
    /// b \cdot (n - 1) + \sum_{i = 0}^{k - 1}{\frac{n \cdot (c_i - 1)}{c_i}}
    /// $$
    ///
    /// where: $b$ is the base degree, $n$ is the `trace_length`, $c_i$ is a cycle length of
    /// periodic column $i$, and $k$ is the total number of periodic columns for this degree
    /// descriptor.
    ///
    /// Thus, evaluation degree of a transition constraint which involves multiplication of two
    /// trace columns and one periodic column with a period length of 32 steps when evaluated
    /// over an execution trace of 64 steps would be:
    ///
    /// $$
    /// 2 \cdot (64 - 1) + \frac{64 \cdot (32 - 1)}{32} = 126 + 62 = 188
    /// $$
    pub fn get_evaluation_degree(&self, trace_length: usize) -> usize {
        let mut result = self.base * (trace_length - 1);
        for cycle_length in self.cycles.iter() {
            result += (trace_length / cycle_length) * (cycle_length - 1);
        }
        result
    }

    /// Returns a minimum blowup factor needed to evaluate constraint of this degree.
    ///
    /// This is guaranteed to be a power of two, greater than one.
    pub fn min_blowup_factor(&self) -> usize {
        // The blowup factor needs to be a power of two large enough to accommodate degree of
        // transition constraints defined by rational functions `C(x) / z(x)` where `C(x)` is the
        // constraint polynomial and `z(x)` is the transition constraint divisor.
        //
        // Degree of `C(x)` is always smaller than or equal to `[self.base + self.cycles.len()] * [trace_length - 1]`.
        // Degree of `z(x)` is `[trace_length - 1]`. Thus, the degree of `C(x) / z(x)` is
        // `[self.base + self.cycles.len() - 1] * [trace_length - 1]` and the blowup factor needed
        // to accommodate this degree can be estimated as `self.base + self.cycles.len() - 1`.
        //
        // For example, if degree of our constraints is 6, the blowup factor would need to be 8.
        // However, if the degree is 5, the blowup factor could be as small as 4.
        let degree_bound = self.base + self.cycles.len() - 1;
        cmp::max(degree_bound.next_power_of_two(), ProofOptions::MIN_BLOWUP_FACTOR)
    }
}
