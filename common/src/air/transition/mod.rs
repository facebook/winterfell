// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::cmp;
use math::field::FieldElement;

// CONSTANTS
// ================================================================================================

const MIN_BLOWUP_FACTOR: usize = 2;

// TRANSITION CONSTRAINT GROUP
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransitionConstraintGroup<E: FieldElement> {
    degree: TransitionConstraintDegree,
    degree_adjustment: u32,
    indexes: Vec<usize>,
    coefficients: Vec<(E, E)>,
}

impl<E: FieldElement> TransitionConstraintGroup<E> {
    /// Creates a new transition constraint group to hold constraints of the specified degree.
    pub fn new(degree: TransitionConstraintDegree, degree_adjustment: u32) -> Self {
        TransitionConstraintGroup {
            degree,
            degree_adjustment,
            indexes: vec![],
            coefficients: vec![],
        }
    }

    /// Returns degree descriptor for all constraints in this constraint group.
    pub fn degree(&self) -> &TransitionConstraintDegree {
        &self.degree
    }

    /// Computes a linear combination of evaluations relevant to this constraint group.
    pub fn merge_evaluations<B>(&self, evaluations: &[B], x: B) -> E
    where
        B: FieldElement,
        E: From<B>,
    {
        // compute degree adjustment factor for this group
        let xp = E::from(x.exp(self.degree_adjustment.into()));

        // compute linear combination of evaluations as D(x) * (cc_0 + cc_1 * x^p), where D(x)
        // is an evaluation of a particular constraint, and x^p is the degree adjustment factor
        let mut result = E::ZERO;
        for (&constraint_idx, coefficients) in self.indexes.iter().zip(self.coefficients.iter()) {
            let evaluation = E::from(evaluations[constraint_idx]);
            result += evaluation * (coefficients.0 + coefficients.1 * xp);
        }
        result
    }

    /// Adds a new constraint to the group. The constraint is identified by an index in the
    /// evaluation vector.
    pub fn add(&mut self, constraint_idx: usize, coefficients: (E, E)) {
        self.indexes.push(constraint_idx);
        self.coefficients.push(coefficients);
    }
}

// TRANSITION CONSTRAINT DEGREE
// ================================================================================================

/// Describes constraint degree as a combination of multiplications of periodic and trace
/// registers. For example, degree of a constraint which requires multiplication of two trace
/// registers, and a periodic register with a period of 32 steps can be represented as:
///   base: 2
///   cycles: [32]
#[derive(Clone, Debug)]
pub struct TransitionConstraintDegree {
    base: usize,
    cycles: Vec<usize>,
}

impl TransitionConstraintDegree {
    /// Creates a new transition degree descriptor for constraints which involve multiplications
    /// of regular trace registers. For example, if a constraint involves multiplication of two
    /// trace registers, `degree` should be set to 2.
    pub fn new(degree: usize) -> Self {
        assert!(
            degree > 0,
            "transition constraint degree must be at least one, but was zero"
        );
        TransitionConstraintDegree {
            base: degree,
            cycles: vec![],
        }
    }

    /// Creates a new transition degree descriptor for constraints which involve multiplication
    /// of regular trace registers and periodic columns. For example, if a constraint involves
    /// multiplication of two regular trace registers and one periodic column with a cycle length
    /// of 32 steps, `base_degree` should be set to 2, and `cycles` = vec![32].
    pub fn with_cycles(base_degree: usize, cycles: Vec<usize>) -> Self {
        assert!(
            base_degree > 0,
            "transition constraint degree must be at least one, but was zero"
        );
        for (i, cycle) in cycles.iter().enumerate() {
            assert!(
                cycle.is_power_of_two(),
                "cycle length must be a power of two, but was {} for cycle {}",
                cycle,
                i
            );
        }
        TransitionConstraintDegree {
            base: base_degree,
            cycles,
        }
    }

    /// Computes a degree to which this degree description expands in the context of execution
    /// trace of the specified length.
    pub fn get_evaluation_degree(&self, trace_length: usize) -> usize {
        let mut result = self.base * (trace_length - 1);
        for cycle_length in self.cycles.iter() {
            result += (trace_length / cycle_length) * (cycle_length - 1);
        }
        result
    }

    /// Returns a minimum blowup factor needed to evaluate constraint of this degree. Is
    /// guaranteed to be a power of two, greater than one.
    pub fn min_blowup_factor(&self) -> usize {
        cmp::max(
            (self.base + self.cycles.len()).next_power_of_two(),
            MIN_BLOWUP_FACTOR,
        )
    }
}

// EVALUATION FRAME
// ================================================================================================

pub struct EvaluationFrame<E: FieldElement> {
    pub current: Vec<E>,
    pub next: Vec<E>,
}

impl<E: FieldElement> EvaluationFrame<E> {
    pub fn new(num_registers: usize) -> Self {
        EvaluationFrame {
            current: E::zeroed_vector(num_registers),
            next: E::zeroed_vector(num_registers),
        }
    }
}
