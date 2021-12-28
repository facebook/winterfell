// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::cmp;
use math::FieldElement;
use utils::collections::Vec;

// CONSTANTS
// ================================================================================================

const MIN_BLOWUP_FACTOR: usize = 2;
const MIN_CYCLE_LENGTH: usize = 2;

// TRANSITION CONSTRAINT GROUP
// ================================================================================================
/// A group of transition constraints all having the same degree.
///
/// A transition constraint group does not actually store transition constraints - it stores only
/// their indexes and the info needed to compute their random linear combination. The indexes are
/// assumed to be consistent with the order in which constraint evaluations are written into the
/// `evaluation` table by the [Air::evaluate_transition()](crate::Air::evaluate_transition)
/// function.
///
/// A transition constraint is described by a rational function of the form $\frac{C(x)}{z(x)}$,
/// where:
/// * $C(x)$ is the constraint polynomial.
/// * $z(x)$ is the constraint divisor polynomial.
///
/// The divisor polynomial is the same for all transition constraints (see
/// [Air::transition_constraint_divisor()](crate::Air::transition_constraint_divisor())) and for
/// this reason is not stored in a transition constraint group.
#[derive(Clone, Debug)]
pub struct TransitionConstraintGroup<E: FieldElement> {
    degree: TransitionConstraintDegree,
    degree_adjustment: u32,
    indexes: Vec<usize>,
    coefficients: Vec<(E, E)>,
}

impl<E: FieldElement> TransitionConstraintGroup<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new transition constraint group to hold constraints of the specified degree.
    pub(super) fn new(
        degree: TransitionConstraintDegree,
        trace_poly_degree: usize,
        composition_degree: usize,
    ) -> Self {
        // We want to make sure that once we divide a constraint polynomial by its divisor, the
        // degree of the resulting polynomial will be exactly equal to the composition_degree.
        // For transition constraints, divisor degree = deg(trace). So, target degree for all
        // transitions constraints is simply: deg(composition) + deg(trace)
        let target_degree = composition_degree + trace_poly_degree;
        let evaluation_degree = degree.get_evaluation_degree(trace_poly_degree + 1);
        let degree_adjustment = (target_degree - evaluation_degree) as u32;
        TransitionConstraintGroup {
            degree,
            degree_adjustment,
            indexes: vec![],
            coefficients: vec![],
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns indexes of all constraints in this group.
    pub fn indexes(&self) -> &[usize] {
        &self.indexes
    }

    /// Returns degree descriptors for all constraints in this group.
    pub fn degree(&self) -> &TransitionConstraintDegree {
        &self.degree
    }

    /// Adds a new constraint to the group. The constraint is identified by an index in the
    /// evaluation table.
    pub fn add(&mut self, constraint_idx: usize, coefficients: (E, E)) {
        self.indexes.push(constraint_idx);
        self.coefficients.push(coefficients);
    }

    // EVALUATOR
    // --------------------------------------------------------------------------------------------
    /// Computes a linear combination of evaluations relevant to this constraint group.
    ///
    /// The linear combination is computed as follows:
    /// $$
    /// \sum_{i=0}^{k-1}{C_i(x) \cdot (\alpha_i + \beta_i \cdot x^d)}
    /// $$
    /// where:
    /// * $C_i(x)$ is the evaluation of the $i$th constraint at `x` (same as `evaluations[i]`).
    /// * $\alpha$ and $\beta$ are random field elements. In the interactive version of the
    ///   protocol, these are provided by the verifier.
    /// * $d$ is the degree adjustment factor computed as $D + (n - 1) - deg(C_i(x))$, where
    ///   $D$ is the degree of the composition polynomial, $n$ is the length of the execution
    ///   trace, and $deg(C_i(x))$ is the evaluation degree of the $i$th constraint.
    ///
    /// There are two things to note here. First, the degree adjustment factor $d$ is the same
    /// for all constraints in the group (since all constraints have the same degree). Second,
    /// the merged evaluations represent a polynomial of degree $D + n - 1$, which is higher
    /// then the target degree of the composition polynomial. This is because at this stage,
    /// we are merging only the numerators of transition constraints, and we will need to divide
    /// them by the divisor later on. The degree of the divisor for transition constraints is
    /// always $n - 1$. Thus, once we divide out the divisor, the evaluations will represent a
    /// polynomial of degree $D$.
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
}

// TRANSITION CONSTRAINT DEGREE
// ================================================================================================
/// Degree descriptor of a transition constraint.
///
/// Describes constraint degree as a combination of multiplications of periodic and trace
/// registers. For example, degree of a constraint which requires multiplication of two trace
/// registers can be described as: `base: 2, cycles: []`. A constraint which requires
/// multiplication of 3 trace registers and a periodic register with a period of 32 steps can be
/// described as: `base: 3, cycles: [32]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionConstraintDegree {
    base: usize,
    cycles: Vec<usize>,
}

impl TransitionConstraintDegree {
    /// Creates a new transition constraint degree descriptor for constraints which involve
    /// multiplications of trace registers only.
    ///
    /// For example, if a constraint involves multiplication of two trace registers, `degree`
    /// should be set to 2. If a constraint involves multiplication of three trace registers,
    /// `degree` should be set to 3 etc.
    ///
    /// # Panics
    /// Panics if the provided `degree` is zero.
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
    /// of trace registers and periodic columns.
    ///
    /// For example, if a constraint involves multiplication of two trace registers and one
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
                "cycle length must be at least {}, but was {} for cycle {}",
                MIN_CYCLE_LENGTH,
                cycle,
                i
            );
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
    /// trace registers and one periodic column with a period length of 32 steps when evaluated
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
        cmp::max(
            (self.base + self.cycles.len()).next_power_of_two(),
            MIN_BLOWUP_FACTOR,
        )
    }
}

// EVALUATION FRAME
// ================================================================================================
/// A set of execution trace rows required for evaluation of transition constraints.
///
/// In the current implementation, an evaluation frame always contains two consecutive rows of the
/// execution trace. It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
#[derive(Debug, Clone)]
pub struct EvaluationFrame<E: FieldElement> {
    current: Vec<E>,
    next: Vec<E>,
}

impl<E: FieldElement> EvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new evaluation frame instantiated with the specified number of registers.
    ///
    /// # Panics
    /// Panics if `num_registers` is zero.
    pub fn new(num_registers: usize) -> Self {
        assert!(
            num_registers > 0,
            "number of registers must be greater than zero"
        );
        EvaluationFrame {
            current: E::zeroed_vector(num_registers),
            next: E::zeroed_vector(num_registers),
        }
    }

    /// Returns a new evaluation frame instantiated from the provided rows.
    ///
    /// # Panics
    /// Panics if:
    /// * Lengths of the provided rows are zero.
    /// * Lengths of the provided rows are not the same.
    pub fn from_rows(current: Vec<E>, next: Vec<E>) -> Self {
        assert!(!current.is_empty(), "a row must contain at least one value");
        assert_eq!(
            current.len(),
            next.len(),
            "number of values in the rows must be the same"
        );
        Self { current, next }
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current row.
    #[inline(always)]
    pub fn current(&self) -> &[E] {
        &self.current
    }

    /// Returns a mutable reference to the current row.
    #[inline(always)]
    pub fn current_mut(&mut self) -> &mut [E] {
        &mut self.current
    }

    /// Returns a reference to the next row.
    #[inline(always)]
    pub fn next(&self) -> &[E] {
        &self.next
    }

    /// Returns a mutable reference to the next row.
    #[inline(always)]
    pub fn next_mut(&mut self) -> &mut [E] {
        &mut self.next
    }
}
