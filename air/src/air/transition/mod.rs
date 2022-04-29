// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{AirContext, BTreeMap, ConstraintDivisor, ExtensionOf, FieldElement, Vec};

mod frame;
pub use frame::EvaluationFrame;

mod degree;
pub use degree::TransitionConstraintDegree;

// CONSTANTS
// ================================================================================================

const MIN_CYCLE_LENGTH: usize = 2;

// TRANSITION CONSTRAINT INFO
// ================================================================================================
/// Metadata for transition constraints of a computation.
///
/// This metadata includes:
/// - List of transition constraint degrees for the main trace segment, as well as for auxiliary
///   trace segments (if any).
/// - Groupings of constraints by their degree, separately for the main trace segment and for
///   auxiliary tace segment.
/// - Divisor of transition constraints for a computation.
pub struct TransitionConstraints<E: FieldElement> {
    main_constraints: Vec<TransitionConstraintGroup<E>>,
    main_constraint_degrees: Vec<TransitionConstraintDegree>,
    aux_constraints: Vec<TransitionConstraintGroup<E>>,
    aux_constraint_degrees: Vec<TransitionConstraintDegree>,
    divisor: ConstraintDivisor<E::BaseField>,
}

impl<E: FieldElement> TransitionConstraints<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [TransitionConstraints] for a computation described by the
    /// specified AIR context.
    ///
    /// # Panics
    /// Panics if the number of transition constraints in the context does not match the number of
    /// provided composition coefficients.
    pub fn new(context: &AirContext<E::BaseField>, composition_coefficients: &[(E, E)]) -> Self {
        assert_eq!(
            context.num_transition_constraints(),
            composition_coefficients.len(),
            "number of transition constraints must match the number of composition coefficient tuples"
        );

        // build constraint divisor; the same divisor applies to all transition constraints
        let divisor = ConstraintDivisor::from_transition(
            context.trace_len(),
            context.num_transition_exemptions(),
        );

        // group constraints by their degree, separately for constraints against main and auxiliary
        // trace segments

        let (main_constraint_coefficients, aux_constraint_coefficients) =
            composition_coefficients.split_at(context.main_transition_constraint_degrees.len());

        let main_constraint_degrees = context.main_transition_constraint_degrees.clone();
        let main_constraints = group_constraints(
            &main_constraint_degrees,
            context,
            main_constraint_coefficients,
            divisor.degree(),
        );
        let aux_constraint_degrees = context.aux_transition_constraint_degrees.clone();
        let aux_constraints = group_constraints(
            &aux_constraint_degrees,
            context,
            aux_constraint_coefficients,
            divisor.degree(),
        );

        Self {
            main_constraints,
            main_constraint_degrees,
            aux_constraints,
            aux_constraint_degrees,
            divisor,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns transition constraint info for constraints applied against the main trace segment
    /// of a computation grouped by constraint degree.
    pub fn main_constraints(&self) -> &[TransitionConstraintGroup<E>] {
        &self.main_constraints
    }

    /// Returns a list of transition constraint degree descriptors for the main trace segment of
    /// a computation.
    ///
    /// This list will be identical to the list passed into the [AirContext::new()] method as
    /// the `transition_constraint_degrees` parameter, or into [AirContext::new_multi_segment()]
    /// as the `main_transition_constraint_degrees` parameter.
    pub fn main_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.main_constraint_degrees
    }

    /// Returns the number of constraints applied against the main trace segment of a computation.
    pub fn num_main_constraints(&self) -> usize {
        self.main_constraint_degrees.len()
    }

    /// Returns transition constraint info for constraints applied against auxiliary trace segments
    /// of a computation grouped by constraint degree.
    pub fn aux_constraints(&self) -> &[TransitionConstraintGroup<E>] {
        &self.aux_constraints
    }

    /// Returns a list of transition constraint degree descriptors for auxiliary trace segments of
    /// a computation.
    ///
    /// This list will be identical to the list passed into [AirContext::new_multi_segment()]
    /// as the `aux_transition_constraint_degrees` parameter.
    pub fn aux_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.aux_constraint_degrees
    }

    /// Returns the number of constraints applied against auxiliary trace segments of a
    /// computation.
    pub fn num_aux_constraints(&self) -> usize {
        self.aux_constraint_degrees.len()
    }

    /// Returns a divisor for transition constraints.
    ///
    /// All transition constraints have the same divisor which has the form:
    /// $$
    /// z(x) = \frac{x^n - 1}{x - g^{n - 1}}
    /// $$
    /// where: $n$ is the length of the execution trace and $g$ is the generator of the trace
    /// domain.
    ///
    /// This divisor specifies that transition constraints must hold on all steps of the
    /// execution trace except for the last one.
    pub fn divisor(&self) -> &ConstraintDivisor<E::BaseField> {
        &self.divisor
    }

    // CONSTRAINT COMPOSITION
    // --------------------------------------------------------------------------------------------

    /// Computes a linear combination of all transition constraint evaluations and divides the
    /// result by transition constraint divisor.
    ///
    /// A transition constraint is described by a rational function of the form $\frac{C(x)}{z(x)}$,
    /// where:
    /// * $C(x)$ is the constraint polynomial.
    /// * $z(x)$ is the constraint divisor polynomial.
    ///
    /// Thus, this function computes a linear combination of $C(x)$ evaluations. For more detail on
    ///  how this linear combination is computed refer to [TransitionConstraintGroup::merge_evaluations].
    ///
    /// Since, the divisor polynomial is the same for all transition constraints (see
    /// [ConstraintDivisor::from_transition]), we can divide the linear combination by the
    /// divisor rather than dividing each individual $C(x)$ evaluation. This requires executing only
    /// one division at the end.
    pub fn combine_evaluations<F>(&self, main_evaluations: &[F], aux_evaluations: &[E], x: F) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        // merge constraint evaluations for the main trace segment
        let mut result = self.main_constraints().iter().fold(E::ZERO, |acc, group| {
            acc + group.merge_evaluations::<F, F>(main_evaluations, x)
        });

        // merge constraint evaluations for auxiliary trace segments (if any)
        if self.num_aux_constraints() > 0 {
            result += self.aux_constraints().iter().fold(E::ZERO, |acc, group| {
                acc + group.merge_evaluations::<F, E>(aux_evaluations, x)
            });
        }

        // divide out the evaluation of divisor at x and return the result
        let z = E::from(self.divisor.evaluate_at(x));
        result / z
    }
}

// TRANSITION CONSTRAINT GROUP
// ================================================================================================
/// A group of transition constraints all having the same degree.
///
/// A transition constraint group does not actually store transition constraints - it stores only
/// their indexes and the info needed to compute their random linear combination. The indexes are
/// assumed to be consistent with the order in which constraint evaluations are written into the
/// `evaluation` table by the [Air::evaluate_transition()](crate::Air::evaluate_transition) or
/// [Air::evaluate_aux_transition()](crate::Air::evaluate_aux_transition) function.
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
        trace_length: usize,
        composition_degree: usize,
        divisor_degree: usize,
    ) -> Self {
        // We want to make sure that once we divide a constraint polynomial by its divisor, the
        // degree of the resulting polynomial will be exactly equal to the composition_degree.
        let target_degree = composition_degree + divisor_degree;
        let evaluation_degree = degree.get_evaluation_degree(trace_length);
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
    pub fn merge_evaluations<B, F>(&self, evaluations: &[F], x: B) -> E
    where
        B: FieldElement,
        F: FieldElement<BaseField = B::BaseField> + ExtensionOf<B>,
        E: FieldElement<BaseField = B::BaseField> + ExtensionOf<B> + ExtensionOf<F>,
    {
        // compute degree adjustment factor for this group
        let xp = x.exp(self.degree_adjustment.into());

        // compute linear combination of evaluations as D(x) * (cc_0 + cc_1 * x^p), where D(x)
        // is an evaluation of a particular constraint, and x^p is the degree adjustment factor
        let mut result = E::ZERO;
        for (&constraint_idx, coefficients) in self.indexes.iter().zip(self.coefficients.iter()) {
            let evaluation = evaluations[constraint_idx];
            result += (coefficients.0 + coefficients.1.mul_base(xp)).mul_base(evaluation);
        }
        result
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Groups transition constraints by their degree.
fn group_constraints<E: FieldElement>(
    degrees: &[TransitionConstraintDegree],
    context: &AirContext<E::BaseField>,
    coefficients: &[(E, E)],
    divisor_degree: usize,
) -> Vec<TransitionConstraintGroup<E>> {
    // iterate over transition constraint degrees, and assign each constraint to the appropriate
    // group based on its degree
    let mut groups = BTreeMap::new();
    for (i, degree) in degrees.iter().enumerate() {
        let evaluation_degree = degree.get_evaluation_degree(context.trace_len());
        let group = groups.entry(evaluation_degree).or_insert_with(|| {
            TransitionConstraintGroup::new(
                degree.clone(),
                context.trace_len(),
                context.composition_degree(),
                divisor_degree,
            )
        });
        group.add(i, coefficients[i]);
    }

    // convert from hash map into a vector and return
    groups.into_iter().map(|e| e.1).collect()
}
