// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    evaluation_table::EvaluationTableFragment, BoundaryConstraintGroup, ConstraintEvaluationTable,
    PeriodicValueTable, StarkDomain, TraceLde,
};
use air::{
    Air, ConstraintCompositionCoefficients, ConstraintDivisor, EvaluationFrame,
    TransitionConstraintGroup,
};
use math::FieldElement;
use utils::{
    collections::{BTreeMap, Vec},
    iter_mut,
};

#[cfg(feature = "concurrent")]
use utils::{iterators::*, rayon};

// CONSTANTS
// ================================================================================================

#[cfg(feature = "concurrent")]
const MIN_CONCURRENT_DOMAIN_SIZE: usize = 8192;

// CONSTRAINT EVALUATOR
// ================================================================================================

pub struct ConstraintEvaluator<'a, A: Air, E: FieldElement<BaseField = A::BaseField>> {
    air: &'a A,
    boundary_constraints: Vec<BoundaryConstraintGroup<A::BaseField, E>>,
    transition_constraints: Vec<TransitionConstraintGroup<E>>,
    periodic_values: PeriodicValueTable<A::BaseField>,
    divisors: Vec<ConstraintDivisor<A::BaseField>>,

    #[cfg(debug_assertions)]
    transition_constraint_degrees: Vec<usize>,
}

impl<'a, A: Air, E: FieldElement<BaseField = A::BaseField>> ConstraintEvaluator<'a, A, E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new evaluator which can be used to evaluate transition and boundary constraints
    /// over extended execution trace.
    pub fn new(air: &'a A, coefficients: ConstraintCompositionCoefficients<E>) -> Self {
        // collect expected degrees for all transition constraints to compare them against actual
        // degrees; we do this in debug mode only because this comparison is expensive
        #[cfg(debug_assertions)]
        let transition_constraint_degrees = air
            .transition_constraint_degrees()
            .iter()
            .map(|d| d.get_evaluation_degree(air.trace_length()))
            .collect();

        // build transition constraint groups; these will be used later to compute a random
        // linear combination of transition constraint evaluations.
        let transition_constraints = air.get_transition_constraints(&coefficients.transition);

        // build periodic value table
        let periodic_values = PeriodicValueTable::new(air);

        // set divisor for transition constraints; all transition constraints have the same divisor
        let mut divisors = vec![air.transition_constraint_divisor()];

        // build boundary constraints and also append divisors for each group of boundary
        // constraints to the divisor list
        let mut twiddle_map = BTreeMap::new();
        let boundary_constraints = air
            .get_boundary_constraints(&coefficients.boundary)
            .into_iter()
            .map(|group| {
                divisors.push(group.divisor().clone());
                BoundaryConstraintGroup::new(group, air, &mut twiddle_map)
            })
            .collect();

        ConstraintEvaluator {
            air,
            boundary_constraints,
            transition_constraints,
            periodic_values,
            divisors,
            #[cfg(debug_assertions)]
            transition_constraint_degrees,
        }
    }

    // EVALUATOR
    // --------------------------------------------------------------------------------------------
    /// Evaluates constraints against the provided extended execution trace. Constraints are
    /// evaluated over a constraint evaluation domain. This is an optimization because constraint
    /// evaluation domain can be many times smaller than the full LDE domain.
    pub fn evaluate(
        &self,
        trace: &TraceLde<A::BaseField>,
        domain: &StarkDomain<A::BaseField>,
    ) -> ConstraintEvaluationTable<A::BaseField, E> {
        assert_eq!(
            trace.len(),
            domain.lde_domain_size(),
            "extended trace length is not consistent with evaluation domain"
        );
        // allocate space for constraint evaluations; when we are in debug mode, we also allocate
        // memory to hold all transition constraint evaluations (before they are merged into a
        // single value) so that we can check their degree late
        #[cfg(not(debug_assertions))]
        let mut evaluation_table =
            ConstraintEvaluationTable::<A::BaseField, E>::new(domain, self.divisors.clone());
        #[cfg(debug_assertions)]
        let mut evaluation_table = ConstraintEvaluationTable::<A::BaseField, E>::new(
            domain,
            self.divisors.clone(),
            self.transition_constraint_degrees.to_vec(),
        );

        // when `concurrent` feature is enabled, break the evaluation table into multiple fragments
        // to evaluate them into multiple threads; unless the constraint evaluation domain is small,
        // then don't bother with concurrent evaluation

        #[cfg(not(feature = "concurrent"))]
        let num_fragments = 1;

        #[cfg(feature = "concurrent")]
        let num_fragments = if domain.ce_domain_size() >= MIN_CONCURRENT_DOMAIN_SIZE {
            rayon::current_num_threads().next_power_of_two()
        } else {
            1
        };

        let mut fragments = evaluation_table.fragments(num_fragments);
        iter_mut!(fragments).for_each(|fragment| self.evaluate_fragment(trace, domain, fragment));

        // when in debug mode, make sure expected transition constraint degrees align with
        // actual degrees we got during constraint evaluation
        #[cfg(debug_assertions)]
        evaluation_table.validate_transition_degrees();

        evaluation_table
    }

    // EVALUATION HELPERS
    // --------------------------------------------------------------------------------------------

    /// Evaluates constraints for a single fragment of the evaluation table.
    fn evaluate_fragment(
        &self,
        trace: &TraceLde<A::BaseField>,
        domain: &StarkDomain<A::BaseField>,
        fragment: &mut EvaluationTableFragment<A::BaseField, E>,
    ) {
        // initialize buffers to hold trace values and evaluation results at each step;
        let mut ev_frame = EvaluationFrame::new(trace.width());
        let mut evaluations = vec![E::ZERO; fragment.num_columns()];
        let mut t_evaluations = vec![A::BaseField::ZERO; self.air.num_transition_constraints()];

        // pre-compute values needed to determine x coordinates in the constraint evaluation domain
        let g = domain.ce_domain_generator();
        let mut x = domain.offset() * g.exp((fragment.offset() as u64).into());

        // this will be used to convert steps in constraint evaluation domain to steps in
        // LDE domain
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();

        for i in 0..fragment.num_rows() {
            let step = i + fragment.offset();

            // update evaluation frame buffer with data from the execution trace; this will
            // read current and next rows from the trace into the buffer; data in the trace
            // table is extended over the LDE domain, so, we need to convert step in constraint
            // evaluation domain, into a step in LDE domain, in case these domains are different
            trace.read_frame_into(step << lde_shift, &mut ev_frame);

            // evaluate transition constraints and save the merged result the first slot of the
            // evaluations buffer
            evaluations[0] =
                self.evaluate_transition_constraints(&ev_frame, x, step, &mut t_evaluations);

            // when in debug mode, save transition constraint evaluations
            #[cfg(debug_assertions)]
            fragment.update_transition_evaluations(step, &t_evaluations);

            // evaluate boundary constraints; the results go into remaining slots of the
            // evaluations buffer
            self.evaluate_boundary_constraints(ev_frame.current(), x, step, &mut evaluations[1..]);

            // record the result in the evaluation table
            fragment.update_row(i, &evaluations);

            // update x to the next value
            x *= g;
        }
    }

    /// Evaluates transition constraints at the specified step of the execution trace. `step` is
    /// the step in the constraint evaluation, and `x` is the corresponding domain value. That
    /// is, x = s * g^step, where g is the generator of the constraint evaluation domain, and s
    /// is the domain offset.
    fn evaluate_transition_constraints(
        &self,
        frame: &EvaluationFrame<A::BaseField>,
        x: A::BaseField,
        step: usize,
        evaluations: &mut [A::BaseField],
    ) -> E {
        // TODO: use a more efficient way to zero out memory
        evaluations.fill(A::BaseField::ZERO);

        // get periodic values at the evaluation step
        let periodic_values = self.periodic_values.get_row(step);

        // evaluate transition constraints and save the results into evaluations buffer
        self.air
            .evaluate_transition(frame, periodic_values, evaluations);

        // merge transition constraint evaluations into a single value and return it;
        // we can do this here because all transition constraints have the same divisor.
        self.transition_constraints
            .iter()
            .fold(E::ZERO, |result, group| {
                result + group.merge_evaluations(evaluations, x)
            })
    }

    /// Evaluates all boundary constraint groups at a specific step of the execution trace.
    /// `step` is the step in the constraint evaluation domain, and `x` is the corresponding
    /// domain value. That is, x = s * g^step, where g is the generator of the constraint
    /// evaluation domain, and s is the domain offset.
    fn evaluate_boundary_constraints(
        &self,
        state: &[A::BaseField],
        x: A::BaseField,
        step: usize,
        result: &mut [E],
    ) {
        // compute the adjustment degree outside of the group so that we can re-use
        // it for groups which have the same adjustment degree
        let mut degree_adjustment = self.boundary_constraints[0].degree_adjustment;
        let mut xp = E::from(x.exp(degree_adjustment.into()));

        for (group, result) in self.boundary_constraints.iter().zip(result.iter_mut()) {
            // recompute adjustment degree only when it has changed
            if group.degree_adjustment != degree_adjustment {
                degree_adjustment = group.degree_adjustment;
                xp = E::from(x.exp(degree_adjustment.into()));
            }
            // evaluate the group and save the result
            *result = group.evaluate(state, step, x, xp);
        }
    }
}
