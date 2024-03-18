// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    super::EvaluationTableFragment, BoundaryConstraints, CompositionPolyTrace,
    ConstraintEvaluationTable, ConstraintEvaluator, PeriodicValueTable, StarkDomain, TraceLde,
};
use air::{
    Air, AuxTraceRandElements, ConstraintCompositionCoefficients, EvaluationFrame,
    LagrangeKernelBoundaryConstraint, LagrangeKernelEvaluationFrame,
    LagrangeKernelTransitionConstraints, TransitionConstraints,
};
use alloc::vec::Vec;
use math::{batch_inversion, FieldElement};
use utils::iter_mut;

#[cfg(feature = "concurrent")]
use utils::{iterators::*, rayon};

// CONSTANTS
// ================================================================================================

#[cfg(feature = "concurrent")]
const MIN_CONCURRENT_DOMAIN_SIZE: usize = 8192;

// DEFAULT CONSTRAINT EVALUATOR
// ================================================================================================

/// Default implementation of the [ConstraintEvaluator] trait.
///
/// This implementation iterates over all evaluation frames of an extended execution trace and
/// evaluates constraints over these frames one-by-one. Constraint evaluations are merged together
/// using random linear combinations and in the end, only a single column is returned.
///
/// When `concurrent` feature is enabled, the extended execution trace is split into sets of
/// sequential evaluation frames (called fragments), and frames in each fragment are evaluated
/// in separate threads.
pub struct DefaultConstraintEvaluator<'a, A: Air, E: FieldElement<BaseField = A::BaseField>> {
    air: &'a A,
    boundary_constraints: BoundaryConstraints<E>,
    transition_constraints: TransitionConstraints<E>,
    lagrange_constraints_evaluator: LagrangeConstraintsBatchEvaluator<E>,
    aux_rand_elements: AuxTraceRandElements<E>,
    periodic_values: PeriodicValueTable<E::BaseField>,
}

impl<'a, A, E> ConstraintEvaluator<E> for DefaultConstraintEvaluator<'a, A, E>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
{
    type Air = A;

    fn evaluate<T: TraceLde<E>>(
        self,
        trace: &T,
        domain: &StarkDomain<<E as FieldElement>::BaseField>,
    ) -> CompositionPolyTrace<E> {
        assert_eq!(
            trace.trace_len(),
            domain.lde_domain_size(),
            "extended trace length is not consistent with evaluation domain"
        );

        // build a list of constraint divisors; currently, all transition constraints have the same
        // divisor which we put at the front of the list; boundary constraint divisors are appended
        // after that
        let mut divisors = vec![self.transition_constraints.divisor().clone()];
        divisors.append(&mut self.boundary_constraints.get_divisors());

        // allocate space for constraint evaluations; when we are in debug mode, we also allocate
        // memory to hold all transition constraint evaluations (before they are merged into a
        // single value) so that we can check their degrees later
        #[cfg(not(debug_assertions))]
        let mut evaluation_table = ConstraintEvaluationTable::<E>::new(domain, divisors);
        #[cfg(debug_assertions)]
        let mut evaluation_table =
            ConstraintEvaluationTable::<E>::new(domain, divisors, &self.transition_constraints);

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

        // evaluate constraints for each fragment; if the trace consist of multiple segments
        // we evaluate constraints for all segments. otherwise, we evaluate constraints only
        // for the main segment.
        let mut fragments = evaluation_table.fragments(num_fragments);
        iter_mut!(fragments).for_each(|fragment| {
            if self.air.trace_info().is_multi_segment() {
                self.evaluate_fragment_full(trace, domain, fragment);
            } else {
                self.evaluate_fragment_main(trace, domain, fragment);
            }
        });

        // when in debug mode, make sure expected transition constraint degrees align with
        // actual degrees we got during constraint evaluation
        #[cfg(debug_assertions)]
        evaluation_table.validate_transition_degrees();

        // combine all evaluations into a single column
        let combined_evaluations = if self.air.context().has_lagrange_kernel_aux_column() {
            // if present, linearly combine the Lagrange kernel evaluations too
            let main_and_aux_evaluations = evaluation_table.combine();

            let lagrange_kernel_combined_evals =
                self.evaluate_lagrange_kernel_constraints(trace, domain);

            debug_assert_eq!(main_and_aux_evaluations.len(), lagrange_kernel_combined_evals.len());

            main_and_aux_evaluations
                .into_iter()
                .zip(lagrange_kernel_combined_evals)
                .map(|(eval_1, eval_2)| eval_1 + eval_2)
                .collect()
        } else {
            evaluation_table.combine()
        };

        CompositionPolyTrace::new(combined_evaluations)
    }
}

impl<'a, A, E> DefaultConstraintEvaluator<'a, A, E>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new evaluator which can be used to evaluate transition and boundary constraints
    /// over extended execution trace.
    pub fn new(
        air: &'a A,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self {
        // build transition constraint groups; these will be used to compose transition constraint
        // evaluations
        let transition_constraints =
            air.get_transition_constraints(&composition_coefficients.transition);
        // build periodic value table
        let periodic_values = PeriodicValueTable::new(air);

        // build boundary constraint groups; these will be used to evaluate and compose boundary
        // constraint evaluations.
        let boundary_constraints = BoundaryConstraints::new(
            air,
            &aux_rand_elements,
            &composition_coefficients.boundary,
            composition_coefficients.lagrange.boundary,
        );

        let lagrange_constraints_evaluator = LagrangeConstraintsBatchEvaluator::new(
            air,
            aux_rand_elements.clone(),
            composition_coefficients,
        );

        DefaultConstraintEvaluator {
            air,
            boundary_constraints,
            transition_constraints,
            lagrange_constraints_evaluator,
            aux_rand_elements,
            periodic_values,
        }
    }

    // EVALUATION HELPERS
    // --------------------------------------------------------------------------------------------

    /// Evaluates constraints for a single fragment of the evaluation table.
    ///
    /// This evaluates constraints only over the main segment of the execution trace.
    fn evaluate_fragment_main<T: TraceLde<E>>(
        &self,
        trace: &T,
        domain: &StarkDomain<A::BaseField>,
        fragment: &mut EvaluationTableFragment<E>,
    ) {
        // initialize buffers to hold trace values and evaluation results at each step;
        let mut main_frame = EvaluationFrame::new(trace.trace_info().main_trace_width());
        let mut evaluations = vec![E::ZERO; fragment.num_columns()];
        let mut t_evaluations = vec![E::BaseField::ZERO; self.num_main_transition_constraints()];

        // this will be used to convert steps in constraint evaluation domain to steps in
        // LDE domain
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();

        for i in 0..fragment.num_rows() {
            let step = i + fragment.offset();

            // update evaluation frame buffer with data from the execution trace; this will
            // read current and next rows from the trace into the buffer; data in the trace
            // table is extended over the LDE domain, so, we need to convert step in constraint
            // evaluation domain, into a step in LDE domain, in case these domains are different
            trace.read_main_trace_frame_into(step << lde_shift, &mut main_frame);

            // evaluate transition constraints and save the merged result the first slot of the
            // evaluations buffer
            evaluations[0] = self.evaluate_main_transition(&main_frame, step, &mut t_evaluations);

            // when in debug mode, save transition constraint evaluations
            #[cfg(debug_assertions)]
            fragment.update_transition_evaluations(i, &t_evaluations, &[]);

            // evaluate boundary constraints; the results go into remaining slots of the
            // evaluations buffer
            let main_state = main_frame.current();
            self.boundary_constraints.evaluate_main(
                main_state,
                domain,
                step,
                &mut evaluations[1..],
            );

            // record the result in the evaluation table
            fragment.update_row(i, &evaluations);
        }
    }

    /// Evaluates constraints for a single fragment of the evaluation table.
    ///
    /// This evaluates constraints only over all segments of the execution trace (i.e. main segment
    /// and all auxiliary segments).
    fn evaluate_fragment_full<T: TraceLde<E>>(
        &self,
        trace: &T,
        domain: &StarkDomain<A::BaseField>,
        fragment: &mut EvaluationTableFragment<E>,
    ) {
        // initialize buffers to hold trace values and evaluation results at each step
        let mut main_frame = EvaluationFrame::new(trace.trace_info().main_trace_width());
        let mut aux_frame = EvaluationFrame::new(trace.trace_info().aux_trace_width());
        let mut tm_evaluations = vec![E::BaseField::ZERO; self.num_main_transition_constraints()];
        let mut ta_evaluations = vec![E::ZERO; self.num_aux_transition_constraints()];
        let mut evaluations = vec![E::ZERO; fragment.num_columns()];

        // this will be used to convert steps in constraint evaluation domain to steps in
        // LDE domain
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();

        for i in 0..fragment.num_rows() {
            let step = i + fragment.offset();

            // read both the main and the auxiliary evaluation frames from the trace
            trace.read_main_trace_frame_into(step << lde_shift, &mut main_frame);
            trace.read_aux_trace_frame_into(step << lde_shift, &mut aux_frame);

            // evaluate transition constraints and save the merged result the first slot of the
            // evaluations buffer; we evaluate and compose constraints in the same function, we
            // can just add up the results of evaluating main and auxiliary constraints.
            evaluations[0] = self.evaluate_main_transition(&main_frame, step, &mut tm_evaluations);

            evaluations[0] +=
                self.evaluate_aux_transition(&main_frame, &aux_frame, step, &mut ta_evaluations);

            // when in debug mode, save transition constraint evaluations
            #[cfg(debug_assertions)]
            fragment.update_transition_evaluations(i, &tm_evaluations, &ta_evaluations);

            // evaluate boundary constraints; the results go into remaining slots of the
            // evaluations buffer
            let main_state = main_frame.current();
            let aux_state = aux_frame.current();
            self.boundary_constraints.evaluate_all(
                main_state,
                aux_state,
                domain,
                step,
                &mut evaluations[1..],
            );

            // record the result in the evaluation table
            fragment.update_row(i, &evaluations);
        }
    }

    fn evaluate_lagrange_kernel_constraints<T: TraceLde<E>>(
        &self,
        trace: &T,
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E> {
        let lagrange_kernel_aux_column_idx = self
            .air
            .context()
            .lagrange_kernel_aux_column_idx()
            .expect("expected Lagrange kernel aux column index to be present");

        // this will be used to convert steps in constraint evaluation domain to steps in
        // LDE domain
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();

        let mut lagrange_kernel_column_frames =
            vec![LagrangeKernelEvaluationFrame::<E>::new_empty(); domain.ce_domain_size()];

        for (step, frame) in lagrange_kernel_column_frames.iter_mut().enumerate() {
            trace.read_lagrange_kernel_frame_into(
                step << lde_shift,
                lagrange_kernel_aux_column_idx,
                frame,
            );
        }

        let num_trans_constraints = self.air.context().trace_len().ilog2() as usize;

        self.lagrange_constraints_evaluator.evaluate_lagrange_kernel_constraints::<A>(
            num_trans_constraints,
            lagrange_kernel_column_frames,
            domain,
        )
    }

    // TRANSITION CONSTRAINT EVALUATORS
    // --------------------------------------------------------------------------------------------

    /// Evaluates transition constraints of the main execution trace at the specified step of the
    /// constraint evaluation domain.
    ///
    /// `x` is the corresponding domain value at the specified step. That is, x = s * g^step,
    /// where g is the generator of the constraint evaluation domain, and s is the domain offset.
    fn evaluate_main_transition(
        &self,
        main_frame: &EvaluationFrame<E::BaseField>,
        step: usize,
        evaluations: &mut [E::BaseField],
    ) -> E {
        // TODO: use a more efficient way to zero out memory
        evaluations.fill(E::BaseField::ZERO);

        // get periodic values at the evaluation step
        let periodic_values = self.periodic_values.get_row(step);

        // evaluate transition constraints over the main segment of the execution trace and save
        // the results into evaluations buffer
        self.air.evaluate_transition(main_frame, periodic_values, evaluations);

        // merge transition constraint evaluations into a single value and return it;
        // we can do this here because all transition constraints have the same divisor.
        evaluations
            .iter()
            .zip(self.transition_constraints.main_constraint_coef().iter())
            .fold(E::ZERO, |acc, (&const_eval, &coef)| acc + coef.mul_base(const_eval))
    }

    /// Evaluates all transition constraints (i.e., for main and auxiliary trace segments) at the
    /// specified step of the constraint evaluation domain.
    ///
    /// `x` is the corresponding domain value at the specified step. That is, x = s * g^step,
    /// where g is the generator of the constraint evaluation domain, and s is the domain offset.
    fn evaluate_aux_transition(
        &self,
        main_frame: &EvaluationFrame<E::BaseField>,
        aux_frame: &EvaluationFrame<E>,
        step: usize,
        evaluations: &mut [E],
    ) -> E {
        // TODO: use a more efficient way to zero out memory
        evaluations.fill(E::ZERO);

        // get periodic values at the evaluation step
        let periodic_values = self.periodic_values.get_row(step);

        // evaluate transition constraints over auxiliary trace segments and save the results into
        // evaluations buffer
        self.air.evaluate_aux_transition(
            main_frame,
            aux_frame,
            periodic_values,
            &self.aux_rand_elements,
            evaluations,
        );

        // merge transition constraint evaluations into a single value and return it;
        // we can do this here because all transition constraints have the same divisor.
        evaluations
            .iter()
            .zip(self.transition_constraints.aux_constraint_coef().iter())
            .fold(E::ZERO, |acc, (&const_eval, &coef)| acc + coef * const_eval)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of transition constraints applied against the main segment of the
    /// execution trace.
    fn num_main_transition_constraints(&self) -> usize {
        self.transition_constraints.num_main_constraints()
    }

    /// Returns the number of transition constraints applied against all auxiliary trace segments.
    fn num_aux_transition_constraints(&self) -> usize {
        self.transition_constraints.num_aux_constraints()
    }
}

// LAGRANGE CONSTRAINTS BATCH EVALUATOR
// ================================================================================================

/// Contains a specific strategy for evaluating the Lagrange kernel boundary and transition
/// constraints where the divisors' evaluation is batched.
///
/// Specifically, [`batch_inversion`] is used to reduce the number of divisions performed.
struct LagrangeConstraintsBatchEvaluator<E: FieldElement> {
    lagrange_kernel_boundary_constraint: Option<LagrangeKernelBoundaryConstraint<E>>,
    lagrange_kernel_transition_constraints: Option<LagrangeKernelTransitionConstraints<E>>,
    aux_rand_elements: AuxTraceRandElements<E>,
}

impl<E: FieldElement> LagrangeConstraintsBatchEvaluator<E> {
    /// Constructs a new [`LagrangeConstraintsBatchEvaluator`].
    pub fn new<A: Air>(
        air: &A,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self
    where
        E: FieldElement<BaseField = A::BaseField>,
    {
        let lagrange_kernel_transition_constraints =
            air.context().lagrange_kernel_aux_column_idx().map(|_| {
                LagrangeKernelTransitionConstraints::new(
                    air.context(),
                    composition_coefficients.lagrange.transition,
                )
            });
        let lagrange_kernel_boundary_constraint = composition_coefficients.lagrange.boundary.map(
            |lagrange_kernel_boundary_coefficient| {
                let lagrange_kernel_aux_rand_elements = aux_rand_elements.get_segment_elements(0);

                LagrangeKernelBoundaryConstraint::new(
                    lagrange_kernel_boundary_coefficient,
                    lagrange_kernel_aux_rand_elements,
                )
            },
        );

        Self {
            lagrange_kernel_boundary_constraint,
            lagrange_kernel_transition_constraints,
            aux_rand_elements,
        }
    }

    /// Evaluates the transition and boundary constraints. Specifically, the constraint evaluations
    /// are divided by their corresponding divisors, and the resulting terms are linearly combined
    /// using the composition coefficients.
    ///
    /// Returns a buffer with the same length as the CE domain, where each element contains the
    /// constraint evaluations (as explained above) at the corresponding domain point.
    pub fn evaluate_lagrange_kernel_constraints<A>(
        &self,
        num_trans_constraints: usize,
        lagrange_kernel_column_frames: Vec<LagrangeKernelEvaluationFrame<E>>,
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let transition_constraint_combined_evaluations = self
            .evaluate_combined_transition_constraints::<A>(
                num_trans_constraints,
                &lagrange_kernel_column_frames,
                domain,
            );

        let boundary_constraint_combined_evaluations: Vec<E> = self
            .evaluate_combined_boundary_constraints::<A>(&lagrange_kernel_column_frames, domain);

        // combine boundary and transition constraint combined evaluations
        transition_constraint_combined_evaluations
            .into_iter()
            .zip(boundary_constraint_combined_evaluations)
            .map(|(transitions_combined, boundaries_combined)| {
                transitions_combined + boundaries_combined
            })
            .collect()
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Evaluate the transition constraints where the divisors' evaluations are batched to reduce
    /// the number of divisions performed (which has a big effect on performance).
    ///
    /// This algorithm takes advantage of some structure in the divisors' evaluations. Recall that
    /// the divisor for the i'th transition constraint is `x^(2^i) - 1`. When substituting `x` for
    /// each value of the constraint evaluation domain, for constraints `i>0`, the divisor
    /// evaluations "wrap-around" such that some values repeat. For example,
    /// i=0: no repetitions
    /// i=1: the first half of the buffer is equal to the second half
    /// i=2: each 1/4th of the buffer are equal
    /// i=3: each 1/8th of the buffer are equal
    /// ...
    /// Therefore, we only compute the non-repeating section of the buffer in each iteration, and index
    /// into it accordingly.
    fn evaluate_combined_transition_constraints<A>(
        &self,
        num_trans_constraints: usize,
        lagrange_kernel_column_frames: &[LagrangeKernelEvaluationFrame<E>],
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let lagrange_kernel_transition_constraints = self
            .lagrange_kernel_transition_constraints
            .as_ref()
            .expect("expected Lagrange kernel transition constraints to be present");

        let mut combined_evaluations_acc = E::zeroed_vector(domain.ce_domain_size());
        let mut denominators: Vec<E> = Vec::with_capacity(domain.ce_domain_size());

        for trans_constraint_idx in 0..num_trans_constraints {
            let num_non_repeating_denoms =
                domain.ce_domain_size() / 2_usize.pow(trans_constraint_idx as u32);

            for step in 0..num_non_repeating_denoms {
                let domain_point = domain.get_ce_x_at(step);
                let denominator = lagrange_kernel_transition_constraints
                    .evaluate_ith_divisor(trans_constraint_idx, domain_point);
                denominators.push(denominator);
            }
            let denominators_inv = batch_inversion(&denominators);

            for step in 0..domain.ce_domain_size() {
                let numerator = lagrange_kernel_transition_constraints.evaluate_ith_numerator(
                    &lagrange_kernel_column_frames[step],
                    self.aux_rand_elements.get_segment_elements(0),
                    trans_constraint_idx,
                );
                combined_evaluations_acc[step] +=
                    numerator * denominators_inv[step % denominators_inv.len()];
            }

            denominators.truncate(0);
        }

        combined_evaluations_acc
    }

    /// Evaluate the boundary constraint where the divisors' evaluations are batched to reduce the
    /// number of divisions performed (which has a big effect on performance).
    fn evaluate_combined_boundary_constraints<A>(
        &self,
        lagrange_kernel_column_frames: &[LagrangeKernelEvaluationFrame<E>],
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let mut boundary_numerator_evals = Vec::with_capacity(domain.ce_domain_size());
        let mut boundary_denominator_evals = Vec::with_capacity(domain.ce_domain_size());

        for (step, frame) in lagrange_kernel_column_frames.iter().enumerate() {
            let domain_point = domain.get_ce_x_at(step);

            {
                let constraint = self
                    .lagrange_kernel_boundary_constraint
                    .as_ref()
                    .expect("expected Lagrange boundary constraint to be present");

                let boundary_numerator = constraint.evaluate_numerator_at(frame);
                boundary_numerator_evals.push(boundary_numerator);

                let boundary_denominator = constraint.evaluate_denominator_at(domain_point.into());
                boundary_denominator_evals.push(boundary_denominator);
            }
        }

        let boundary_denominators_inv = batch_inversion(&boundary_denominator_evals);

        boundary_numerator_evals
            .into_iter()
            .zip(boundary_denominators_inv)
            .map(|(numerator, denom_inv)| numerator * denom_inv)
            .collect()
    }
}
