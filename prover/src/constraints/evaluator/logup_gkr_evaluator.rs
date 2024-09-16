// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{
    Air, AuxRandElements, ConstraintCompositionCoefficients, EvaluationFrame,
    LagrangeKernelEvaluationFrame, LogUpGkrEvaluator, TransitionConstraints,
};
use math::FieldElement;
use tracing::instrument;
use utils::iter_mut;
#[cfg(feature = "concurrent")]
use utils::{iterators::*, rayon};

use super::{
    super::EvaluationTableFragment,
    logup_gkr::{LagrangeKernelTransitionConstraintsDivisor, LogUpGkrConstraintsEvaluator},
    BoundaryConstraints, CompositionPolyTrace, ConstraintEvaluationTable, ConstraintEvaluator,
    PeriodicValueTable, StarkDomain, TraceLde,
};
use crate::constraints::evaluator::logup_gkr::compute_s_col_divisor;

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
pub struct LogUpGkrConstraintEvaluator<'a, A: Air, E: FieldElement<BaseField = A::BaseField>> {
    air: &'a A,
    boundary_constraints: BoundaryConstraints<E>,
    transition_constraints: TransitionConstraints<E>,
    periodic_values: PeriodicValueTable<E::BaseField>,
    logup_gkr_constraints_evaluator: LogUpGkrConstraintsEvaluator<E>,
    aux_rand_elements: AuxRandElements<E>,
}

impl<'a, A, E> ConstraintEvaluator<E> for LogUpGkrConstraintEvaluator<'a, A, E>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
{
    type Air = A;

    #[instrument(
        skip_all,
        name = "evaluate_constraints",
        fields(
            ce_domain_size = %domain.ce_domain_size()
        )
    )]
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

        let lagrange_constraints_divisors = LagrangeKernelTransitionConstraintsDivisor::<E>::new(
            self.logup_gkr_constraints_evaluator
                .lagrange_kernel_constraints
                .transition
                .num_constraints(),
            domain,
        );
        let s_col_constraint_divisor = compute_s_col_divisor::<E>(domain, self.air.trace_length());

        let boundary_divisors_inv =
            self.logup_gkr_constraints_evaluator.compute_boundary_divisors_inv(domain);

        // allocate space for constraint evaluations; when we are in debug mode, we also allocate
        // memory to hold all transition constraint evaluations (before they are merged into a
        // single value) so that we can check their degrees later
        #[cfg(not(debug_assertions))]
        let mut evaluation_table = ConstraintEvaluationTable::<E>::new(domain, divisors, true);
        #[cfg(debug_assertions)]
        let mut evaluation_table = ConstraintEvaluationTable::<E>::new(
            domain,
            divisors,
            &self.transition_constraints,
            true,
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

        // evaluate constraints for each fragment; if the trace consist of multiple segments
        // we evaluate constraints for all segments. otherwise, we evaluate constraints only
        // for the main segment.
        let mut fragments = evaluation_table.fragments(num_fragments);
        iter_mut!(fragments).for_each(|fragment| {
            self.evaluate_fragment_full(
                trace,
                domain,
                fragment,
                &lagrange_constraints_divisors,
                &boundary_divisors_inv,
                &s_col_constraint_divisor,
            );
        });

        // when in debug mode, make sure expected transition constraint degrees align with
        // actual degrees we got during constraint evaluation
        #[cfg(debug_assertions)]
        evaluation_table.validate_transition_degrees();

        CompositionPolyTrace::new(evaluation_table.combine())
    }
}

impl<'a, A, E> LogUpGkrConstraintEvaluator<'a, A, E>
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
        aux_rand_elements: AuxRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self {
        assert!(
            air.context().logup_gkr_enabled(),
            "`LogUpGkrConstraintEvaluator` can only be used when LogUp-GKR is enabled"
        );

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
            Some(&aux_rand_elements),
            &composition_coefficients.boundary,
        );

        let logup_gkr_constraints_evaluator = LogUpGkrConstraintsEvaluator::new(
            air,
            aux_rand_elements
                .gkr_data()
                .expect("expected LogUp-GKR randomness to be present"),
            composition_coefficients
                .lagrange
                .expect("expected Lagrange kernel composition coefficients to be present"),
            composition_coefficients
                .s_col
                .expect("expected s-column composition coefficient to be present"),
        );
        air.trace_info();

        Self {
            air,
            boundary_constraints,
            transition_constraints,
            logup_gkr_constraints_evaluator,
            aux_rand_elements,
            periodic_values,
        }
    }

    // EVALUATION HELPER
    // --------------------------------------------------------------------------------------------

    /// Evaluates constraints for a single fragment of the evaluation table.
    ///
    /// This evaluates constraints only over all segments of the execution trace (i.e. main segment
    /// and all auxiliary segments).
    fn evaluate_fragment_full<T: TraceLde<E>>(
        &self,
        trace: &T,
        domain: &StarkDomain<A::BaseField>,
        fragment: &mut EvaluationTableFragment<E>,
        trans_constraints_divisors: &LagrangeKernelTransitionConstraintsDivisor<E>,
        boundary_divisors_inv: &[E],
        s_col_constraint_divisor: &[E::BaseField],
    ) {
        // initialize buffers to hold trace values and evaluation results at each step
        let mut main_frame = EvaluationFrame::new(trace.trace_info().main_segment_width());
        let mut aux_frame = EvaluationFrame::new(trace.trace_info().aux_segment_width());
        let mut tm_evaluations = vec![E::BaseField::ZERO; self.num_main_transition_constraints()];
        let mut ta_evaluations = vec![E::ZERO; self.num_aux_transition_constraints()];
        let mut evaluations = vec![E::ZERO; fragment.num_columns()];
        let frame_length = trace.trace_info().length().ilog2() as usize + 1;
        let mut lagrange_frame = LagrangeKernelEvaluationFrame::new_empty(frame_length);

        let evaluator = self.air.get_logup_gkr_evaluator();
        let mut query = vec![E::BaseField::ZERO; evaluator.get_oracles().len()];

        // this will be used to convert steps in constraint evaluation domain to steps in
        // LDE domain
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();

        for i in 0..fragment.num_rows() {
            let step = i + fragment.offset();

            // read both the main and the auxiliary evaluation frames from the trace
            trace.read_main_trace_frame_into(step << lde_shift, &mut main_frame);
            trace.read_lagrange_kernel_frame_into(
                step << lde_shift,
                self.logup_gkr_constraints_evaluator.l_col_idx,
                &mut lagrange_frame,
            );
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

            // evaluate Lagrange kernel constraints and assign them to the last column
            *evaluations.last_mut().expect("should contain at least one entry") = self
                .evaluate_s_column_transition(
                    &evaluator,
                    &main_frame,
                    &aux_frame,
                    &mut query,
                    s_col_constraint_divisor[step % (domain.trace_to_ce_blowup())],
                );
            // evaluate s-column constraints and add them to the last column
            *evaluations.last_mut().expect("should contain at least one entry") += self
                .evaluate_lagrange_transition(
                    &lagrange_frame,
                    step,
                    trans_constraints_divisors,
                    boundary_divisors_inv,
                );

            // evaluate boundary constraints; the results go into remaining slots of the
            // evaluations buffer
            let main_state = main_frame.current();
            let aux_state = aux_frame.current();
            let limit = evaluations.len() - 1;
            self.boundary_constraints.evaluate_all(
                main_state,
                aux_state,
                domain,
                step,
                &mut evaluations[1..limit],
            );

            // record the result in the evaluation table
            fragment.update_row(i, &evaluations);
        }
    }

    // TRANSITION CONSTRAINT EVALUATOR
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

    /// Evaluates all transition constraints (i.e., for main and the auxiliary trace segment) at the
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

        // evaluate transition constraints over the auxiliary trace segment and save the results into
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
        let evaluation = evaluations
            .iter()
            .zip(self.transition_constraints.aux_constraint_coef().iter())
            .fold(E::ZERO, |acc, (&const_eval, &coef)| acc + coef * const_eval);

        evaluation
    }

    /// Computes the transition and boundary constraints for the Lagrange kernel.
    fn evaluate_lagrange_transition(
        &self,
        lagrange_frame: &LagrangeKernelEvaluationFrame<E>,
        step: usize,
        trans_constraints_divisors: &LagrangeKernelTransitionConstraintsDivisor<E>,
        boundary_divisors_inv: &[E],
    ) -> E {
        // Compute the combined transition and boundary constraints evaluations for this row
        let lagrange_combined_evaluations = {
            let mut combined_evaluations = E::ZERO;

            // combine transition constraints
            for trans_constraint_idx in 0..self
                .logup_gkr_constraints_evaluator
                .lagrange_kernel_constraints
                .transition
                .num_constraints()
            {
                let numerator = self
                    .logup_gkr_constraints_evaluator
                    .lagrange_kernel_constraints
                    .transition
                    .evaluate_ith_numerator(
                        &lagrange_frame,
                        &self.logup_gkr_constraints_evaluator.gkr_data.lagrange_kernel_eval_point,
                        trans_constraint_idx,
                    );
                let inv_divisor =
                    trans_constraints_divisors.get_inverse_divisor_eval(trans_constraint_idx, step);

                combined_evaluations += numerator * inv_divisor;
            }

            // combine boundary constraints
            {
                let boundary_numerator = self
                    .logup_gkr_constraints_evaluator
                    .lagrange_kernel_constraints
                    .boundary
                    .evaluate_numerator_at(&lagrange_frame);

                combined_evaluations += boundary_numerator * boundary_divisors_inv[step];
            }

            combined_evaluations
        };

        lagrange_combined_evaluations
    }

    /// Computes the transition constraints for the s-column.
    ///
    /// The s-column implements the cohomological sum-check argument of [1] and
    /// the constraint we enfore is exactly Eq (4) in Lemma 1 in [1].
    ///
    /// [1]: https://eprint.iacr.org/2021/930
    fn evaluate_s_column_transition(
        &self,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        main_frame: &EvaluationFrame<E::BaseField>,
        aux_frame: &EvaluationFrame<E>,
        query: &mut [E::BaseField],
        divisor_at_step: E::BaseField,
    ) -> E {
        let l_col_idx = self.logup_gkr_constraints_evaluator.l_col_idx;
        let s_col_idx = self.logup_gkr_constraints_evaluator.s_col_idx;
        let mean = self.logup_gkr_constraints_evaluator.mean;

        let l_cur = aux_frame.current()[l_col_idx];
        let s_cur = aux_frame.current()[s_col_idx];
        let s_nxt = aux_frame.next()[s_col_idx];

        evaluator.build_query(&main_frame, query);
        let batched_query =
            self.logup_gkr_constraints_evaluator.gkr_data.compute_batched_query(&query);

        let rhs = s_cur - mean + batched_query * l_cur;
        let lhs = s_nxt;

        let s_col_combined_evaluation = (rhs - lhs)
            * self
                .logup_gkr_constraints_evaluator
                .s_col_composition_coefficient
                .mul_base(divisor_at_step);
        s_col_combined_evaluation
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of transition constraints applied against the main segment of the
    /// execution trace.
    fn num_main_transition_constraints(&self) -> usize {
        self.transition_constraints.num_main_constraints()
    }

    /// Returns the number of transition constraints applied against the auxiliary trace segment.
    fn num_aux_transition_constraints(&self) -> usize {
        self.transition_constraints.num_aux_constraints()
    }
}
