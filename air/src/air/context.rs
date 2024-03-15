// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{air::TransitionConstraintDegree, ProofOptions, TraceInfo};
use alloc::vec::Vec;
use core::cmp;
use math::StarkField;

// AIR CONTEXT
// ================================================================================================
/// STARK parameters and trace properties for a specific execution of a computation.
#[derive(Clone, PartialEq, Eq)]
pub struct AirContext<B: StarkField> {
    pub(super) options: ProofOptions,
    pub(super) trace_info: TraceInfo,
    pub(super) main_transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    pub(super) aux_transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    pub(super) num_main_assertions: usize,
    pub(super) num_aux_assertions: usize,
    pub(super) ce_blowup_factor: usize,
    pub(super) trace_domain_generator: B,
    pub(super) lde_domain_generator: B,
    pub(super) num_transition_exemptions: usize,
}

impl<B: StarkField> AirContext<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [AirContext] instantiated for computations which require a single
    /// execution trace segment.
    ///
    /// The list of transition constraint degrees defines the total number of transition
    /// constraints and their expected degrees. Constraint evaluations computed by
    /// [Air::evaluate_transition()](crate::Air::evaluate_transition) function are expected to be
    /// in the order defined by this list.
    ///
    /// # Panics
    /// Panics if
    /// * `transition_constraint_degrees` is an empty vector.
    /// * `num_assertions` is zero.
    /// * Blowup factor specified by the provided `options` is too small to accommodate degrees
    ///   of the specified transition constraints.
    /// * `trace_info` describes a multi-segment execution trace.
    pub fn new(
        trace_info: TraceInfo,
        transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        num_assertions: usize,
        options: ProofOptions,
    ) -> Self {
        assert!(
            !trace_info.is_multi_segment(),
            "provided trace info describes a multi-segment execution trace"
        );
        Self::new_multi_segment(
            trace_info,
            transition_constraint_degrees,
            Vec::new(),
            num_assertions,
            0,
            options,
        )
    }

    /// Returns a new instance of [AirContext] instantiated for computations which require multiple
    /// execution trace segments.
    ///
    /// The lists of transition constraint degrees defines the total number of transition
    /// constraints and their expected degrees. Constraint evaluations computed by
    /// [Air::evaluate_transition()](crate::Air::evaluate_transition) function are expected to be
    /// in the order defined by `main_transition_constraint_degrees` list. Constraint evaluations
    /// computed by [Air::evaluate_aux_transition()](crate::Air::evaluate_aux_transition) function
    /// are expected to be in the order defined by `aux_transition_constraint_degrees` list.
    ///
    /// # Panics
    /// Panics if
    /// * `main_transition_constraint_degrees` is an empty vector.
    /// * `num_main_assertions` is zero.
    /// * `trace_info.is_multi_segment() == true` but:
    ///   - `aux_transition_constraint_degrees` is an empty vector.
    ///   - `num_aux_assertions` is zero.
    /// * `trace_info.is_multi_segment() == false` but:
    ///   - `aux_transition_constraint_degrees` is a non-empty vector.
    ///   - `num_aux_assertions` is greater than zero.
    /// * Blowup factor specified by the provided `options` is too small to accommodate degrees
    ///   of the specified transition constraints.
    pub fn new_multi_segment(
        trace_info: TraceInfo,
        main_transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        aux_transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        num_main_assertions: usize,
        num_aux_assertions: usize,
        options: ProofOptions,
    ) -> Self {
        assert!(
            !main_transition_constraint_degrees.is_empty(),
            "at least one transition constraint degree must be specified"
        );
        assert!(num_main_assertions > 0, "at least one assertion must be specified");

        if trace_info.is_multi_segment() {
            assert!(
                !aux_transition_constraint_degrees.is_empty(),
                "at least one transition constraint degree must be specified for auxiliary trace segments"
            );
            assert!(
                num_aux_assertions > 0,
                "at least one assertion must be specified against auxiliary trace segments"
            );
        } else {
            assert!(
                aux_transition_constraint_degrees.is_empty(),
                "auxiliary transition constraint degrees specified for a single-segment trace"
            );
            assert!(
                num_aux_assertions == 0,
                "auxiliary assertions specified for a single-segment trace"
            );
        }

        // determine minimum blowup factor needed to evaluate transition constraints by taking
        // the blowup factor of the highest degree constraint
        let mut ce_blowup_factor = 0;
        for degree in main_transition_constraint_degrees.iter() {
            if degree.min_blowup_factor() > ce_blowup_factor {
                ce_blowup_factor = degree.min_blowup_factor();
            }
        }

        for degree in aux_transition_constraint_degrees.iter() {
            if degree.min_blowup_factor() > ce_blowup_factor {
                ce_blowup_factor = degree.min_blowup_factor();
            }
        }

        assert!(
            options.blowup_factor() >= ce_blowup_factor,
            "blowup factor too small; expected at least {}, but was {}",
            ce_blowup_factor,
            options.blowup_factor()
        );

        let trace_length = trace_info.length();
        let lde_domain_size = trace_length * options.blowup_factor();

        AirContext {
            options,
            trace_info,
            main_transition_constraint_degrees,
            aux_transition_constraint_degrees,
            num_main_assertions,
            num_aux_assertions,
            ce_blowup_factor,
            trace_domain_generator: B::get_root_of_unity(trace_length.ilog2()),
            lde_domain_generator: B::get_root_of_unity(lde_domain_size.ilog2()),
            num_transition_exemptions: 1,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of the execution trace for an instance of a computation.
    ///
    // This is guaranteed to be a power of two greater than or equal to 8.
    pub fn trace_len(&self) -> usize {
        self.trace_info.length()
    }

    /// Returns degree of trace polynomials for an instance of a computation.
    ///
    /// The degree is always `trace_length` - 1.
    pub fn trace_poly_degree(&self) -> usize {
        self.trace_info.length() - 1
    }

    /// Returns size of the constraint evaluation domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length * ce_blowup_factor`.
    pub fn ce_domain_size(&self) -> usize {
        self.trace_info.length() * self.ce_blowup_factor
    }

    /// Returns the size of the low-degree extension domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length * lde_blowup_factor`.
    pub fn lde_domain_size(&self) -> usize {
        self.trace_info.length() * self.options.blowup_factor()
    }

    /// Returns the number of transition constraints for a computation.
    ///
    /// The number of transition constraints is defined by the total number of transition
    /// constraint degree descriptors (for both the main and the auxiliary trace constraints).
    /// This number is used to determine how many transition constraint coefficients need to be
    /// generated for merging transition constraints into a composition polynomial.
    pub fn num_transition_constraints(&self) -> usize {
        self.main_transition_constraint_degrees.len() + self.aux_transition_constraint_degrees.len()
    }

    /// Returns the number of transition constraints placed against the main trace segment.
    pub fn num_main_transition_constraints(&self) -> usize {
        self.main_transition_constraint_degrees.len()
    }

    /// Returns the number of transition constraints placed against all auxiliary trace segments.
    pub fn num_aux_transition_constraints(&self) -> usize {
        self.aux_transition_constraint_degrees.len()
    }

    /// Returns the total number of assertions defined for a computation.
    ///
    /// The number of assertions consists of the assertions placed against the main segment of an
    /// execution trace as well as assertions placed against all auxiliary trace segments.
    pub fn num_assertions(&self) -> usize {
        self.num_main_assertions + self.num_aux_assertions
    }

    /// Returns the number of rows at the end of an execution trace to which transition constraints
    /// do not apply.
    ///
    /// This is guaranteed to be at least 1 (which is the default value), but could be greater.
    /// The maximum number of exemptions is determined by a combination of transition constraint
    /// degrees and blowup factor specified for the computation.
    pub fn num_transition_exemptions(&self) -> usize {
        self.num_transition_exemptions
    }

    /// Returns the number of columns needed to store the constraint composition polynomial.
    ///
    /// This is the maximum of:
    /// 1. The maximum evaluation degree over all transition constraints minus the degree
    /// of the transition constraint divisor divided by trace length.
    /// 2. `1`, because the constraint composition polynomial requires at least one column.
    ///
    /// Since the degree of a constraint `C(x)` can be well approximated by
    /// `[constraint.base + constraint.cycles.len()] * [trace_length - 1]` the degree of the
    /// constraint composition polynomial can be approximated by:
    /// `([constraint.base + constraint.cycles.len()] * [trace_length - 1] - [trace_length - n])`
    /// where `constraint` is the constraint attaining the maximum and `n` is the number of
    /// exemption points.
    /// In the case `n = 1`, the expression simplifies to:
    /// `[constraint.base + constraint.cycles.len() - 1] * [trace_length - 1]`
    /// Thus, if each column is of length `trace_length`, we would need
    /// `[constraint.base + constraint.cycles.len() - 1]` columns to store the coefficients of
    /// the constraint composition polynomial.
    /// This means that if the highest constraint degree is equal to `5`, the constraint
    /// composition polynomial will require four columns and if the highest constraint degree is
    /// equal to `7`, it will require six columns to store.
    pub fn num_constraint_composition_columns(&self) -> usize {
        let mut highest_constraint_degree = 0_usize;
        for degree in self
            .main_transition_constraint_degrees
            .iter()
            .chain(self.aux_transition_constraint_degrees.iter())
        {
            let eval_degree = degree.get_evaluation_degree(self.trace_len());
            if eval_degree > highest_constraint_degree {
                highest_constraint_degree = eval_degree
            }
        }
        let trace_length = self.trace_len();
        let transition_divisior_degree = trace_length - self.num_transition_exemptions();

        // we use the identity: ceil(a/b) = (a + b - 1)/b
        let num_constraint_col =
            (highest_constraint_degree - transition_divisior_degree + trace_length - 1)
                / trace_length;

        cmp::max(num_constraint_col, 1)
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the number of transition exemptions for this context.
    ///
    /// # Panics
    /// Panics if:
    /// * The number of exemptions is zero.
    /// * The number of exemptions exceeds half of the trace length.
    /// * Given the combination of transition constraints degrees and the blowup factor in this
    ///   context, the number of exemptions is too larger for a valid computation of the constraint
    ///   composition polynomial.
    pub fn set_num_transition_exemptions(mut self, n: usize) -> Self {
        assert!(n > 0, "number of transition exemptions must be greater than zero");
        // exemptions which are for more than half the trace plus one are probably a mistake
        assert!(
            n <= self.trace_len() / 2 + 1,
            "number of transition exemptions cannot exceed {}, but was {}",
            self.trace_len() / 2 + 1,
            n
        );
        // make sure the composition polynomial can be computed correctly with the specified
        // number of exemptions.
        // The `ce_blowup` factor puts a ceiling on the maximal degree of a constraint composition
        // polynomial we can accommodate. On the other hand, adding exemption points reduces the
        // degree of the divisor which results in an increase of the resulting constraint composition
        // polynomial.Thus we need to check that the number of exemption points is not too large
        // given the above.
        for degree in self
            .main_transition_constraint_degrees
            .iter()
            .chain(self.aux_transition_constraint_degrees.iter())
        {
            let eval_degree = degree.get_evaluation_degree(self.trace_len());
            let max_constraint_composition_degree = self.ce_domain_size() - 1;
            let max_exemptions = max_constraint_composition_degree + self.trace_len() - eval_degree;
            assert!(
                n <= max_exemptions,
                "number of transition exemptions cannot exceed: {max_exemptions}, but was {n}"
            )
        }

        self.num_transition_exemptions = n;
        self
    }
}
