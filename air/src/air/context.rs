// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::cmp;

use math::StarkField;

use crate::{air::TransitionConstraintDegree, ProofOptions, TraceInfo};

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
    pub(super) lagrange_kernel_aux_column_idx: Option<usize>,
    pub(super) ce_blowup_factor: usize,
    pub(super) trace_domain_generator: B,
    pub(super) lde_domain_generator: B,
    pub(super) num_transition_exemptions: usize,
    pub(super) trace_length_ext: usize,
    pub(super) zk_parameters: Option<ZkParameters>,
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
            None,
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
        lagrange_kernel_aux_column_idx: Option<usize>,
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
                "at least one transition constraint degree must be specified for the auxiliary trace segment"
                );
            assert!(
                num_aux_assertions > 0,
                "at least one assertion must be specified against the auxiliary trace segment"
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

        // validate Lagrange kernel aux column, if any
        if let Some(lagrange_kernel_aux_column_idx) = lagrange_kernel_aux_column_idx {
            assert!(
            lagrange_kernel_aux_column_idx == trace_info.get_aux_segment_width() - 1,
            "Lagrange kernel column should be the last column of the auxiliary trace: index={}, but aux trace width is {}",
            lagrange_kernel_aux_column_idx, trace_info.get_aux_segment_width()
            );
        }

        let h = options.zk_witness_randomizer_degree().unwrap_or(0);
        let trace_length = trace_info.length();
        let trace_length_ext = (trace_length + h as usize).next_power_of_two();
        let zk_blowup = trace_length_ext / trace_length;
        let lde_domain_size = trace_length_ext * options.blowup_factor();
        // equation (12) in https://eprint.iacr.org/2024/1037
        let h_q = options.num_queries() + 1;
        let zk_parameters = if options.is_zk() {
            Some(ZkParameters {
                degree_witness_randomizer: h as usize,
                degree_constraint_randomizer: h_q,
                zk_blowup_witness: zk_blowup,
            })
        } else {
            None
        };

        // determine minimum blowup factor needed to evaluate transition constraints by taking
        // the blowup factor of the highest degree constraint
        let mut ce_blowup_factor = 0;
        for degree in main_transition_constraint_degrees.iter() {
            if degree.min_blowup_factor(trace_length, trace_length_ext) > ce_blowup_factor {
                ce_blowup_factor = degree.min_blowup_factor(trace_length, trace_length_ext);
            }
        }

        for degree in aux_transition_constraint_degrees.iter() {
            if degree.min_blowup_factor(trace_length, trace_length_ext) > ce_blowup_factor {
                ce_blowup_factor = degree.min_blowup_factor(trace_length, trace_length_ext);
            }
        }

        assert!(
            options.blowup_factor() >= ce_blowup_factor,
            "blowup factor too small; expected at least {}, but was {}",
            ce_blowup_factor,
            options.blowup_factor()
        );

        AirContext {
            options,
            trace_info,
            main_transition_constraint_degrees,
            aux_transition_constraint_degrees,
            num_main_assertions,
            num_aux_assertions,
            lagrange_kernel_aux_column_idx,
            ce_blowup_factor,
            trace_domain_generator: B::get_root_of_unity(trace_length.ilog2()),
            lde_domain_generator: B::get_root_of_unity(lde_domain_size.ilog2()),
            num_transition_exemptions: 1,
            trace_length_ext,
            zk_parameters,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the trace info for an instance of a computation.
    pub fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    /// Returns length of the execution trace for an instance of a computation.
    ///
    /// This is guaranteed to be a power of two greater than or equal to 8.
    pub fn trace_len(&self) -> usize {
        self.trace_info.length()
    }

    /// Returns length of the possibly extended execution trace. This is the same as the original
    /// trace length when zero-knowledge is not enabled.
    pub fn trace_length_ext(&self) -> usize {
        self.trace_length_ext
    }

    /// Returns degree of trace polynomials for an instance of a computation.
    ///
    /// The degree is always `trace_length_ext` - 1.
    pub fn trace_poly_degree(&self) -> usize {
        self.trace_length_ext() - 1
    }

    /// Returns size of the constraint evaluation domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length_ext * ce_blowup_factor`.
    pub fn ce_domain_size(&self) -> usize {
        self.trace_length_ext() * self.ce_blowup_factor
    }

    /// Returns the size of the low-degree extension domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length_ext * lde_blowup_factor`.
    pub fn lde_domain_size(&self) -> usize {
        self.trace_length_ext() * self.options.blowup_factor()
    }

    /// Returns the number of transition constraints for a computation, excluding the Lagrange
    /// kernel transition constraints, which are managed separately.
    ///
    /// The number of transition constraints is defined by the total number of transition constraint
    /// degree descriptors (for both the main and the auxiliary trace constraints). This number is
    /// used to determine how many transition constraint coefficients need to be generated for
    /// merging transition constraints into a constraint composition polynomial.
    pub fn num_transition_constraints(&self) -> usize {
        self.main_transition_constraint_degrees.len() + self.aux_transition_constraint_degrees.len()
    }

    /// Returns the number of transition constraints placed against the main trace segment.
    pub fn num_main_transition_constraints(&self) -> usize {
        self.main_transition_constraint_degrees.len()
    }

    /// Returns the number of transition constraints placed against the auxiliary trace segment.
    pub fn num_aux_transition_constraints(&self) -> usize {
        self.aux_transition_constraint_degrees.len()
    }

    /// Returns the index of the auxiliary column which implements the Lagrange kernel, if any
    pub fn lagrange_kernel_aux_column_idx(&self) -> Option<usize> {
        self.lagrange_kernel_aux_column_idx
    }

    /// Returns true if the auxiliary trace segment contains a Lagrange kernel column
    pub fn has_lagrange_kernel_aux_column(&self) -> bool {
        self.lagrange_kernel_aux_column_idx().is_some()
    }

    /// Returns the total number of assertions defined for a computation, excluding the Lagrange
    /// kernel assertion, which is managed separately.
    ///
    /// The number of assertions consists of the assertions placed against the main segment of an
    /// execution trace as well as assertions placed against the auxiliary trace segment.
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
    /// 1. The maximum evaluation degree over all transition constraints minus the degree of the
    ///    transition constraint divisor divided by trace length.
    /// 2. `1`, because the constraint composition polynomial requires at least one column.
    ///
    /// Since the degree of a constraint `C(x)` can be computed as
    ///
    ///   `[constraint.base + constraint.cycles.len()] * [trace_length - 1]`
    ///
    /// the degree of the constraint composition polynomial can be computed as:
    ///
    ///   `([constraint.base + constraint.cycles.len()] * [trace_length - 1] - [trace_length - n])`
    ///
    /// where `constraint` is the constraint attaining the maximum and `n` is the number of
    /// exemption points. In the case `n = 1`, the expression simplifies to:
    ///
    ///   `[constraint.base + constraint.cycles.len() - 1] * [trace_length - 1]`
    ///
    /// Thus, if each column is of length `trace_length`, we would need
    ///
    ///   `[constraint.base + constraint.cycles.len() - 1]`
    ///
    /// columns to store the coefficients of the constraint composition polynomial. This means that
    /// if the highest constraint degree is equal to `5`, the constraint composition polynomial will
    /// require four columns and if the highest constraint degree is equal to `7`, it will require
    /// six columns to store.
    ///
    /// Note that the Lagrange kernel constraints require only 1 column, since the degree of the
    /// numerator is `trace_len - 1` for all transition constraints (i.e. the base degree is 1).
    /// Hence, no matter what the degree of the divisor is for each, the degree of the fraction will
    /// be at most `trace_len - 1`.
    ///
    /// TODO: update documentation
    pub fn num_constraint_composition_columns(&self) -> usize {
        let mut highest_constraint_degree = 0_usize;
        for degree in self
            .main_transition_constraint_degrees
            .iter()
            .chain(self.aux_transition_constraint_degrees.iter())
        {
            let eval_degree =
                degree.get_evaluation_degree(self.trace_len(), self.trace_length_ext());
            if eval_degree > highest_constraint_degree {
                highest_constraint_degree = eval_degree
            }
        }
        let trace_length = self.trace_len();
        let trace_length_ext = self.trace_length_ext();
        let transition_divisior_degree = trace_length - self.num_transition_exemptions();

        let num_constraint_col =
            (highest_constraint_degree - transition_divisior_degree).div_ceil(trace_length_ext);

        if self.zk_parameters.is_some() {
            let quotient_degree = if highest_constraint_degree < trace_length_ext {
                // This means that our transition constraints have degree 1 and hence the boundary
                // constraints will determine the degree
                trace_length_ext - 2
            } else {
                highest_constraint_degree - transition_divisior_degree
            };
            let n_q = self.options.num_queries();
            let den = self.trace_length_ext() - (n_q + 1);

            (quotient_degree + 1).div_ceil(den)
        } else {
            cmp::max(num_constraint_col, 1)
        }
    }

    pub fn constraint_composition_degree(&self) -> usize {
        let mut highest_constraint_degree = 0_usize;
        for degree in self
            .main_transition_constraint_degrees
            .iter()
            .chain(self.aux_transition_constraint_degrees.iter())
        {
            let eval_degree =
                degree.get_evaluation_degree(self.trace_len(), self.trace_length_ext());
            if eval_degree > highest_constraint_degree {
                highest_constraint_degree = eval_degree
            }
        }
        let trace_length = self.trace_len();
        let transition_divisior_degree = trace_length - self.num_transition_exemptions();

        //   highest_constraint_degree - transition_divisior_degree
        if highest_constraint_degree < self.trace_length_ext {
            // This means that our transition constraints have degree 1 and hence the boundary
            // constraints will determine the degree
            self.trace_length_ext - 2
        } else {
            highest_constraint_degree - transition_divisior_degree
        }
    }

    pub fn num_coefficients_chunk_quotient(&self) -> usize {
        if self.zk_parameters().is_some() {
            let num_constraint_composition_cols = self.num_constraint_composition_columns();
            let quotient_degree = self.constraint_composition_degree();

            (quotient_degree + 1).div_ceil(num_constraint_composition_cols)
        } else {
            self.trace_len()
        }
    }

    pub fn zk_parameters(&self) -> Option<ZkParameters> {
        self.zk_parameters
    }

    pub fn zk_blowup_factor(&self) -> usize {
        self.zk_parameters()
            .map(|parameters| parameters.zk_blowup_witness())
            .unwrap_or(1)
    }

    pub fn zk_witness_randomizer_degree(&self) -> usize {
        self.zk_parameters()
            .map(|parameters| parameters.degree_witness_randomizer())
            .unwrap_or(0)
    }

    pub fn zk_constraint_randomizer_degree(&self) -> usize {
        self.zk_parameters()
            .map(|parameters| parameters.degree_constraint_randomizer())
            .unwrap_or(0)
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
            let eval_degree =
                degree.get_evaluation_degree(self.trace_len(), self.trace_length_ext());
            let max_constraint_composition_degree = self.ce_domain_size() - 1;
            let max_exemptions =
                max_constraint_composition_degree + self.trace_length_ext() - eval_degree;
            assert!(
                n <= max_exemptions,
                "number of transition exemptions cannot exceed: {max_exemptions}, but was {n}"
            )
        }

        self.num_transition_exemptions = n;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkParameters {
    degree_witness_randomizer: usize,
    degree_constraint_randomizer: usize,
    zk_blowup_witness: usize,
}

impl ZkParameters {
    pub fn degree_witness_randomizer(&self) -> usize {
        self.degree_witness_randomizer
    }

    pub fn degree_constraint_randomizer(&self) -> usize {
        self.degree_constraint_randomizer
    }

    pub fn zk_blowup_witness(&self) -> usize {
        self.zk_blowup_witness
    }
}
