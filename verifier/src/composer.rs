// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{proof::Table, Air, DeepCompositionCoefficients, EvaluationFrame};
use math::{batch_inversion, FieldElement};
use utils::collections::Vec;

// DEEP COMPOSER
// ================================================================================================

pub struct DeepComposer<E: FieldElement> {
    cc: DeepCompositionCoefficients<E>,
    x_coordinates: Vec<E>,
    z: [E; 2],
}

impl<E: FieldElement> DeepComposer<E> {
    /// Creates a new composer for computing DEEP composition polynomial values.
    pub fn new<A: Air<BaseField = E::BaseField>>(
        air: &A,
        query_positions: &[usize],
        z: E,
        cc: DeepCompositionCoefficients<E>,
    ) -> Self {
        // compute LDE domain coordinates for all query positions
        let g_lde = air.lde_domain_generator();
        let domain_offset = air.domain_offset();
        let x_coordinates: Vec<E> = query_positions
            .iter()
            .map(|&p| E::from(g_lde.exp_vartime((p as u64).into()) * domain_offset))
            .collect();

        DeepComposer {
            cc,
            x_coordinates,
            z: [z, z * E::from(air.trace_domain_generator())],
        }
    }

    /// For each queried trace state, combines column values into a single value by computing
    /// their random linear combinations as follows:
    ///
    /// - Assume each column value is an evaluation of a trace polynomial T_i(x).
    /// - For each T_i(x) compute T'_i(x) = (T_i(x) - T_i(z)) / (x - z) and
    ///   T''_i = (T_i(x) - T_i(z * g)) / (x - z * g), where z is the out-of-domain point and
    ///   g is the generation of the LDE domain.
    /// - Then, combine all T'_i(x) and T''_i(x) values together by computing
    ///   T(x) = sum(T'_i(x) * cc'_i + T''_i(x) * cc''_i) for all i, where cc'_i and cc''_i are
    ///   the coefficients for the random linear combination drawn from the public coin.
    ///
    /// Note that values of T_i(z) and T_i(z * g) are received from the prover and passed into
    /// this function via the `ood_frame` parameter.
    pub fn compose_trace_columns(
        &self,
        queried_main_trace_states: Table<E::BaseField>,
        queried_aux_trace_states: Option<Table<E>>,
        ood_main_frame: EvaluationFrame<E>,
        ood_aux_frame: Option<EvaluationFrame<E>>,
    ) -> Vec<E> {
        let ood_main_trace_states = [ood_main_frame.current(), ood_main_frame.next()];

        // compose columns of of the main trace segment; we do this separately for numerators of
        // each query; we also track common denominator for each query separately; this way we can
        // use a batch inversion in the end.
        let n = queried_main_trace_states.num_rows();
        let mut result_num = Vec::<E>::with_capacity(n);
        let mut result_den = Vec::<E>::with_capacity(n);

        for ((_, row), &x) in (0..n)
            .zip(queried_main_trace_states.rows())
            .zip(&self.x_coordinates)
        {
            let mut t1_num = E::ZERO;
            let mut t2_num = E::ZERO;

            for (i, &value) in row.iter().enumerate() {
                let value = E::from(value);
                // compute the numerator of T'_i(x) as (T_i(x) - T_i(z)), multiply it by a
                // composition coefficient, and add the result to the numerator aggregator
                t1_num += (value - ood_main_trace_states[0][i]) * self.cc.trace[i].0;

                // compute the numerator of T''_i(x) as (T_i(x) - T_i(z * g)), multiply it by a
                // composition coefficient, and add the result to the numerator aggregator
                t2_num += (value - ood_main_trace_states[1][i]) * self.cc.trace[i].1;
            }
            // compute the common denominator as (x - z) * (x - z * g)
            let t1_den = x - self.z[0];
            let t2_den = x - self.z[1];
            result_den.push(t1_den * t2_den);

            // add the numerators of T'_i(x) and T''_i(x) together; we can do this because later on
            // we'll use the common denominator computed above.
            result_num.push(t1_num * t2_den + t2_num * t1_den);
        }

        // if the trace has auxiliary segments, compose columns from these segments as well; we
        // also do this separately for numerators and denominators.
        if let Some(queried_aux_trace_states) = queried_aux_trace_states {
            let ood_aux_frame = ood_aux_frame.expect("missing auxiliary OOD frame");
            let ood_aux_trace_states = [ood_aux_frame.current(), ood_aux_frame.next()];

            // we define this offset here because composition of the main trace columns has
            // consumed some number of composition coefficients already.
            let cc_offset = queried_main_trace_states.num_columns();

            for ((j, row), &x) in (0..n)
                .zip(queried_aux_trace_states.rows())
                .zip(&self.x_coordinates)
            {
                let mut t1_num = E::ZERO;
                let mut t2_num = E::ZERO;
                for (i, &value) in row.iter().enumerate() {
                    // compute the numerator of T'_i(x) as (T_i(x) - T_i(z)), multiply it by a
                    // composition coefficient, and add the result to the numerator aggregator
                    t1_num += (value - ood_aux_trace_states[0][i]) * self.cc.trace[cc_offset + i].0;

                    // compute the numerator of T''_i(x) as (T_i(x) - T_i(z * g)), multiply it by a
                    // composition coefficient, and add the result to the numerator aggregator
                    t2_num += (value - ood_aux_trace_states[1][i]) * self.cc.trace[cc_offset + i].1;
                }

                // compute the common denominators (x - z) and (x - z * g), and use the to aggregate
                // numerators into the common numerator computed for the main trace of this query
                let t1_den = x - self.z[0];
                let t2_den = x - self.z[1];
                result_num[j] += t1_num * t2_den + t2_num * t1_den;
            }
        }

        result_den = batch_inversion(&result_den);
        result_num
            .iter()
            .zip(result_den)
            .map(|(n, d)| *n * d)
            .collect()
    }

    /// For each queried set of composition polynomial column evaluations, combine evaluations
    /// into a single value by computing their random linear combination as follows:
    ///
    /// - Assume each queried value is an evaluation of a composition polynomial column H_i(x).
    /// - For each H_i(x), compute H'_i(x) = (H_i(x) - H(z^m)) / (x - z^m), where m is the total
    ///   number of composition polynomial columns.
    /// - Then, combine all H_i(x) values together by computing H(x) = sum(H_i(x) * cc_i) for
    ///   all i, where cc_i is the coefficient for the random linear combination drawn from the
    ///   public coin.
    ///
    /// Note that values of H_i(z^m)are received from teh prover and passed into this function
    /// via the `ood_evaluations` parameter.
    pub fn compose_constraint_evaluations(
        &self,
        queried_evaluations: Table<E>,
        ood_evaluations: Vec<E>,
    ) -> Vec<E> {
        assert_eq!(queried_evaluations.num_rows(), self.x_coordinates.len());

        let n = queried_evaluations.num_rows();
        let mut result_num = Vec::<E>::with_capacity(n);
        let mut result_den = Vec::<E>::with_capacity(n);

        // compute z^m
        let num_evaluation_columns = ood_evaluations.len() as u32;
        let z_m = self.z[0].exp_vartime(num_evaluation_columns.into());

        // combine composition polynomial columns separately for numerators and denominators;
        // this way we can use batch inversion in the end.
        for (query_values, &x) in queried_evaluations.rows().zip(&self.x_coordinates) {
            let mut composition_num = E::ZERO;
            for (i, &evaluation) in query_values.iter().enumerate() {
                // compute the numerator of H'_i(x) as (H_i(x) - H_i(z^m)), multiply it by a
                // composition coefficient, and add the result to the numerator aggregator
                composition_num += (evaluation - ood_evaluations[i]) * self.cc.constraints[i];
            }
            result_num.push(composition_num);
            result_den.push(x - z_m);
        }

        result_den = batch_inversion(&result_den);
        result_num
            .iter()
            .zip(result_den)
            .map(|(n, d)| *n * d)
            .collect()
    }

    /// Combines trace and constraint compositions together, and also rases the degree of the
    /// resulting value by one to match trace polynomial degree. This is needed because when
    /// we divide evaluations by (x - z) and (x - z * g) the degree is reduced by one - so,
    /// we compensate for it here.
    #[rustfmt::skip]
    pub fn combine_compositions(&self, t_composition: Vec<E>, c_composition: Vec<E>) -> Vec<E> {
        assert_eq!(t_composition.len(), self.x_coordinates.len());
        assert_eq!(c_composition.len(), self.x_coordinates.len());

        let mut result = Vec::with_capacity(self.x_coordinates.len());
        for ((&x, t), c) in self.x_coordinates.iter().zip(t_composition).zip(c_composition) {
            // compute C(x) by adding the two compositions together
            let composition = t + c;

            // raise the degree of C(x) by computing C'(x) = C(x) * (cc_0 + x * cc_1), where
            // cc_0 and cc_1 are the coefficients for the random linear combination drawn from
            // the public coin.
            result.push(composition * (self.cc.degree.0 + x * self.cc.degree.1));
        }

        result
    }
}
