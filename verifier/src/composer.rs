// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{proof::Table, Air, DeepCompositionCoefficients, EvaluationFrame, FieldExtension};
use math::FieldElement;
use utils::collections::Vec;

// DEEP COMPOSER
// ================================================================================================

pub struct DeepComposer<E: FieldElement> {
    field_extension: FieldExtension,
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
            .map(|&p| E::from(g_lde.exp((p as u64).into()) * domain_offset))
            .collect();

        DeepComposer {
            field_extension: air.options().field_extension(),
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
    /// - In cases when the proof was generated using an extension field, we also compute
    ///   T'''_i(x) = (T_i(x) - T_i(z_conjugate)) / (x - z_conjugate), and add it to T(x) similarly
    ///   to the way described above. This is needed in order to verify that the trace is defined
    ///   over the base field, rather than the extension field.
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

        // when field extension is enabled, these will be set to conjugates of trace values at
        // z as well as conjugate of z itself. we do this only for the main trace since auxiliary
        // trace columns are in the extension field.
        let conjugate_values =
            get_conjugate_values(self.field_extension, ood_main_trace_states[0], self.z[0]);

        // compose columns of of the main trace segment
        let mut result = E::zeroed_vector(queried_main_trace_states.num_rows());
        for ((result, row), &x) in result
            .iter_mut()
            .zip(queried_main_trace_states.rows())
            .zip(&self.x_coordinates)
        {
            for (i, &value) in row.iter().enumerate() {
                let value = E::from(value);
                // compute T'_i(x) = (T_i(x) - T_i(z)) / (x - z), multiply it by a composition
                // coefficient, and add the result to T(x)
                let t1 = (value - ood_main_trace_states[0][i]) / (x - self.z[0]);
                *result += t1 * self.cc.trace[i].0;

                // compute T''_i(x) = (T_i(x) - T_i(z * g)) / (x - z * g), multiply it by a
                // composition coefficient, and add the result to T(x)
                let t2 = (value - ood_main_trace_states[1][i]) / (x - self.z[1]);
                *result += t2 * self.cc.trace[i].1;

                // when extension field is enabled compute
                // T'''_i(x) = (T_i(x) - T_i(z_conjugate)) / (x - z_conjugate)
                if let Some((z_conjugate, ref trace_at_z1_conjugates)) = conjugate_values {
                    let t3 = (value - trace_at_z1_conjugates[i]) / (x - z_conjugate);
                    *result += t3 * self.cc.trace[i].2;
                }
            }
        }

        // if the trace has auxiliary segments, compose columns from these segments as well
        if let Some(queried_aux_trace_states) = queried_aux_trace_states {
            let ood_aux_frame = ood_aux_frame.expect("missing auxiliary OOD frame");
            let ood_aux_trace_states = [ood_aux_frame.current(), ood_aux_frame.next()];

            // we define this offset here because composition of the main trace columns has
            // consumed some number of composition coefficients already.
            let cc_offset = queried_main_trace_states.num_columns();

            for ((result, row), &x) in result
                .iter_mut()
                .zip(queried_aux_trace_states.rows())
                .zip(&self.x_coordinates)
            {
                for (i, &value) in row.iter().enumerate() {
                    // compute T'_i(x) = (T_i(x) - T_i(z)) / (x - z), multiply it by a composition
                    // coefficient, and add the result to T(x)
                    let t1 = (value - ood_aux_trace_states[0][i]) / (x - self.z[0]);
                    *result += t1 * self.cc.trace[cc_offset + i].0;

                    // compute T''_i(x) = (T_i(x) - T_i(z * g)) / (x - z * g), multiply it by a
                    // composition coefficient, and add the result to T(x)
                    let t2 = (value - ood_aux_trace_states[1][i]) / (x - self.z[1]);
                    *result += t2 * self.cc.trace[cc_offset + i].1;
                }
            }
        }

        result
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

        let mut result = Vec::with_capacity(queried_evaluations.num_rows());

        // compute z^m
        let num_evaluation_columns = ood_evaluations.len() as u32;
        let z_m = self.z[0].exp(num_evaluation_columns.into());

        for (query_values, &x) in queried_evaluations.rows().zip(&self.x_coordinates) {
            let mut composition = E::ZERO;
            for (i, &evaluation) in query_values.iter().enumerate() {
                // compute H'_i(x) = (H_i(x) - H(z^m)) / (x - z^m)
                let h_i = (evaluation - ood_evaluations[i]) / (x - z_m);
                // multiply it by a pseudo-random coefficient, and add the result to H(x)
                composition += h_i * self.cc.constraints[i];
            }
            result.push(composition);
        }

        result
    }

    /// Combines trace and constraint compositions together, and also rases the degree of the
    /// resulting value by one to match trace polynomial degree. This is needed because when
    /// we divide evaluations by (x - z), (x - z * g) etc. the degree is reduced by one - so,
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

// HELPER FUNCTIONS
// ================================================================================================

/// When field extension is used, returns conjugate values of the `trace_state` and `z`;
/// otherwise, returns None.
fn get_conjugate_values<E: FieldElement>(
    extension: FieldExtension,
    trace_state: &[E],
    z: E,
) -> Option<(E, Vec<E>)> {
    if extension.is_none() {
        None
    } else {
        Some((
            z.conjugate(),
            trace_state.iter().map(|v| v.conjugate()).collect(),
        ))
    }
}
