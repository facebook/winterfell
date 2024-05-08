// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use super::{constraints::CompositionPoly, StarkDomain, TracePolyTable};
use air::{proof::TraceOodFrame, DeepCompositionCoefficients};
use alloc::vec::Vec;
use math::{
    add_in_place, fft, mul_acc,
    polynom::{self, syn_div_roots_in_place},
    ExtensionOf, FieldElement, StarkField,
};
use utils::iter_mut;

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// DEEP COMPOSITION POLYNOMIAL
// ================================================================================================
pub struct DeepCompositionPoly<E: FieldElement> {
    coefficients: Vec<E>,
    cc: DeepCompositionCoefficients<E>,
    z: E,
}

impl<E: FieldElement> DeepCompositionPoly<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new DEEP composition polynomial. Initially, this polynomial will be empty, and
    /// the intent is to populate the coefficients via add_trace_polys() and add_constraint_polys()
    /// methods.
    pub fn new(z: E, cc: DeepCompositionCoefficients<E>) -> Self {
        DeepCompositionPoly {
            coefficients: vec![],
            cc,
            z,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of the DEEP composition polynomial.
    pub fn poly_size(&self) -> usize {
        self.coefficients.len()
    }

    /// Returns the degree of the composition polynomial.
    pub fn degree(&self) -> usize {
        polynom::degree_of(&self.coefficients)
    }

    // TRACE POLYNOMIAL COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Combines all trace polynomials into a single polynomial and saves the result into
    /// the DEEP composition polynomial. The combination is done as follows:
    ///
    /// - Compute polynomials T'_i(x) = (T_i(x) - T_i(z)) / (x - z) and
    ///   T''_i(x) = (T_i(x) - T_i(z * g)) / (x - z * g) for all i, where T_i(x) is a trace
    ///   polynomial for column i.
    /// - Then, combine together all T'_i(x) and T''_i(x) polynomials using a random linear
    ///   combination as T(x) = sum((T'_i(x) + T''_i(x)) * cc_i) for all i, where cc_i is
    ///   the coefficient for the random linear combination drawn from the public coin.
    /// - If a Lagrange kernel is present, combine one additional term defined as
    ///   (T_l(x) - p_S(x)) / Z_S(x), where:
    ///
    /// 1. $T_l(x) is the evaluation of the Lagrange trace polynomial at $x$.
    /// 2. $S$ is the set of opening points for the Lagrange kernel i.e.,
    ///    $S := {z, z.g, z.g^2, ..., z.g^{2^{log_2(\nu) - 1}}}$.
    /// 3. $p_S(X)$ is the polynomial of minimal degree interpolating the set
    ///    ${(a, T_l(a)): a \in S}$.
    /// 4. $Z_S(X)$ is the polynomial of minimal degree vanishing over the set $S$.
    ///
    /// Note that evaluations of T_i(z) and T_i(z * g) are passed in via the `ood_trace_state`
    /// parameter.
    /// If a Lagrange kernel is present, the evaluations of $T_l$ over the set $S$ are provided
    /// separately via `ood_trace_state`.
    pub fn add_trace_polys(
        &mut self,
        trace_polys: TracePolyTable<E>,
        ood_trace_states: TraceOodFrame<E>,
    ) {
        assert!(self.coefficients.is_empty());

        // compute a second out-of-domain point offset from z by exactly trace generator; this
        // point defines the "next" computation state in relation to point z
        let trace_length = trace_polys.poly_size();
        let g = E::from(E::BaseField::get_root_of_unity(trace_length.ilog2()));
        let next_z = self.z * g;

        // combine trace polynomials into 2 composition polynomials T'(x) and T''(x)
        let mut t1_composition = E::zeroed_vector(trace_length);
        let mut t2_composition = E::zeroed_vector(trace_length);

        // index of a trace polynomial; we declare it here so that we can maintain index continuity
        // across all trace segments
        let mut i = 0;

        // --- merge polynomials of the main trace segment ----------------------------------------
        for poly in trace_polys.main_trace_polys() {
            // compute T'(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E::BaseField, E>(
                &mut t1_composition,
                poly,
                ood_trace_states.current_row()[i],
                self.cc.trace[i],
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E::BaseField, E>(
                &mut t2_composition,
                poly,
                ood_trace_states.next_row()[i],
                self.cc.trace[i],
            );

            i += 1;
        }

        // --- merge polynomials of the auxiliary trace segment ----------------------------------
        for poly in trace_polys.aux_trace_polys() {
            // compute T'(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut t1_composition,
                poly,
                ood_trace_states.current_row()[i],
                self.cc.trace[i],
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut t2_composition,
                poly,
                ood_trace_states.next_row()[i],
                self.cc.trace[i],
            );

            i += 1;
        }

        // divide the composition polynomials by (x - z) and (x - z * g), respectively,
        // and add the resulting polynomials together; the output of this step
        // is a single trace polynomial T(x) and deg(T(x)) = trace_length - 2.
        let mut trace_poly =
            merge_trace_compositions(vec![t1_composition, t2_composition], vec![self.z, next_z]);

        // finally compose the final term associated to the Lagrange kernel trace polynomial if
        // there is one present.
        if let Some(poly) = trace_polys.lagrange_poly() {
            let ood_eval_frame = ood_trace_states.lagrange_kernel_frame().expect(
                "should contain OOD values for Lagrange kernel trace polynomial if we are here",
            );

            let log_trace_len = poly.len().ilog2();
            let g = E::from(E::BaseField::get_root_of_unity(log_trace_len));
            let mut xs = Vec::with_capacity(log_trace_len as usize + 1);

            // push z
            xs.push(self.z);

            // compute the values (z * g), (z * g^2), (z * g^4), ..., (z * g^(2^(v-1)))
            let mut g_exp = g;
            for _ in 0..log_trace_len {
                let x = g_exp * self.z;
                xs.push(x);
                g_exp *= g_exp;
            }

            // compute the numerator
            let p_s = polynom::interpolate(&xs, ood_eval_frame.inner(), true);
            let mut numerator = polynom::sub(poly, &p_s);

            // divide by the zero polynomial of the set S
            syn_div_roots_in_place(&mut numerator, &xs);

            // multiply by constraint composition randomness
            let quotient = numerator;
            let scaled_with_randomness =
                polynom::mul_by_scalar(&quotient, self.cc.lagrange.unwrap());

            trace_poly = polynom::add(&scaled_with_randomness, &trace_poly);
        };

        // set the coefficients of the DEEP composition polynomial
        self.coefficients = trace_poly;
        assert_eq!(self.poly_size() - 2, self.degree());
    }

    // CONSTRAINT POLYNOMIAL COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Divides out OOD point z from the constraint composition polynomial and saves the result
    /// into the DEEP composition polynomial. This method is intended to be called only after the
    /// add_trace_polys() method has been executed. The composition is done as follows:
    ///
    /// - For each H_i(x), compute H'_i(x) = (H_i(x) - H(z)) / (x - z), where H_i(x) is the
    ///   ith composition polynomial column.
    /// - Then, combine all H_i(x) polynomials together by computing H(x) = sum(H_i(x) * cc_i) for
    ///   all i, where cc_i is the coefficient for the random linear combination drawn from the
    ///   public coin.
    ///
    /// Note that evaluations of H_i(x) at z are passed in via the `ood_evaluations` parameter.
    pub fn add_composition_poly(
        &mut self,
        composition_poly: CompositionPoly<E>,
        ood_evaluations: Vec<E>,
    ) {
        assert!(!self.coefficients.is_empty());

        let z = self.z;

        let mut column_polys = composition_poly.into_columns();

        // Divide out the OOD point z from column polynomials
        iter_mut!(column_polys).zip(ood_evaluations).for_each(|(poly, value_at_z)| {
            // compute H'_i(x) = (H_i(x) - H_i(z)) / (x - z)
            poly[0] -= value_at_z;
            polynom::syn_div_in_place(poly, 1, z);
        });

        // add H'_i(x) * cc_i for all i into the DEEP composition polynomial
        for (i, poly) in column_polys.into_iter().enumerate() {
            mul_acc::<E, E>(&mut self.coefficients, &poly, self.cc.constraints[i]);
        }
        assert_eq!(self.poly_size() - 2, self.degree());
    }

    // LOW-DEGREE EXTENSION
    // --------------------------------------------------------------------------------------------
    /// Evaluates DEEP composition polynomial over the specified LDE domain and returns the result.
    pub fn evaluate(self, domain: &StarkDomain<E::BaseField>) -> Vec<E> {
        fft::evaluate_poly_with_offset(
            &self.coefficients,
            domain.trace_twiddles(),
            domain.offset(),
            domain.trace_to_lde_blowup(),
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Divides each polynomial in the list by the corresponding divisor, and computes the
/// coefficient-wise sum of all resulting polynomials.
fn merge_trace_compositions<E: FieldElement>(mut polys: Vec<Vec<E>>, divisors: Vec<E>) -> Vec<E> {
    // divide all polynomials by their corresponding divisor
    iter_mut!(polys).zip(divisors).for_each(|(poly, divisor)| {
        polynom::syn_div_in_place(poly, 1, divisor);
    });

    // add all polynomials together into a single polynomial
    let mut result = polys.remove(0);
    for poly in polys.iter() {
        add_in_place(&mut result, poly);
    }

    result
}

/// Computes (P(x) - value) * k and saves the result into the accumulator.
fn acc_trace_poly<F, E>(accumulator: &mut [E], poly: &[F], value: E, k: E)
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    mul_acc(accumulator, poly, k);
    let adjusted_tz = value * k;
    accumulator[0] -= adjusted_tz;
}
