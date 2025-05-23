// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use alloc::vec::Vec;

use air::{
    proof::{QuotientOodFrame, TraceOodFrame},
    DeepCompositionCoefficients,
};
use math::{
    add_in_place, fft, mul_acc,
    polynom::{self},
    ExtensionOf, FieldElement, StarkField,
};
use utils::iter_mut;
#[cfg(feature = "concurrent")]
use utils::iterators::*;

use super::{constraints::CompositionPoly, StarkDomain, TracePolyTable};

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
        DeepCompositionPoly { coefficients: vec![], cc, z }
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
    /// Combines all trace and quotients polynomials into a single polynomial and saves the result
    /// into the DEEP composition polynomial. The combination is done as follows:
    ///
    /// - Compute polynomials T'_i(x) = (T_i(x) - T_i(z)) / (x - z) and
    ///   T''_i(x) = (T_i(x) - T_i(z * g)) / (x - z * g) for all i, where T_i(x) is a trace
    ///   or quotient polynomial for column i.
    /// - Then, combine together all T'_i(x) and T''_i(x) polynomials using a random linear
    ///   combination as T(x) = sum((T'_i(x) + T''_i(x)) * cc_i) for all i, where cc_i is
    ///   the coefficient for the random linear combination drawn from the public coin.
    ///
    /// Note that evaluations of T_i(z) and T_i(z * g) are passed in via the `ood_trace_state`
    /// and `ood_quotient_states` parameter.
    pub fn add_trace_polys(
        &mut self,
        trace_polys: TracePolyTable<E>,
        quotient_polys: CompositionPoly<E>,
        ood_trace_states: TraceOodFrame<E>,
        ood_quotient_states: QuotientOodFrame<E>,
    ) {
        assert!(self.coefficients.is_empty());

        // compute a second out-of-domain point offset from z by exactly trace generator; this
        // point defines the "next" computation state in relation to point z
        let trace_length = trace_polys.poly_size();
        let g = E::from(E::BaseField::get_root_of_unity(trace_length.ilog2()));
        let next_z = self.z * g;

        // combine trace polynomials into 2 composition polynomials T'(x) and T''(x)
        let mut composition_z = vec![E::ZERO; trace_length];
        let mut composition_gz = vec![E::ZERO; trace_length];

        // index of a trace polynomial; we declare it here so that we can maintain index continuity
        // across all trace segments
        let mut i = 0;

        // --- merge polynomials of the main trace segment ----------------------------------------
        for poly in trace_polys.main_trace_polys() {
            // compute T'(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E::BaseField, E>(
                &mut composition_z,
                poly,
                ood_trace_states.current_row()[i],
                self.cc.trace[i],
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E::BaseField, E>(
                &mut composition_gz,
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
                &mut composition_z,
                poly,
                ood_trace_states.current_row()[i],
                self.cc.trace[i],
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut composition_gz,
                poly,
                ood_trace_states.next_row()[i],
                self.cc.trace[i],
            );

            i += 1;
        }

        // --- merge polynomials of the composition polynomial trace ------------------------------
        for (i, poly) in quotient_polys.into_columns().iter().enumerate() {
            // compute T'(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut composition_z,
                poly,
                ood_quotient_states.current_row()[i],
                self.cc.constraints[i],
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut composition_gz,
                poly,
                ood_quotient_states.next_row()[i],
                self.cc.constraints[i],
            );
        }

        // divide the composition polynomials by (x - z) and (x - z * g), respectively,
        // and add the resulting polynomials together; the output of this step
        // is a single trace polynomial T(x) and deg(T(x)) = trace_length - 2.
        let trace_poly =
            merge_compositions(vec![composition_z, composition_gz], vec![self.z, next_z]);

        // set the coefficients of the DEEP composition polynomial
        self.coefficients = trace_poly;
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
fn merge_compositions<E: FieldElement>(mut polys: Vec<Vec<E>>, divisors: Vec<E>) -> Vec<E> {
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
