// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{constraints::CompositionPoly, StarkDomain, TracePolyTable};
use air::{Air, DeepCompositionCoefficients};
use math::{add_in_place, fft, log2, mul_acc, polynom, ExtensionOf, FieldElement, StarkField};
use utils::{collections::Vec, iter_mut};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// DEEP COMPOSITION POLYNOMIAL
// ================================================================================================
pub struct DeepCompositionPoly<E: FieldElement> {
    coefficients: Vec<E>,
    cc: DeepCompositionCoefficients<E>,
    z: E,
    field_extension: bool,
}

impl<E: FieldElement> DeepCompositionPoly<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new DEEP composition polynomial. Initially, this polynomial will be empty, and
    /// the intent is to populate the coefficients via add_trace_polys() and add_constraint_polys()
    /// methods.
    pub fn new<A>(air: &A, z: E, cc: DeepCompositionCoefficients<E>) -> Self
    where
        A: Air<BaseField = E::BaseField>,
    {
        DeepCompositionPoly {
            coefficients: vec![],
            cc,
            z,
            field_extension: !air.options().field_extension().is_none(),
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
    /// - Then, combine together all T'_i(x) polynomials using random liner combination as
    ///   T(x) = sum(T'_i(x) * cc'_i + T''_i(x) * cc''_i) for all i, where cc'_i and cc''_i are
    ///   the coefficients for the random linear combination drawn from the public coin.
    /// - In cases when we generate the proof using an extension field, we also compute
    ///   T'''_i(x) = (T_i(x) - T_i(z_conjugate)) / (x - z_conjugate), and add it to T(x) similarly
    ///   to the way described above. This is needed in order to verify that the trace is defined
    ///   over the base field, rather than the extension field.
    ///
    /// Note that evaluations of T_i(z) and T_i(z * g) are passed in via the `ood_frame` parameter.
    pub fn add_trace_polys(
        &mut self,
        trace_polys: TracePolyTable<E>,
        ood_trace_states: Vec<Vec<E>>,
    ) {
        assert!(self.coefficients.is_empty());

        // compute a second out-of-domain point offset from z by exactly trace generator; this
        // point defines the "next" computation state in relation to point z
        let trace_length = trace_polys.poly_size();
        let g = E::from(E::BaseField::get_root_of_unity(log2(trace_length)));
        let next_z = self.z * g;

        // combine trace polynomials into 2 composition polynomials T'(x) and T''(x), and if
        // we are using a field extension, also T'''(x)
        let mut t1_composition = E::zeroed_vector(trace_length);
        let mut t2_composition = E::zeroed_vector(trace_length);
        let mut t3_composition = if self.field_extension {
            E::zeroed_vector(trace_length)
        } else {
            Vec::new()
        };

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
                ood_trace_states[0][i],
                self.cc.trace[i].0,
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E::BaseField, E>(
                &mut t2_composition,
                poly,
                ood_trace_states[1][i],
                self.cc.trace[i].1,
            );

            // when extension field is enabled, compute T'''(x) = T(x) - T(z_conjugate), multiply
            // it by a pseudo-random coefficient, and add the result into composition polynomial
            if self.field_extension {
                acc_trace_poly::<E::BaseField, E>(
                    &mut t3_composition,
                    poly,
                    ood_trace_states[0][i].conjugate(),
                    self.cc.trace[i].2,
                );
            }

            i += 1;
        }

        // --- merge polynomials of the auxiliary trace segments ----------------------------------

        // since trace polynomials are already in an extension field (when extension fields are
        // used), we don't apply conjugate composition to them
        for poly in trace_polys.aux_trace_polys() {
            // compute T'(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut t1_composition,
                poly,
                ood_trace_states[0][i],
                self.cc.trace[i].0,
            );

            // compute T''(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_trace_poly::<E, E>(
                &mut t2_composition,
                poly,
                ood_trace_states[1][i],
                self.cc.trace[i].1,
            );

            i += 1;
        }

        // divide the composition polynomials by (x - z), (x - z * g), and (x - z_conjugate)
        // respectively, and add the resulting polynomials together; the output of this step
        // is a single trace polynomial T(x) and deg(T(x)) = trace_length - 2.
        let trace_poly = merge_trace_compositions(
            vec![t1_composition, t2_composition, t3_composition],
            vec![self.z, next_z, self.z.conjugate()],
        );

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
    /// - For each H_i(x), compute H'_i(x) = (H_i(x) - H(z^m)) / (x - z^m), where H_i(x) is the
    ///   ith composition polynomial column and m is the total number of columns.
    /// - Then, combine all H_i(x) polynomials together by computing H(x) = sum(H_i(x) * cc_i) for
    ///   all i, where cc_i is the coefficient for the random linear combination drawn from the
    ///   public coin.
    ///
    /// Note that evaluations of H_i(x) at z^m are passed in via the `ood_evaluations` parameter.
    pub fn add_composition_poly(
        &mut self,
        composition_poly: CompositionPoly<E>,
        ood_evaluations: Vec<E>,
    ) {
        assert!(!self.coefficients.is_empty());

        // compute z^m
        let num_columns = composition_poly.num_columns() as u32;
        let z_m = self.z.exp(num_columns.into());

        let mut column_polys = composition_poly.into_columns();

        // Divide out the OOD point z from column polynomials
        iter_mut!(column_polys)
            .zip(ood_evaluations)
            .for_each(|(poly, value_at_z_m)| {
                // compute H'_i(x) = (H_i(x) - H_i(z^m)) / (x - z^m)
                poly[0] -= value_at_z_m;
                polynom::syn_div_in_place(poly, 1, z_m);
            });

        // add H'_i(x) * cc_i for all i into the DEEP composition polynomial
        for (i, poly) in column_polys.into_iter().enumerate() {
            mul_acc::<E, E>(&mut self.coefficients, &poly, self.cc.constraints[i]);
        }
        assert_eq!(self.poly_size() - 2, self.degree());
    }

    // FINAL DEGREE ADJUSTMENT
    // --------------------------------------------------------------------------------------------
    /// Increase the degree of the DEEP composition polynomial by one. After add_trace_polys() and
    /// add_composition_poly() are executed, the degree of the DEEP composition polynomial is
    /// trace_length - 2 because in these functions we divide the polynomials of degree
    /// trace_length - 1 by (x - z), (x - z * g) etc. which decreases the degree by one. We want to
    /// ensure that degree of the DEEP composition polynomial is trace_length - 1, so we make the
    /// adjustment here by computing C'(x) = C(x) * (cc_0 + x * cc_1), where cc_0 and cc_1 are the
    /// coefficients for the random linear combination drawn from the public coin.
    pub fn adjust_degree(&mut self) {
        assert_eq!(self.poly_size() - 2, self.degree());

        let mut result = E::zeroed_vector(self.coefficients.len());

        // this is equivalent to C(x) * cc_0
        mul_acc::<E, E>(&mut result, &self.coefficients, self.cc.degree.0);
        // this is equivalent to C(x) * x * cc_1
        mul_acc::<E, E>(
            &mut result[1..],
            &self.coefficients[..(self.coefficients.len() - 1)],
            self.cc.degree.1,
        );

        self.coefficients = result;
        assert_eq!(self.poly_size() - 1, self.degree());
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
        // skip empty polynomials; this could happen for conjugate composition polynomial (T3)
        // when extension field is not enabled.
        if !poly.is_empty() {
            polynom::syn_div_in_place(poly, 1, divisor);
        }
    });

    // add all polynomials together into a single polynomial
    let mut result = polys.remove(0);
    for poly in polys.iter() {
        if !poly.is_empty() {
            add_in_place(&mut result, poly);
        }
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
