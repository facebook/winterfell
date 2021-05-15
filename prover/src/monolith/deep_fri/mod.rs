// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{constraints::ConstraintPoly, StarkDomain, TracePolyTable};
use common::{CompositionCoefficients, ComputationContext, EvaluationFrame};
use math::{
    fft,
    field::{FieldElement, StarkField},
    polynom,
    utils::{self, add_in_place},
};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// COMPOSITION POLYNOMIAL
// ================================================================================================
pub struct CompositionPoly<E: FieldElement> {
    coefficients: Vec<E>,
    cc: CompositionCoefficients<E>,
    z: E,
    field_extension: bool,
}

impl<E: FieldElement> CompositionPoly<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new composition polynomial. This also initializes memory needed to hold
    /// polynomial coefficients.
    pub fn new(context: &ComputationContext, z: E, cc: CompositionCoefficients<E>) -> Self {
        CompositionPoly {
            coefficients: E::zeroed_vector(context.trace_length()),
            cc,
            z,
            field_extension: !context.options().field_extension().is_none(),
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the degree of the composition polynomial.
    pub fn degree(&self) -> usize {
        polynom::degree_of(&self.coefficients)
    }

    // TRACE POLYNOMIAL COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Combines all trace polynomials into a single polynomial and saves the result into
    /// the composition polynomial. The combination is done as follows:
    /// 1. First, state of trace registers at deep points z and z * g are computed;
    /// 2. Then, polynomials T1_i(x) = (T_i(x) - T_i(z)) / (x - z) and
    /// T2_i(x) = (T_i(x) - T_i(z * g)) / (x - z * g) are computed for all i and combined
    /// together into a single polynomial using a pseudo-random linear combination;
    /// 3. Then the degree of the polynomial is adjusted to match the composition degree.
    pub fn add_trace_polys<B>(&mut self, trace_polys: TracePolyTable<B>) -> EvaluationFrame<E>
    where
        B: StarkField,
        E: From<B>,
    {
        // compute a second out-of-domain point offset from z by exactly trace generator; this point
        // defines the "next" computation state in relation to point z
        let trace_length = trace_polys.poly_size();
        let g = E::from(B::get_root_of_unity(utils::log2(trace_length)));
        let next_z = self.z * g;

        // compute state of registers at deep points z and z * g
        let trace_state1 = trace_polys.evaluate_at(self.z);
        let trace_state2 = trace_polys.evaluate_at(next_z);

        // combine trace polynomials into 2 composition polynomials T1(x) and T2(x), and if
        // we are using a field extension, also T3(x)
        let polys = trace_polys.into_vec();
        let mut t1_composition = E::zeroed_vector(trace_length);
        let mut t2_composition = E::zeroed_vector(trace_length);
        let mut t3_composition = if self.field_extension {
            E::zeroed_vector(trace_length)
        } else {
            Vec::new()
        };
        for (i, poly) in polys.into_iter().enumerate() {
            // compute T1(x) = T(x) - T(z), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_poly(
                &mut t1_composition,
                &poly,
                trace_state1[i],
                self.cc.trace[i].0,
            );

            // compute T2(x) = T(x) - T(z * g), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial
            acc_poly(
                &mut t2_composition,
                &poly,
                trace_state2[i],
                self.cc.trace[i].1,
            );

            // compute T3(x) = T(x) - T(z_conjugate), multiply it by a pseudo-random coefficient,
            // and add the result into composition polynomial. When extension field is enabled,
            // this constraint is needed to prove that the trace is defined over the base field,
            // rather than the extension field.
            if self.field_extension {
                acc_poly(
                    &mut t3_composition,
                    &poly,
                    trace_state1[i].conjugate(),
                    self.cc.trace[i].2,
                );
            }
        }

        // divide the composition polynomials by (x - z), (x - z * g), and (x - z_conjugate)
        // respectively, and add the resulting polynomials together; the output of this step
        // is a single trace polynomial T(x) and deg(T(x)) = trace_length - 2.
        let trace_poly = merge_trace_compositions(
            vec![t1_composition, t2_composition, t3_composition],
            vec![self.z, next_z, self.z.conjugate()],
        );
        debug_assert_eq!(trace_length - 2, polynom::degree_of(&trace_poly));

        // TODO: fix
        self.coefficients = trace_poly;

        // trace states at OOD points z and z * g are returned to be included in the proof
        EvaluationFrame {
            current: trace_state1,
            next: trace_state2,
        }
    }

    // CONSTRAINT POLYNOMIAL COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Divides out OOD point z from the constraint polynomial and saves the result into the
    /// composition polynomial.
    pub fn add_constraint_poly(&mut self, constraint_poly: ConstraintPoly<E>) -> Vec<E> {
        let num_columns = constraint_poly.num_columns() as u32;

        // TODO: add comment
        let z_p = self.z.exp(num_columns.into());

        let mut result = Vec::new();

        // TODO: implement multi-threaded version
        for (i, mut poly) in constraint_poly.into_polys().into_iter().enumerate() {
            // evaluate the polynomial at point z'
            let value_at_z = polynom::eval(&poly, z_p);
            result.push(value_at_z);

            // compute C(x) = (P(x) - P(z)) / (x - z')
            poly[0] -= value_at_z;
            polynom::syn_div_in_place(&mut poly, 1, z_p);

            // add C(x) * K into the result
            utils::mul_acc(&mut self.coefficients, &poly, self.cc.constraints[i]);
        }

        result
    }

    // FINAL DEGREE ADJUSTMENT
    // --------------------------------------------------------------------------------------------
    // TODO: add comment
    pub fn adjust_degree(&mut self) {
        let mut result = E::zeroed_vector(self.coefficients.len());

        // The next few lines are an optimized way of computing:
        // C(x) = T(x) * k_1 + T(x) * x * k_2
        // where k_1 and k_2 are pseudo-random coefficients.

        // this is equivalent to T(x) * k_1
        utils::mul_acc(&mut result, &self.coefficients, self.cc.degree.0);
        // this is equivalent to T(x) * x * k_2
        utils::mul_acc(
            &mut result[1..],
            &self.coefficients[..(self.coefficients.len() - 1)],
            self.cc.degree.1,
        );

        self.coefficients = result;
    }

    // LOW-DEGREE EXTENSION
    // --------------------------------------------------------------------------------------------
    /// Evaluates DEEP composition polynomial over the specified LDE domain and returns the result.
    pub fn evaluate<B>(self, domain: &StarkDomain<B>) -> Vec<E>
    where
        B: StarkField,
        E: From<B>,
    {
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
#[cfg(not(feature = "concurrent"))]
fn merge_trace_compositions<E: FieldElement>(mut polys: Vec<Vec<E>>, divisors: Vec<E>) -> Vec<E> {
    // divide all polynomials by their corresponding divisor
    for (poly, &divisor) in polys.iter_mut().zip(divisors.iter()) {
        // skip empty polynomials; this could happen for conjugate composition polynomial (T3)
        // when extension field is not enabled.
        if !poly.is_empty() {
            polynom::syn_div_in_place(poly, 1, divisor);
        }
    }

    // add all polynomials together into a single polynomial
    let mut result = polys.remove(0);
    for poly in polys.iter() {
        if !poly.is_empty() {
            add_in_place(&mut result, poly);
        }
    }

    result
}

/// Same as above function, but performs division in parallel threads.
#[cfg(feature = "concurrent")]
fn merge_trace_compositions<E: FieldElement>(mut polys: Vec<Vec<E>>, divisors: Vec<E>) -> Vec<E> {
    polys
        .par_iter_mut()
        .zip(divisors.par_iter())
        .for_each(|(poly, &divisor)| {
            if !poly.is_empty() {
                polynom::syn_div_in_place(poly, 1, divisor);
            }
        });

    let mut result = polys.remove(0);
    for poly in polys.iter() {
        if !poly.is_empty() {
            add_in_place(&mut result, poly);
        }
    }

    result
}

/// Computes (P(x) - value) * k and saves the result into the accumulator
fn acc_poly<B, E>(accumulator: &mut Vec<E>, poly: &[B], value: E, k: E)
where
    B: StarkField,
    E: FieldElement + From<B>,
{
    utils::mul_acc(accumulator, poly, k);
    let adjusted_tz = value * k;
    accumulator[0] -= adjusted_tz;
}
