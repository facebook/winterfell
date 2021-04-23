// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::StarkDomain;
use math::{
    fft,
    field::{FieldElement, StarkField},
    polynom,
};

// CONSTRAINT POLYNOMIAL
// ================================================================================================
pub struct ConstraintPoly<E: FieldElement> {
    coefficients: Vec<E>,
    degree: usize,
}

impl<E: FieldElement> ConstraintPoly<E> {
    /// Returns a new constraint polynomial.
    pub fn new(coefficients: Vec<E>, degree: usize) -> Self {
        assert!(
            coefficients.len().is_power_of_two(),
            "number of coefficients must be a power of 2"
        );
        // this check is expensive - so, check in debug mode only
        debug_assert_eq!(
            degree,
            polynom::degree_of(&coefficients),
            "inconsistent constraint polynomial degree; expected {}, but was {}",
            degree,
            polynom::degree_of(&coefficients)
        );
        ConstraintPoly {
            coefficients,
            degree,
        }
    }

    /// Returns the degree of this constraint polynomial.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the length of the vector containing constraint polynomial coefficients;
    /// this is guaranteed to be a power of 2.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Returns the coefficients of the polynomial in the reverse-degree order (lowest-degree
    /// coefficients first); some of the leading coefficients may be zeros.
    #[allow(dead_code)]
    pub fn coefficients(&self) -> &[E] {
        &self.coefficients
    }

    /// Evaluates the polynomial the the specified point `x`.
    #[allow(dead_code)]
    pub fn evaluate_at(&self, x: E) -> E {
        polynom::eval(&self.coefficients, x)
    }

    // LOW-DEGREE EXTENSION
    // --------------------------------------------------------------------------------------------
    /// Evaluates constraint polynomial over the specified LDE domain and returns the result.
    pub fn evaluate<B>(&self, domain: &StarkDomain<B>) -> Vec<E>
    where
        B: StarkField,
        E: From<B>,
    {
        assert_eq!(
            self.len(),
            domain.ce_domain_size(),
            "inconsistent evaluation domain size; expected {}, but received {}",
            self.len(),
            domain.ce_domain_size()
        );

        fft::evaluate_poly_with_offset(
            &self.coefficients,
            domain.ce_twiddles(),
            domain.offset(),
            domain.ce_to_lde_blowup(),
        )
    }

    /// Transforms this constraint polynomial into a vector of coefficients.
    pub fn into_vec(self) -> Vec<E> {
        self.coefficients
    }
}
