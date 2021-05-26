// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::field::FieldElement;

// CONSTRAINT COMPOSITION COEFFICIENTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct ConstraintCompositionCoefficients<E: FieldElement> {
    pub transition: Vec<(E, E)>,
    pub boundary: Vec<(E, E)>,
}

// DEEP COMPOSITION COEFFICIENTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct DeepCompositionCoefficients<E: FieldElement> {
    pub trace: Vec<(E, E, E)>,
    pub constraints: Vec<E>,
    pub degree: (E, E),
}
