// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::math::{fields::f128::BaseElement, FieldElement};

pub fn compute_fib_term(n: usize) -> BaseElement {
    let mut t0 = BaseElement::ONE;
    let mut t1 = BaseElement::ONE;

    for _ in 0..(n - 1) {
        t1 = t0 + t1;
        core::mem::swap(&mut t0, &mut t1);
    }

    t1
}

pub fn compute_mulfib_term(n: usize) -> BaseElement {
    let mut t0 = BaseElement::ONE;
    let mut t1 = BaseElement::new(2);

    for _ in 0..(n - 1) {
        t1 = t0 * t1;
        core::mem::swap(&mut t0, &mut t1);
    }

    t1
}

#[cfg(test)]
pub fn build_proof_options(use_extension_field: bool) -> winterfell::ProofOptions {
    use winterfell::{FieldExtension, HashFunction, ProofOptions};

    let extension = if use_extension_field {
        FieldExtension::Quadratic
    } else {
        FieldExtension::None
    };
    ProofOptions::new(28, 8, 0, HashFunction::Blake3_256, extension, 4, 256)
}
