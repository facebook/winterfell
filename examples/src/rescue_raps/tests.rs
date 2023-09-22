// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Blake3_256;
use winter_fri::fri_schedule::FoldingSchedule;
use winterfell::{FieldExtension, ProofOptions};

#[test]
fn rescue_test_basic_proof_verification() {
    let rescue_eg = Box::new(super::RescueRapsExample::<Blake3_256>::new(
        128,
        build_options(false),
    ));
    crate::tests::test_basic_proof_verification(rescue_eg);
}

#[test]
fn rescue_test_basic_proof_verification_extension() {
    let rescue_eg = Box::new(super::RescueRapsExample::<Blake3_256>::new(
        128,
        build_options(true),
    ));
    crate::tests::test_basic_proof_verification(rescue_eg);
}

#[test]
fn rescue_test_basic_proof_verification_fail() {
    let rescue_eg = Box::new(super::RescueRapsExample::<Blake3_256>::new(
        128,
        build_options(false),
    ));
    crate::tests::test_basic_proof_verification_fail(rescue_eg);
}

fn build_options(use_extension_field: bool) -> ProofOptions {
    let extension = if use_extension_field {
        FieldExtension::Quadratic
    } else {
        FieldExtension::None
    };

    let fri_constant_schedule = FoldingSchedule::new_constant(4, 31);
    ProofOptions::new(28, 8, 0, extension, &fri_constant_schedule)
}
