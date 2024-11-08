// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, ProofOptions};

use super::Blake3_256;

#[test]
fn vdf_test_basic_proof_verification() {
    let fib = Box::new(super::VdfExample::<Blake3_256>::new(128, build_options(false)));
    crate::tests::test_basic_proof_verification(fib);
}

#[test]
fn vdf_test_basic_proof_verification_extension() {
    let fib = Box::new(super::VdfExample::<Blake3_256>::new(128, build_options(true)));
    crate::tests::test_basic_proof_verification(fib);
}

#[test]
fn vdf_test_basic_proof_verification_fail() {
    let fib = Box::new(super::VdfExample::<Blake3_256>::new(128, build_options(false)));
    crate::tests::test_basic_proof_verification_fail(fib);
}

fn build_options(use_extension_field: bool) -> ProofOptions {
    let extension = if use_extension_field {
        FieldExtension::Quadratic
    } else {
        FieldExtension::None
    };
    ProofOptions::new(2, 4, 0, extension, 2, 255, true)
}
