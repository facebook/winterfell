// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{super::utils::build_proof_options, Blake3_256};

#[test]
fn mulfib2_test_basic_proof_verification() {
    let fib = Box::new(super::MulFib2Example::<Blake3_256>::new(16, build_proof_options(false)));
    crate::tests::test_basic_proof_verification(fib);
}

#[test]
fn mulfib2_test_basic_proof_verification_extension() {
    let fib = Box::new(super::MulFib2Example::<Blake3_256>::new(16, build_proof_options(true)));
    crate::tests::test_basic_proof_verification(fib);
}

#[test]
fn mulfib2_test_basic_proof_verification_fail() {
    let fib = Box::new(super::MulFib2Example::<Blake3_256>::new(16, build_proof_options(false)));
    crate::tests::test_basic_proof_verification_fail(fib);
}
