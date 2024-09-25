// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, ProofOptions};

use super::{Rp64_256, AUX_TRACE_WIDTH};

#[test]
fn logup_gkr_small_test_basic_proof_verification() {
    let logup_gkr = Box::new(super::LogUpGkrSimple::<Rp64_256>::new(128, AUX_TRACE_WIDTH, build_options(false)));
    crate::tests::test_basic_proof_verification(logup_gkr);
}

#[test]
fn logup_gkr_small_test_basic_proof_verification_extension() {
    let logup_gkr = Box::new(super::LogUpGkrSimple::<Rp64_256>::new(128, AUX_TRACE_WIDTH, build_options(true)));
    crate::tests::test_basic_proof_verification(logup_gkr);
}

#[test]
fn logup_gkr_small_test_basic_proof_verification_fail() {
    let logup_gkr = Box::new(super::LogUpGkrSimple::<Rp64_256>::new(128, AUX_TRACE_WIDTH, build_options(false)));
    crate::tests::test_basic_proof_verification_fail(logup_gkr);
}

fn build_options(use_extension_field: bool) -> ProofOptions {
    let extension = if use_extension_field {
        FieldExtension::Quadratic
    } else {
        FieldExtension::None
    };
    ProofOptions::new(28, 8, 0, extension, 4, 31)
}
