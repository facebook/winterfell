// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Example;

pub fn test_basic_proof_verification(e: Box<dyn Example>) {
    let proof = e.prove();
    assert!(e.verify(proof).is_ok());
}

pub fn test_basic_proof_verification_fail(e: Box<dyn Example>) {
    let proof = e.prove();
    let verified = e.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}
