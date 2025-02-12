// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Proof;

#[test]
pub fn starkproof_new_dummy_doesnt_panic() {
    let _ = Proof::new_dummy();
}

#[test]
fn dummy_proof_serialization() {
    let proof = Proof::new_dummy();

    let bytes = proof.to_bytes();

    let proof_copy = Proof::from_bytes(&bytes).unwrap();

    assert_eq!(proof, proof_copy);
}
