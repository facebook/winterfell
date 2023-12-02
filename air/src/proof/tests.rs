// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::StarkProof;

#[test]
pub fn starkproof_new_dummy_doesnt_panic() {
    let _ = StarkProof::new_dummy();
}
