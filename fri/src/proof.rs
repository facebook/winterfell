// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriProofLayer {
    pub values: Vec<Vec<u8>>,
    pub paths: Vec<Vec<[u8; 32]>>,
    pub depth: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriProof {
    pub layers: Vec<FriProofLayer>,
    pub rem_values: Vec<u8>,
    pub partitioned: bool,
}
