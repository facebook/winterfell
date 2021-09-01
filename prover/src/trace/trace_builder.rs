// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::ExecutionTrace;
use math::StarkField;

// TRACE BUILDER TRAIT
// ================================================================================================

/// TODO: add docs
pub trait TraceBuilder {
    type BaseField: StarkField;

    fn build_trace(&self) -> ExecutionTrace<Self::BaseField>;
}
