// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub mod errors;
pub mod proof;

mod context;
pub use context::ComputationContext;

mod options;
pub use options::{FieldExtension, HashFunction, ProofOptions};

mod air;
pub use air::{
    Air, Assertion, BoundaryConstraint, BoundaryConstraintGroup, ConstraintCompositionCoefficients,
    ConstraintDivisor, DeepCompositionCoefficients, EvaluationFrame, TraceInfo,
    TransitionConstraintDegree, TransitionConstraintGroup,
};
