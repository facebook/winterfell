// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains components need to describe arbitrary computations in a STARK-specific
//! format.
//!
//! Before we can generate proofs attesting that some computations were executed correctly, we
//! need to describe these computations in a way that can be understood by the Winterfell prover
//! and verifier.
//!
//! More formally, we need to reduce our computations to algebraic statements involving a set of
//! bounded-degree polynomials. This step is usually called *arithmetization*. STARK arithmetization
//! reduces computations to an *algebraic intermediate representation* or AIR for short. For basics
//! of AIR arithmetization please refer to the excellent posts from StarkWare:
//!
//! * [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
//! * [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
//! * [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)
//!
//! Coming up with efficient arithmetizations for computations is highly non-trivial, and
//! describing arithmetizations could be tedious and error-prone. The [Air] trait aims to help
//! with the latter, which, hopefully, also makes the former a little simpler. For additional
//! details, please refer to the documentation of the [Air] trait itself.
//!
//! This crate also contains components describing STARK protocol parameters ([ProofOptions]) and
//! proof structure ([Proof](proof::Proof)).

#![no_std]

#[macro_use]
extern crate alloc;

pub mod proof;

mod errors;
pub use errors::AssertionError;

mod options;
pub use options::{BatchingMethod, FieldExtension, PartitionOptions, ProofOptions};

mod air;
pub use air::{
    Air, AirContext, Assertion, AuxRandElements, BoundaryConstraint, BoundaryConstraintGroup,
    BoundaryConstraints, ConstraintCompositionCoefficients, ConstraintDivisor,
    DeepCompositionCoefficients, EvaluationFrame, TraceInfo, TransitionConstraintDegree,
    TransitionConstraints,
};
