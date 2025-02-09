// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::proof::Queries;
use crypto::{ElementHasher, Hasher, VectorCommitment};
use math::FieldElement;

use super::RowMatrix;

mod default;
pub use default::DefaultConstraintCommitment;

// CONSTRAINT COMMITMENT
// ================================================================================================

/// Constraint evaluation commitment.
///
/// The commitment consists of two components:
/// * Evaluations of composition polynomial columns over the LDE domain.
/// * Vector commitment where each vector element corresponds to the digest of a row in the
///   composition polynomial evaluation matrix.
pub trait ConstraintCommitment<E: FieldElement> {
    /// The hash function used for hashing the rows of trace segment LDEs.
    type HashFn: ElementHasher<BaseField = E::BaseField>;

    /// The vector commitment scheme used for commiting to the trace.
    type VC: VectorCommitment<Self::HashFn>;

    /// Returns the commitment.
    fn commitment(&self) -> <Self::HashFn as Hasher>::Digest;

    /// Returns constraint evaluations at the specified positions along with a batch opening proof
    /// against the vector commitment.
    fn query(self, positions: &[usize]) -> Queries;
}
