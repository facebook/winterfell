// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::proof::Queries;
use alloc::vec::Vec;
use core::marker::PhantomData;

use air::proof::Queries;
use crypto::{ElementHasher, VectorCommitment};
use math::FieldElement;

use super::RowMatrix;

// CONSTRAINT COMMITMENT
// ================================================================================================

/// Constraint evaluation commitment.
///
/// The commitment consists of two components:
/// * Evaluations of composition polynomial columns over the LDE domain.
/// * Vector commitment where each vector element corresponds to the digest of a row in
///   the composition polynomial evaluation matrix.
pub struct ConstraintCommitment<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
> {
    evaluations: RowMatrix<E>,
    vector_commitment: V,
    _h: PhantomData<H>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>, V: VectorCommitment<H>>
    ConstraintCommitment<E, H, V>
{
    /// Creates a new constraint evaluation commitment from the provided composition polynomial
    /// evaluations and the corresponding vector commitment.
    pub fn new(evaluations: RowMatrix<E>, commitment: V) -> ConstraintCommitment<E, H, V> {
        ConstraintCommitment {
            evaluations,
            vector_commitment: commitment,
            _h: PhantomData,
        }
    }

    /// Returns the commitment.
    pub fn commitment(&self) -> H::Digest {
        self.vector_commitment.commitment()
    }

    /// Returns constraint evaluations at the specified positions along with a batch opening proof
    /// against the vector commitment.
    pub fn query(self, positions: &[usize]) -> Queries {
        // build batch opening proof to the leaves specified by positions
        let opening_proof = self
            .vector_commitment
            .open_many(positions)
            .expect("failed to generate a batch opening proof for constraint queries");

        // determine a set of evaluations corresponding to each position
        let mut evaluations = Vec::new();
        for &position in positions {
            let row = self.evaluations.row(position).to_vec();
            evaluations.push(row);
        }

        Queries::new::<H, E, V>(opening_proof.1, evaluations)
    }
}
