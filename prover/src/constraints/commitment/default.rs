// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use air::{proof::Queries, PartitionOptions};
use crypto::{ElementHasher, VectorCommitment};
use math::FieldElement;
use tracing::info_span;

use super::{ConstraintCommitment, RowMatrix};
use crate::{CompositionPoly, CompositionPolyTrace, StarkDomain, DEFAULT_SEGMENT_WIDTH};

// CONSTRAINT COMMITMENT
// ================================================================================================

/// Constraint evaluation commitment.
///
/// The commitment consists of two components:
/// * Evaluations of composition polynomial columns over the LDE domain.
/// * Vector commitment where each vector element corresponds to the digest of a row in the
///   composition polynomial evaluation matrix.
pub struct DefaultConstraintCommitment<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
> {
    evaluations: RowMatrix<E>,
    vector_commitment: V,
    _h: PhantomData<H>,
}

impl<E, H, V> DefaultConstraintCommitment<E, H, V>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    /// Creates a new constraint evaluation commitment from the provided composition polynomial
    /// evaluations and the corresponding vector commitment.
    pub fn new(
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<E::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self, CompositionPoly<E>) {
        // extend the main execution trace and build a commitment to the extended trace
        let (evaluations, commitment, composition_poly) = build_constraint_commitment::<E, H, V>(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        );

        assert_eq!(
            evaluations.num_rows(),
            commitment.domain_len(),
            "number of rows in constraint evaluation matrix must be the same as the size \
            of the vector commitment domain"
        );

        let commitment = Self {
            evaluations,
            vector_commitment: commitment,
            _h: PhantomData,
        };

        (commitment, composition_poly)
    }
}

impl<E, H, V> ConstraintCommitment<E> for DefaultConstraintCommitment<E, H, V>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField> + core::marker::Sync,
    V: VectorCommitment<H> + core::marker::Sync,
{
    type HashFn = H;
    type VC = V;

    /// Returns the commitment.
    fn commitment(&self) -> H::Digest {
        self.vector_commitment.commitment()
    }

    /// Returns constraint evaluations at the specified positions along with a batch opening proof
    /// against the vector commitment.
    fn query(self, positions: &[usize]) -> Queries {
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

fn build_constraint_commitment<E, H, V>(
    composition_poly_trace: CompositionPolyTrace<E>,
    num_constraint_composition_columns: usize,
    domain: &StarkDomain<E::BaseField>,
    partition_options: PartitionOptions,
) -> (RowMatrix<E>, V, CompositionPoly<E>)
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    // first, build constraint composition polynomial from its trace as follows:
    // - interpolate the trace into a polynomial in coefficient form
    // - "break" the polynomial into a set of column polynomials each of degree equal to
    //   trace_length - 1
    let composition_poly = info_span!(
        "build_composition_poly_columns",
        num_columns = num_constraint_composition_columns
    )
    .in_scope(|| {
        CompositionPoly::new(composition_poly_trace, domain, num_constraint_composition_columns)
    });
    assert_eq!(composition_poly.num_columns(), num_constraint_composition_columns);
    assert_eq!(composition_poly.column_degree(), domain.trace_length() - 1);

    // then, evaluate composition polynomial columns over the LDE domain
    let domain_size = domain.lde_domain_size();
    let composed_evaluations = info_span!("evaluate_composition_poly_columns").in_scope(|| {
        RowMatrix::evaluate_polys_over::<DEFAULT_SEGMENT_WIDTH>(composition_poly.data(), domain)
    });
    assert_eq!(composed_evaluations.num_cols(), num_constraint_composition_columns);
    assert_eq!(composed_evaluations.num_rows(), domain_size);

    // finally, build constraint evaluation commitment
    let commitment = info_span!(
        "compute_constraint_evaluation_commitment",
        log_domain_size = domain_size.ilog2()
    )
    .in_scope(|| composed_evaluations.commit_to_rows::<H, V>(partition_options));

    (composed_evaluations, commitment, composition_poly)
}
