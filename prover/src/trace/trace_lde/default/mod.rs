// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{proof::Queries, LagrangeKernelEvaluationFrame, TraceInfo};
use tracing::info_span;

use super::{
    ColMatrix, ElementHasher, EvaluationFrame, FieldElement, StarkDomain, 
    TraceLde, TracePolyTable,
};
use crate::{RowMatrix, DEFAULT_SEGMENT_WIDTH};
use core::marker::PhantomData;
use crypto::VectorCommitment;

#[cfg(test)]
mod tests;

// TRACE LOW DEGREE EXTENSION
// ================================================================================================
/// Contains all segments of the extended execution trace, the commitments to these segments, the
/// LDE blowup factor, and the [TraceInfo].
///
/// Segments are stored in two groups:
/// - Main segment: this is the first trace segment generated by the prover. Values in this segment
///   will always be elements in the base field (even when an extension field is used).
/// - Auxiliary segments: a list of 0 or more segments for traces generated after the prover
///   commits to the first trace segment. Currently, at most 1 auxiliary segment is possible.
pub struct DefaultTraceLde<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment,
> {
    // low-degree extension of the main segment of the trace
    main_segment_lde: RowMatrix<E::BaseField>,
    // commitment to the main segment of the trace
    main_segment_tree: V,
    // low-degree extensions of the auxiliary segment of the trace
    aux_segment_lde: Option<RowMatrix<E>>,
    // commitment to the auxiliary segment of the trace
    aux_segment_tree: Option<V>,
    blowup: usize,
    trace_info: TraceInfo,
    _h: PhantomData<H>,
}

impl<
        E: FieldElement,
        H: ElementHasher<BaseField = E::BaseField, Digest = <V as VectorCommitment>::Item>,
        V: VectorCommitment,
    > DefaultTraceLde<E, H, V>
{
    /// Takes the main trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, evaluates the polynomials over the LDE domain, commits to the
    /// polynomial evaluations, and creates a new [DefaultTraceLde] with the LDE of the main trace
    /// segment and the commitment.
    ///
    /// Returns a tuple containing a [TracePolyTable] with the trace polynomials for the main trace
    /// segment and the new [DefaultTraceLde].
    pub fn new(
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<E::BaseField>,
        domain: &StarkDomain<E::BaseField>,
    ) -> (Self, TracePolyTable<E>) {
        // extend the main execution trace and build a commitment to the extended trace
        let (main_segment_lde, main_segment_tree, main_segment_polys) =
            build_trace_commitment::<E, E::BaseField, H, V>(main_trace, domain);

        let trace_poly_table = TracePolyTable::new(main_segment_polys);
        let trace_lde = DefaultTraceLde {
            main_segment_lde,
            main_segment_tree,
            aux_segment_lde: None,
            aux_segment_tree: None,
            blowup: domain.trace_to_lde_blowup(),
            trace_info: trace_info.clone(),
            _h: PhantomData,
        };

        (trace_lde, trace_poly_table)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in the main segment of the execution trace.
    #[cfg(test)]
    pub fn main_segment_width(&self) -> usize {
        self.main_segment_lde.num_cols()
    }

    /// Returns a reference to [Matrix] representing the main trace segment.
    #[cfg(test)]
    pub fn get_main_segment(&self) -> &RowMatrix<E::BaseField> {
        &self.main_segment_lde
    }

    /// Returns the entire trace for the column at the specified index.
    #[cfg(test)]
    pub fn get_main_segment_column(&self, col_idx: usize) -> Vec<E::BaseField> {
        (0..self.main_segment_lde.num_rows())
            .map(|row_idx| self.main_segment_lde.get(col_idx, row_idx))
            .collect()
    }
}

impl<E, H, V> TraceLde<E> for DefaultTraceLde<E, H, V>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField, Digest = <V as VectorCommitment>::Item>
        + core::marker::Sync,
    V: VectorCommitment + core::marker::Sync,
{
    type HashFn = H;
    type VC = V;

    /// Returns the commitment to the low-degree extension of the main trace segment.
    fn get_main_trace_commitment(&self) -> V::Commitment {
        self.main_segment_tree.commitment()
    }

    /// Takes auxiliary trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, evaluates the polynomials over the LDE domain, and commits to the
    /// polynomial evaluations.
    ///
    /// Returns a tuple containing the column polynomials in coefficient from and the commitment
    /// to the polynomial evaluations over the LDE domain.
    ///
    /// # Panics
    ///
    /// This function will panic if any of the following are true:
    /// - the number of rows in the provided `aux_trace` does not match the main trace.
    /// - the auxiliary trace has been previously set already.
    fn set_aux_trace(
        &mut self,
        aux_trace: &ColMatrix<E>,
        domain: &StarkDomain<E::BaseField>,
    ) -> (ColMatrix<E>, V::Commitment) {
        // extend the auxiliary trace segment and build a commitment to the extended trace
        let (aux_segment_lde, aux_segment_tree, aux_segment_polys) =
            build_trace_commitment::<E, E, H, Self::VC>(aux_trace, domain);

        // check errors
        assert!(
            usize::from(self.aux_segment_lde.is_some()) < self.trace_info.num_aux_segments(),
            "the auxiliary trace has already been added"
        );
        assert_eq!(
            self.main_segment_lde.num_rows(),
            aux_segment_lde.num_rows(),
            "the number of rows in the auxiliary segment must be the same as in the main segment"
        );

        // save the lde and commitment
        self.aux_segment_lde = Some(aux_segment_lde);
        let root_hash = aux_segment_tree.commitment();
        self.aux_segment_tree = Some(aux_segment_tree);

        (aux_segment_polys, root_hash)
    }

    /// Reads current and next rows from the main trace segment into the specified frame.
    fn read_main_trace_frame_into(
        &self,
        lde_step: usize,
        frame: &mut EvaluationFrame<E::BaseField>,
    ) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        // copy main trace segment values into the frame
        frame.current_mut().copy_from_slice(self.main_segment_lde.row(lde_step));
        frame.next_mut().copy_from_slice(self.main_segment_lde.row(next_lde_step));
    }

    /// Reads current and next rows from the auxiliary trace segment into the specified frame.
    ///
    /// # Panics
    /// This currently assumes that there is exactly one auxiliary trace segment, and will panic
    /// otherwise.
    fn read_aux_trace_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<E>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        // copy auxiliary trace segment values into the frame
        let segment = self.aux_segment_lde.as_ref().expect("expected aux segment to be present");
        frame.current_mut().copy_from_slice(segment.row(lde_step));
        frame.next_mut().copy_from_slice(segment.row(next_lde_step));
    }

    fn read_lagrange_kernel_frame_into(
        &self,
        lde_step: usize,
        lagrange_kernel_aux_column_idx: usize,
        frame: &mut LagrangeKernelEvaluationFrame<E>,
    ) {
        let frame = frame.frame_mut();
        frame.truncate(0);

        let aux_segment =
            self.aux_segment_lde.as_ref().expect("expected aux segment to be present");

        frame.push(aux_segment.get(lagrange_kernel_aux_column_idx, lde_step));

        let frame_length = self.trace_info.length().ilog2() as usize + 1;
        for i in 0..frame_length - 1 {
            let shift = self.blowup() * (1 << i);
            let next_lde_step = (lde_step + shift) % self.trace_len();

            frame.push(aux_segment.get(lagrange_kernel_aux_column_idx, next_lde_step));
        }
    }

    /// Returns trace table rows at the specified positions along with an opening proof to these
    /// rows againt the already computed commitment.
    fn query(&self, positions: &[usize]) -> Vec<Queries> {
        // build queries for the main trace segment
        let mut result = vec![build_segment_queries::<E::BaseField, H, V>(
            &self.main_segment_lde,
            &self.main_segment_tree,
            positions,
        )];

        // build queries for the auxiliary trace segment
        if let Some(ref segment_tree) = self.aux_segment_tree {
            let segment_lde =
                self.aux_segment_lde.as_ref().expect("expected aux segment to be present");
            result.push(build_segment_queries::<E, H, V>(segment_lde, segment_tree, positions));
        }

        result
    }

    /// Returns the number of rows in the execution trace.
    fn trace_len(&self) -> usize {
        self.main_segment_lde.num_rows()
    }

    /// Returns blowup factor which was used to extend original execution trace into trace LDE.
    fn blowup(&self) -> usize {
        self.blowup
    }

    /// Returns the trace info of the execution trace.
    fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes a low-degree extension (LDE) of the provided execution trace over the specified
/// domain and builds a commitment to the extended trace.
///
/// The extension is performed by interpolating each column of the execution trace into a
/// polynomial of degree = trace_length - 1, and then evaluating the polynomial over the LDE
/// domain.
///
/// The trace commitment is computed by building a vector containing the hashes of each row of
/// the extended execution trace, then building a vector commitment to the resulting vector.
fn build_trace_commitment<E, F, H, V>(
    trace: &ColMatrix<F>,
    domain: &StarkDomain<E::BaseField>,
) -> (RowMatrix<F>, V, ColMatrix<F>)
where
    E: FieldElement,
    F: FieldElement<BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField, Digest = <V as VectorCommitment>::Item>,
    V: VectorCommitment,
{
    // extend the execution trace
    let (trace_lde, trace_polys) = {
        let span = info_span!(
            "extend_execution_trace",
            num_cols = trace.num_cols(),
            blowup = domain.trace_to_lde_blowup()
        )
        .entered();
        let trace_polys = trace.interpolate_columns();
        let trace_lde =
            RowMatrix::evaluate_polys_over::<DEFAULT_SEGMENT_WIDTH>(&trace_polys, domain);
        drop(span);

        (trace_lde, trace_polys)
    };
    assert_eq!(trace_lde.num_cols(), trace.num_cols());
    assert_eq!(trace_polys.num_rows(), trace.num_rows());
    assert_eq!(trace_lde.num_rows(), domain.lde_domain_size());

    // build trace commitment
    let tree_depth = trace_lde.num_rows().ilog2() as usize;
    let trace_tree = info_span!("compute_execution_trace_commitment", tree_depth)
        .in_scope(|| trace_lde.commit_to_rows::<H, V>());

    (trace_lde, trace_tree, trace_polys)
}

fn build_segment_queries<E, H, V>(
    segment_lde: &RowMatrix<E>,
    segment_tree: &V,
    positions: &[usize],
) -> Queries
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment,
{
    // for each position, get the corresponding row from the trace segment LDE and put all these
    // rows into a single vector
    let trace_states =
        positions.iter().map(|&pos| segment_lde.row(pos).to_vec()).collect::<Vec<_>>();

    // build a batch opening proof to the leaves specified by positions
    let trace_proof = segment_tree
        .open_many(positions)
        .expect("failed to generate a batch opening proof for trace queries");

    Queries::new::<H, E, V>(trace_proof.1, trace_states)
}
