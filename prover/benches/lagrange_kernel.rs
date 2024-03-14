// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::TraceInfo;
use criterion::{criterion_group, criterion_main, Criterion};
use math::{fields::f64::BaseElement, FieldElement};
use winter_prover::{matrix::ColMatrix, Trace};

fn prove_with_lagrange_kernel(c: &mut Criterion) {}

criterion_group!(lagrange_kernel_group, prove_with_lagrange_kernel);
criterion_main!(lagrange_kernel_group);

// TRACE
// =================================================================================================

struct LagrangeTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
    lagrange_kernel_col_idx: Option<usize>,
}

impl LagrangeTrace {
    fn new(
        trace_len: usize,
        aux_segment_width: usize,
        lagrange_kernel_col_idx: Option<usize>,
    ) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        let main_trace_col: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();

        let num_aux_segment_rands = if lagrange_kernel_col_idx.is_some() {
            trace_len.ilog2() as usize
        } else {
            1
        };

        Self {
            main_trace: ColMatrix::new(vec![main_trace_col]),
            info: TraceInfo::new_multi_segment(
                1,
                [aux_segment_width],
                [num_aux_segment_rands],
                trace_len,
                vec![],
            ),
            lagrange_kernel_col_idx,
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LagrangeTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main_trace
    }

    /// Each non-Lagrange kernel segment will simply take the sum the random elements + its index
    fn build_aux_segment<E: FieldElement<BaseField = Self::BaseField>>(
        &mut self,
        aux_segments: &[ColMatrix<E>],
        rand_elements: &[E],
        lagrange_kernel_rand_elements: Option<&[E]>,
    ) -> Option<ColMatrix<E>> {
        assert!(aux_segments.is_empty());

        let mut columns = Vec::new();

        for col_idx in 0..self.aux_trace_width() {
            let column = if self
                .lagrange_kernel_col_idx
                .map(|lagrange_col_idx| lagrange_col_idx == col_idx)
                .unwrap_or_default()
            {
                // building the Lagrange kernel column
                let r = lagrange_kernel_rand_elements.unwrap();

                let mut column = Vec::with_capacity(self.len());

                for row_idx in 0..self.len() {
                    let mut row_value = E::ZERO;
                    for (bit_idx, &r_i) in r.iter().enumerate() {
                        if row_idx & (1 << bit_idx) == 0 {
                            row_value *= E::ONE - r_i;
                        } else {
                            row_value *= r_i;
                        }
                    }
                    column.push(row_value);
                }

                column
            } else {
                // building a dummy auxiliary column
                (0..self.len())
                    .map(|row_idx| {
                        rand_elements.iter().fold(E::ZERO, |acc, &r| acc + r)
                            + E::from(row_idx as u32)
                    })
                    .collect()
            };

            columns.push(column);
        }

        Some(ColMatrix::new(columns))
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut air::EvaluationFrame<Self::BaseField>) {
        let next_row_idx = row_idx + 1;
        assert_ne!(next_row_idx, self.len());

        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }
}
