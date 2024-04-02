// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Two-dimensional data structures used to represent polynomials and polynomial evaluations.

mod row_matrix;
pub use row_matrix::{build_segments, get_evaluation_offsets, RowMatrix};

mod col_matrix;
pub use col_matrix::{ColMatrix, ColumnIter};

mod segments;
pub use segments::Segment;

#[cfg(test)]
mod tests;
