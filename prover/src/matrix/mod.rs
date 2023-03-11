// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod row_matrix;
pub use row_matrix::RowMatrix;

mod col_matrix;
pub use col_matrix::{ColumnIter, Matrix, MultiColumnIter};

mod segments;
use segments::{Segment, SEGMENT_WIDTH};

#[cfg(test)]
mod tests;
