// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod univariate;
pub use univariate::{CompressedUnivariatePoly, CompressedUnivariatePolyEvals};

mod multilinear;
pub use multilinear::{EqFunction, MultiLinearPoly};