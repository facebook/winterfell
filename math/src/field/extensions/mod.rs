// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod quadratic;
pub use quadratic::QuadExtension;

use super::{FieldElement, StarkField};

// EXTENSIBLE FIELD TRAIT
// ================================================================================================

/// TODO: add documentation
pub trait ExtensibleField<const N: usize>: StarkField {
    const EXTENDED_ONE: [Self; N];

    fn mul(a: [Self; N], b: [Self; N]) -> [Self; N];
    fn inv(x: [Self; N]) -> [Self; N];
    fn conjugate(x: [Self; N]) -> [Self; N];
}
