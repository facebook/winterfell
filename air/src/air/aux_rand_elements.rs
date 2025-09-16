// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

/// Holds the randomly generated elements necessary to build the auxiliary trace.
#[derive(Debug, Clone)]
pub struct AuxRandElements<E> {
    rand_elements: Vec<E>,
}

impl<E> AuxRandElements<E> {
    /// Creates a new [`AuxRandElements`].
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self { rand_elements }
    }

    /// Returns the random elements needed to build all columns.
    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }
}
