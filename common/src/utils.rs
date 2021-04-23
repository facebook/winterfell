// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::mem;
use crypto::Hasher;
use math::field::FieldElement;

// CONSTRAINT COMMITMENTS
// ================================================================================================

/// Computes the number of evaluations which will be committed together in a single leaf. For
/// example, if a node in the tree is 32 bytes, and our elements are 16 bytes each, we'll commit
/// to 4 elements in a single leaf.
pub fn evaluations_per_leaf<E: FieldElement, H: Hasher>() -> usize {
    // compute how many elements would fit into two digests
    let digest_size = mem::size_of::<H::Digest>();
    let result = 2 * digest_size / E::ELEMENT_BYTES;

    // make sure we take the biggest power of 2 which is smaller than or equal to result;
    // e.g. 2 -> 2, 3 -> 2, 4 -> 4
    1 << (mem::size_of::<usize>() * 8 - result.leading_zeros() as usize - 1)
}

/// Maps positions in a trace commitment tree to positions in the constraint evaluation
/// commitment tree.
pub fn map_trace_to_constraint_positions(
    trace_positions: &[usize],
    evaluations_per_leaf: usize,
) -> Vec<usize> {
    let mut result = Vec::with_capacity(trace_positions.len());
    for &position in trace_positions.iter() {
        let cp = position / evaluations_per_leaf;
        if !result.contains(&cp) {
            result.push(cp);
        }
    }
    result
}
