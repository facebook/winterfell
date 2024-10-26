// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::slice;

use utils::{iterators::*, rayon};

use crate::Hasher;

// CONSTANTS
// ================================================================================================

pub const MIN_CONCURRENT_LEAVES: usize = 1024;

// PUBLIC FUNCTIONS
// ================================================================================================

/// Returns internal nodes of a Merkle tree constructed from the provided leaves.
///
/// Builds all internal nodes of the Merkle using all available threads and stores the
/// results in a single vector such that root of the tree is at position 1, nodes immediately
/// under the root is at positions 2 and 3 etc.
pub fn build_merkle_nodes<H: Hasher>(leaves: &[H::Digest]) -> Vec<H::Digest> {
    let n = leaves.len() / 2;

    // create un-initialized array to hold all intermediate nodes
    let mut nodes = unsafe { utils::uninit_vector::<H::Digest>(2 * n) };
    nodes[0] = H::Digest::default();

    // re-interpret leaves as an array of two leaves fused together and use it to
    // build first row of internal nodes (parents of leaves)
    let two_leaves = unsafe { slice::from_raw_parts(leaves.as_ptr() as *const [H::Digest; 2], n) };
    nodes[n..]
        .par_iter_mut()
        .zip(two_leaves.par_iter())
        .for_each(|(target, source)| *target = H::merge(source));

    // calculate all other tree nodes, we can't use regular iterators  here because
    // access patterns are rather complicated - so, we use regular threads instead

    // number of sub-trees must always be a power of 2
    let num_subtrees = rayon::current_num_threads().next_power_of_two();
    let batch_size = n / num_subtrees;

    // re-interpret nodes as an array of two nodes fused together
    let two_nodes = unsafe { slice::from_raw_parts(nodes.as_ptr() as *const [H::Digest; 2], n) };

    // process each subtree in a separate thread
    rayon::scope(|s| {
        for i in 0..num_subtrees {
            let nodes = unsafe { &mut *(&mut nodes[..] as *mut [H::Digest]) };
            s.spawn(move |_| {
                let mut batch_size = batch_size / 2;
                let mut start_idx = n / 2 + batch_size * i;
                while start_idx >= num_subtrees {
                    for k in (start_idx..(start_idx + batch_size)).rev() {
                        nodes[k] = H::merge(&two_nodes[k]);
                    }
                    start_idx /= 2;
                    batch_size /= 2;
                }
            });
        }
    });

    // finish the tip of the tree
    for i in (1..num_subtrees).rev() {
        nodes[i] = H::merge(&two_nodes[i]);
    }

    nodes
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use math::fields::f128::BaseElement;
    use proptest::{collection::vec, prelude::*};

    use crate::hash::{ByteDigest, Sha3_256};

    proptest! {
        #[test]
        fn build_merkle_nodes_concurrent(ref data in vec(any::<[u8; 32]>(), 256..257).no_shrink()) {
            let leaves = ByteDigest::bytes_as_digests(data).to_vec();
            let sequential = super::super::build_merkle_nodes::<Sha3_256<BaseElement>>(&leaves);
            let concurrent = super::build_merkle_nodes::<Sha3_256<BaseElement>>(&leaves);
            assert_eq!(concurrent, sequential);
        }
    }
}
