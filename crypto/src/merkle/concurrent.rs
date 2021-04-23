// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::HashFunction;
use rayon::prelude::*;
use std::slice;

// CONSTANTS
// ================================================================================================

pub const MIN_CONCURRENT_LEAVES: usize = 1024;

// PUBLIC FUNCTIONS
// ================================================================================================

/// Builds a all internal nodes of the Merkle using all available threads and stores the
/// results in a single vector such that root of the tree is at position 1, nodes immediately
/// under the root is at positions 2 and 3 etc.
pub fn build_merkle_nodes(leaves: &[[u8; 32]], hash: HashFunction) -> Vec<[u8; 32]> {
    // create un-initialized array to hold all intermediate nodes
    let n = leaves.len() / 2;
    let mut nodes = utils::uninit_vector(2 * n);
    nodes[0] = [0u8; 32];

    // re-interpret leaves as an array of two leaves fused together and use it to
    // build first row of internal nodes (parents of leaves)
    let two_leaves = unsafe { slice::from_raw_parts(leaves.as_ptr() as *const [u8; 64], n) };
    nodes[n..]
        .par_iter_mut()
        .zip(two_leaves.par_iter())
        .for_each(|(target, source)| hash(source, target));

    // calculate all other tree nodes, we can't use regular iterators  here because
    // access patterns are rather complicated - so, we use regular threads instead

    // number of sub-trees must always be a power of 2
    let num_subtrees = rayon::current_num_threads().next_power_of_two();
    let batch_size = n / num_subtrees;

    // re-interpret nodes as an array of two nodes fused together
    let two_nodes = unsafe { slice::from_raw_parts(nodes.as_ptr() as *const [u8; 64], n) };

    // process each subtree in a separate thread
    rayon::scope(|s| {
        for i in 0..num_subtrees {
            let nodes = unsafe { &mut *(&mut nodes[..] as *mut [[u8; 32]]) };
            s.spawn(move |_| {
                let mut batch_size = batch_size / 2;
                let mut start_idx = n / 2 + batch_size * i;
                while start_idx >= num_subtrees {
                    for k in (start_idx..(start_idx + batch_size)).rev() {
                        hash(&two_nodes[k], &mut nodes[k]);
                    }
                    start_idx /= 2;
                    batch_size /= 2;
                }
            });
        }
    });

    // finish the tip of the tree
    for i in (1..num_subtrees).rev() {
        hash(&two_nodes[i], &mut nodes[i]);
    }

    nodes
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn build_merkle_nodes_concurrent(ref data in vec(any::<[u8; 32]>(), 256..257).no_shrink()) {
            let sequential = super::super::build_merkle_nodes(&data, crate::hash::sha3);
            let concurrent = super::build_merkle_nodes(&data, crate::hash::sha3);
            assert_eq!(concurrent, sequential);
        }
    }
}
