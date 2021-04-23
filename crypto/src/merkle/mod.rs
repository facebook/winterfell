// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::HashFunction;
use std::{
    collections::{BTreeSet, HashMap},
    slice,
};

mod proofs;
pub use proofs::BatchMerkleProof;

#[cfg(feature = "concurrent")]
pub mod concurrent;

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

#[derive(Debug)]
pub struct MerkleTree {
    nodes: Vec<[u8; 32]>,
    leaves: Vec<[u8; 32]>,
}

// MERKLE TREE IMPLEMENTATION
// ================================================================================================

impl MerkleTree {
    /// Returns new merkle tree built from the provide leaves using the provided hash function.
    /// When `concurrent` feature is enabled, the tree is built using as many threads as are
    /// available in Rayon's global thread pool (usually as many threads as logical cores).
    /// Otherwise, the tree is built using a single thread.
    pub fn new(leaves: Vec<[u8; 32]>, hash: HashFunction) -> MerkleTree {
        assert!(
            leaves.len().is_power_of_two(),
            "number of leaves must be a power of 2"
        );
        assert!(leaves.len() >= 2, "a tree must contain at least 2 leaves");

        #[cfg(not(feature = "concurrent"))]
        let nodes = build_merkle_nodes(&leaves, hash);

        #[cfg(feature = "concurrent")]
        let nodes = if leaves.len() <= concurrent::MIN_CONCURRENT_LEAVES {
            build_merkle_nodes(&leaves, hash)
        } else {
            concurrent::build_merkle_nodes(&leaves, hash)
        };

        MerkleTree { nodes, leaves }
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> &[u8; 32] {
        &self.nodes[1]
    }

    /// Returns depth of the tree.
    pub fn depth(&self) -> usize {
        self.leaves.len().trailing_zeros() as usize
    }

    /// Returns leaf nodes of the tree.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Computes merkle path the given leaf index.
    pub fn prove(&self, index: usize) -> Vec<[u8; 32]> {
        assert!(index < self.leaves.len(), "invalid index {}", index);

        let mut proof = vec![self.leaves[index], self.leaves[index ^ 1]];

        let mut index = (index + self.nodes.len()) >> 1;
        while index > 1 {
            proof.push(self.nodes[index ^ 1]);
            index >>= 1;
        }

        proof
    }

    /// Computes merkle paths for the provided indexes and compresses the paths into a single proof.
    pub fn prove_batch(&self, indexes: &[usize]) -> BatchMerkleProof {
        let n = self.leaves.len();

        let index_map = map_indexes(indexes, n);
        let indexes = normalize_indexes(indexes);
        let mut values = vec![[0u8; 32]; index_map.len()];
        let mut nodes: Vec<Vec<[u8; 32]>> = Vec::with_capacity(indexes.len());

        // populate the proof with leaf node values
        let mut next_indexes: Vec<usize> = Vec::new();
        for index in indexes {
            let missing: Vec<[u8; 32]> = (index..index + 2)
                .flat_map(|i| {
                    let v = self.leaves[i];
                    if let Some(idx) = index_map.get(&i) {
                        values[*idx] = v;
                        None
                    } else {
                        Some(v)
                    }
                })
                .collect();
            nodes.push(missing);

            next_indexes.push((index + n) >> 1);
        }

        // add required internal nodes to the proof, skipping redundancies
        let depth = self.leaves.len().trailing_zeros() as u8;
        for _ in 1..depth {
            let indexes = next_indexes.clone();
            next_indexes.truncate(0);

            let mut i = 0;
            while i < indexes.len() {
                let sibling_index = indexes[i] ^ 1;
                if i + 1 < indexes.len() && indexes[i + 1] == sibling_index {
                    i += 1;
                } else {
                    nodes[i].push(self.nodes[sibling_index]);
                }

                // add parent index to the set of next indexes
                next_indexes.push(sibling_index >> 1);

                i += 1;
            }
        }

        BatchMerkleProof {
            values,
            nodes,
            depth,
        }
    }

    /// Checks whether the path for the specified index is valid.
    pub fn verify(root: &[u8; 32], index: usize, proof: &[[u8; 32]], hash: HashFunction) -> bool {
        let mut buf = [0u8; 64];
        let mut v = [0u8; 32];

        let r = index & 1;
        buf[..32].copy_from_slice(&proof[r]);
        buf[32..64].copy_from_slice(&proof[1 - r]);
        hash(&buf, &mut v);

        let mut index = (index + usize::pow(2, (proof.len() - 1) as u32)) >> 1;
        for p in proof.iter().skip(2) {
            if index & 1 == 0 {
                buf[..32].copy_from_slice(&v);
                buf[32..64].copy_from_slice(p);
            } else {
                buf[..32].copy_from_slice(p);
                buf[32..64].copy_from_slice(&v);
            }
            hash(&buf, &mut v);
            index >>= 1;
        }

        v == *root
    }

    /// Checks whether the batch proof contains merkle paths for the of the specified indexes.
    pub fn verify_batch(
        root: &[u8; 32],
        indexes: &[usize],
        proof: &BatchMerkleProof,
        hash: HashFunction,
    ) -> bool {
        match proof.get_root(indexes, hash) {
            Some(proof_root) => *root == proof_root,
            None => false,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_merkle_nodes(leaves: &[[u8; 32]], hash: HashFunction) -> Vec<[u8; 32]> {
    let n = leaves.len() / 2;

    // create un-initialized array to hold all intermediate nodes
    let mut nodes = utils::uninit_vector(2 * n);
    nodes[0] = [0u8; 32];

    // re-interpret leaves as an array of two leaves fused together
    let two_leaves = unsafe { slice::from_raw_parts(leaves.as_ptr() as *const [u8; 64], n) };

    // build first row of internal nodes (parents of leaves)
    for (i, j) in (0..n).zip(n..nodes.len()) {
        hash(&two_leaves[i], &mut nodes[j]);
    }

    // re-interpret nodes as an array of two nodes fused together
    let two_nodes = unsafe { slice::from_raw_parts(nodes.as_ptr() as *const [u8; 64], n) };

    // calculate all other tree nodes
    for i in (1..n).rev() {
        hash(&two_nodes[i], &mut nodes[i]);
    }

    nodes
}

fn map_indexes(indexes: &[usize], max_valid: usize) -> HashMap<usize, usize> {
    let mut map = HashMap::new();
    for (i, index) in indexes.iter().cloned().enumerate() {
        map.insert(index, i);
        assert!(index <= max_valid, "invalid index {}", index);
    }
    assert_eq!(indexes.len(), map.len(), "repeating indexes detected");
    map
}

fn normalize_indexes(indexes: &[usize]) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for &index in indexes {
        set.insert(index - (index & 1));
    }
    set.into_iter().collect()
}
