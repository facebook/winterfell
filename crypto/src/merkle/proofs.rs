// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::HashFunction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    pub values: Vec<[u8; 32]>,
    pub nodes: Vec<Vec<[u8; 32]>>,
    pub depth: u8,
}

impl BatchMerkleProof {
    /// Constructs a batch Merkle proof from individual Merkle authentication paths.
    /// TODO: optimize this to reduce amount of vector cloning.
    pub fn from_paths(paths: &[Vec<[u8; 32]>], indexes: &[usize]) -> BatchMerkleProof {
        assert_eq!(
            paths.len(),
            indexes.len(),
            "number of paths must equal number of indexes"
        );
        assert!(!paths.is_empty(), "at least one path must be provided");

        let depth = paths[0].len();

        // sort indexes in ascending order, and also re-arrange paths accordingly
        let mut path_map = BTreeMap::new();
        for (&index, path) in indexes.iter().zip(paths.iter().cloned()) {
            path_map.insert(index, path);
        }
        let indexes = path_map.keys().cloned().collect::<Vec<_>>();
        let paths = path_map.values().cloned().collect::<Vec<_>>();
        path_map.clear();

        let mut values = vec![[0u8; 32]; indexes.len()];
        let mut nodes: Vec<Vec<[u8; 32]>> = Vec::with_capacity(indexes.len());

        // populate values and the first layer of proof nodes
        let mut i = 0;
        while i < indexes.len() {
            values[i] = paths[i][0];
            if indexes.len() > i + 1 && are_siblings(indexes[i], indexes[i + 1]) {
                values[i + 1] = paths[i][1];
                nodes.push(vec![]);
                i += 1;
            } else {
                nodes.push(vec![paths[i][1]]);
            }
            path_map.insert(indexes[i] >> 1, paths[i].clone());
            i += 1;
        }

        // populate all remaining layers of proof nodes
        for d in 2..depth {
            let indexes = path_map.keys().cloned().collect::<Vec<_>>();
            let mut next_path_map = BTreeMap::new();

            let mut i = 0;
            while i < indexes.len() {
                let index = indexes[i];
                let path = path_map.get(&index).unwrap();
                if indexes.len() > i + 1 && are_siblings(index, indexes[i + 1]) {
                    i += 1;
                } else {
                    nodes[i].push(path[d]);
                }
                next_path_map.insert(index >> 1, path.clone());
                i += 1;
            }

            std::mem::swap(&mut path_map, &mut next_path_map);
        }

        BatchMerkleProof {
            values,
            nodes,
            depth: (depth - 1) as u8,
        }
    }

    /// Computes a node to which all Merkle paths aggregated in this proof resolve.
    pub fn get_root(&self, indexes: &[usize], hash: HashFunction) -> Option<[u8; 32]> {
        let mut buf = [0u8; 64];
        let mut v = HashMap::new();

        // replace odd indexes, offset, and sort in ascending order
        let offset = usize::pow(2, self.depth as u32);
        let index_map = super::map_indexes(indexes, offset - 1);
        let indexes = super::normalize_indexes(indexes);
        if indexes.len() != self.nodes.len() {
            return None;
        }

        // for each index use values to compute parent nodes
        let mut next_indexes: Vec<usize> = Vec::new();
        let mut proof_pointers: Vec<usize> = Vec::with_capacity(indexes.len());
        for (i, index) in indexes.into_iter().enumerate() {
            // copy values of leaf sibling leaf nodes into the buffer
            match index_map.get(&index) {
                Some(&index1) => {
                    if self.values.len() <= index1 {
                        return None;
                    }
                    buf[..32].copy_from_slice(&self.values[index1]);
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.values.len() <= index2 {
                                return None;
                            }
                            buf[32..64].copy_from_slice(&self.values[index2]);
                            proof_pointers.push(0);
                        }
                        None => {
                            if self.nodes[i].is_empty() {
                                return None;
                            }
                            buf[32..64].copy_from_slice(&self.nodes[i][0]);
                            proof_pointers.push(1);
                        }
                    }
                }
                None => {
                    if self.nodes[i].is_empty() {
                        return None;
                    }
                    buf[..32].copy_from_slice(&self.nodes[i][0]);
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.values.len() <= index2 {
                                return None;
                            }
                            buf[32..64].copy_from_slice(&self.values[index2]);
                        }
                        None => return None,
                    }
                    proof_pointers.push(1);
                }
            }

            // hash sibling nodes into their parent
            let mut parent = [0u8; 32];
            hash(&buf, &mut parent);

            let parent_index = (offset + index) >> 1;
            v.insert(parent_index, parent);
            next_indexes.push(parent_index);
        }

        // iteratively move up, until we get to the root
        for _ in 1..self.depth {
            let indexes = next_indexes.clone();
            next_indexes.truncate(0);

            let mut i = 0;
            while i < indexes.len() {
                let node_index = indexes[i];
                let sibling_index = node_index ^ 1;

                // determine the sibling
                let sibling: &[u8; 32];
                if i + 1 < indexes.len() && indexes[i + 1] == sibling_index {
                    sibling = match v.get(&sibling_index) {
                        Some(sibling) => sibling,
                        None => return None,
                    };
                    i += 1;
                } else {
                    let pointer = proof_pointers[i];
                    if self.nodes[i].len() <= pointer {
                        return None;
                    }
                    sibling = &self.nodes[i][pointer];
                    proof_pointers[i] += 1;
                }

                // get the node from the map of hashed nodes
                let node = match v.get(&node_index) {
                    Some(node) => node,
                    None => return None,
                };

                // compute parent node from node and sibling
                if node_index & 1 != 0 {
                    buf[..32].copy_from_slice(sibling);
                    buf[32..64].copy_from_slice(node);
                } else {
                    buf[..32].copy_from_slice(node);
                    buf[32..64].copy_from_slice(sibling);
                }
                let mut parent = [0u8; 32];
                hash(&buf, &mut parent);

                // add the parent node to the next set of nodes
                let parent_index = node_index >> 1;
                v.insert(parent_index, parent);
                next_indexes.push(parent_index);

                i += 1;
            }
        }

        v.remove(&1)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Two nodes are siblings if index of the left node is even and right node
/// immediately follows the left node.
fn are_siblings(left: usize, right: usize) -> bool {
    left & 1 == 0 && right - 1 == left
}
