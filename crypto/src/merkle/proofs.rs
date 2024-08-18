// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{collections::BTreeMap, vec::Vec};

use utils::{ByteReader, Deserializable, DeserializationError, Serializable};

use super::MerkleTreeOpening;
use crate::{errors::MerkleTreeError, Hasher};

// BATCH MERKLE PROOF
// ================================================================================================

/// Multiple Merkle proofs aggregated into a single proof.
///
/// The aggregation is done in a way which removes all duplicate internal nodes, and thus,
/// it is possible to achieve non-negligible compression as compared to naively concatenating
/// individual Merkle proofs. The algorithm is for aggregation is a variation of
/// [Octopus](https://eprint.iacr.org/2017/933).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMerkleProof<H: Hasher> {
    /// Hashes of Merkle Tree proof values above the leaf layer
    pub nodes: Vec<Vec<H::Digest>>,
    /// Depth of the leaves
    pub depth: u8,
}

impl<H: Hasher> BatchMerkleProof<H> {
    /// Constructs a batch Merkle proof from collection of single Merkle proofs.
    ///
    /// # Panics
    /// Panics if:
    /// * No proofs have been provided (i.e., `proofs` is an empty slice).
    /// * Number of proofs is not equal to the number of indexes.
    /// * Not all proofs have the same length.
    pub fn from_single_proofs(
        proofs: &[MerkleTreeOpening<H>],
        indexes: &[usize],
    ) -> BatchMerkleProof<H> {
        // TODO: optimize this to reduce amount of vector cloning.
        assert!(!proofs.is_empty(), "at least one proof must be provided");
        assert_eq!(proofs.len(), indexes.len(), "number of proofs must equal number of indexes");

        let depth = proofs[0].1.len();

        // sort indexes in ascending order, and also re-arrange proofs accordingly
        let mut proof_map = BTreeMap::new();
        for (&index, proof) in indexes.iter().zip(proofs.iter().cloned()) {
            assert_eq!(depth, proof.1.len(), "not all proofs have the same length");
            proof_map.insert(index, proof);
        }
        let indexes = proof_map.keys().cloned().collect::<Vec<_>>();
        let proofs = proof_map.values().cloned().collect::<Vec<_>>();
        proof_map.clear();

        let mut leaves = vec![H::Digest::default(); indexes.len()];
        let mut nodes: Vec<Vec<H::Digest>> = Vec::with_capacity(indexes.len());

        // populate values and the first layer of proof nodes
        let mut i = 0;
        while i < indexes.len() {
            leaves[i] = proofs[i].0;

            if indexes.len() > i + 1 && are_siblings(indexes[i], indexes[i + 1]) {
                leaves[i + 1] = proofs[i].1[0];
                nodes.push(vec![]);
                i += 1;
            } else {
                nodes.push(vec![proofs[i].1[0]]);
            }
            proof_map.insert(indexes[i] >> 1, proofs[i].clone());
            i += 1;
        }

        // populate all remaining layers of proof nodes
        for d in 1..depth {
            let indexes = proof_map.keys().cloned().collect::<Vec<_>>();
            let mut next_proof_map = BTreeMap::new();

            let mut i = 0;
            while i < indexes.len() {
                let index = indexes[i];
                let proof = proof_map.get(&index).unwrap();
                if indexes.len() > i + 1 && are_siblings(index, indexes[i + 1]) {
                    i += 1;
                } else {
                    nodes[i].push(proof.1[d]);
                }
                next_proof_map.insert(index >> 1, proof.clone());
                i += 1;
            }

            core::mem::swap(&mut proof_map, &mut next_proof_map);
        }

        BatchMerkleProof { nodes, depth: (depth) as u8 }
    }

    /// Computes a node to which all Merkle proofs aggregated in this proof resolve.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Any of the specified `indexes` is greater than or equal to the number of leaves in the
    ///   tree for which this batch proof was generated.
    /// * List of indexes contains duplicates.
    /// * The proof does not resolve to a single root.
    pub fn get_root(
        &self,
        indexes: &[usize],
        leaves: &[H::Digest],
    ) -> Result<H::Digest, MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }

        let mut buf = [H::Digest::default(); 2];
        let mut v = BTreeMap::new();

        // replace odd indexes, offset, and sort in ascending order
        let index_map = super::map_indexes(indexes, self.depth as usize)?;
        let indexes = super::normalize_indexes(indexes);
        if indexes.len() != self.nodes.len() {
            return Err(MerkleTreeError::InvalidProof);
        }

        // for each index use values to compute parent nodes
        let offset = 2usize.pow(self.depth as u32);
        let mut next_indexes: Vec<usize> = Vec::new();
        let mut proof_pointers: Vec<usize> = Vec::with_capacity(indexes.len());
        for (i, index) in indexes.into_iter().enumerate() {
            // copy values of leaf sibling leaf nodes into the buffer
            match index_map.get(&index) {
                Some(&index1) => {
                    if leaves.len() <= index1 {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = leaves[index1];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = leaves[index2];
                            proof_pointers.push(0);
                        },
                        None => {
                            if self.nodes[i].is_empty() {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.nodes[i][0];
                            proof_pointers.push(1);
                        },
                    }
                },
                None => {
                    if self.nodes[i].is_empty() {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.nodes[i][0];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = leaves[index2];
                        },
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                    proof_pointers.push(1);
                },
            }

            // hash sibling nodes into their parent
            let parent = H::merge(&buf);

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
                let sibling: H::Digest;
                if i + 1 < indexes.len() && indexes[i + 1] == sibling_index {
                    sibling = match v.get(&sibling_index) {
                        Some(sibling) => *sibling,
                        None => return Err(MerkleTreeError::InvalidProof),
                    };
                    i += 1;
                } else {
                    let pointer = proof_pointers[i];
                    if self.nodes[i].len() <= pointer {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    sibling = self.nodes[i][pointer];
                    proof_pointers[i] += 1;
                }

                // get the node from the map of hashed nodes
                let node = match v.get(&node_index) {
                    Some(node) => node,
                    None => return Err(MerkleTreeError::InvalidProof),
                };

                // compute parent node from node and sibling
                if node_index & 1 != 0 {
                    buf[0] = sibling;
                    buf[1] = *node;
                } else {
                    buf[0] = *node;
                    buf[1] = sibling;
                }
                let parent = H::merge(&buf);

                // add the parent node to the next set of nodes
                let parent_index = node_index >> 1;
                v.insert(parent_index, parent);
                next_indexes.push(parent_index);

                i += 1;
            }
        }
        v.remove(&1).ok_or(MerkleTreeError::InvalidProof)
    }

    /// Computes the uncompressed individual Merkle proofs which aggregate to this batch proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Number of provided indexes does not match the number of leaf nodes in the proof.
    pub fn into_openings(
        self,
        leaves: &[H::Digest],
        indexes: &[usize],
    ) -> Result<Vec<MerkleTreeOpening<H>>, MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }
        if indexes.len() != leaves.len() {
            return Err(MerkleTreeError::InvalidProof);
        }

        let mut partial_tree_map = BTreeMap::new();

        for (&i, leaf) in indexes.iter().zip(leaves.iter()) {
            partial_tree_map.insert(i + (1 << (self.depth)), *leaf);
        }

        let mut buf = [H::Digest::default(); 2];
        let mut v = BTreeMap::new();

        // replace odd indexes, offset, and sort in ascending order
        let original_indexes = indexes;
        let index_map = super::map_indexes(indexes, self.depth as usize)?;
        let indexes = super::normalize_indexes(indexes);
        if indexes.len() != self.nodes.len() {
            return Err(MerkleTreeError::InvalidProof);
        }

        // for each index use values to compute parent nodes
        let offset = 2usize.pow(self.depth as u32);
        let mut next_indexes: Vec<usize> = Vec::new();
        let mut proof_pointers: Vec<usize> = Vec::with_capacity(indexes.len());
        for (i, index) in indexes.into_iter().enumerate() {
            // copy values of leaf sibling leaf nodes into the buffer
            match index_map.get(&index) {
                Some(&index1) => {
                    if leaves.len() <= index1 {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = leaves[index1];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = leaves[index2];
                            proof_pointers.push(0);
                        },
                        None => {
                            if self.nodes[i].is_empty() {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.nodes[i][0];
                            proof_pointers.push(1);
                        },
                    }
                },
                None => {
                    if self.nodes[i].is_empty() {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.nodes[i][0];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = leaves[index2];
                        },
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                    proof_pointers.push(1);
                },
            }

            // hash sibling nodes into their parent and add it to partial_tree
            let parent = H::merge(&buf);
            partial_tree_map.insert(offset + index, buf[0]);
            partial_tree_map.insert((offset + index) ^ 1, buf[1]);
            let parent_index = (offset + index) >> 1;
            v.insert(parent_index, parent);
            next_indexes.push(parent_index);
            partial_tree_map.insert(parent_index, parent);
        }

        // iteratively move up, until we get to the root
        for _ in 1..self.depth {
            let indexes = next_indexes.clone();
            next_indexes.clear();

            let mut i = 0;
            while i < indexes.len() {
                let node_index = indexes[i];
                let sibling_index = node_index ^ 1;

                // determine the sibling
                let sibling = if i + 1 < indexes.len() && indexes[i + 1] == sibling_index {
                    i += 1;
                    match v.get(&sibling_index) {
                        Some(sibling) => *sibling,
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                } else {
                    let pointer = proof_pointers[i];
                    if self.nodes[i].len() <= pointer {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    proof_pointers[i] += 1;
                    self.nodes[i][pointer]
                };

                // get the node from the map of hashed nodes
                let node = match v.get(&node_index) {
                    Some(node) => node,
                    None => return Err(MerkleTreeError::InvalidProof),
                };

                // compute parent node from node and sibling
                partial_tree_map.insert(node_index ^ 1, sibling);
                let parent = if node_index & 1 != 0 {
                    H::merge(&[sibling, *node])
                } else {
                    H::merge(&[*node, sibling])
                };

                // add the parent node to the next set of nodes and partial_tree
                let parent_index = node_index >> 1;
                v.insert(parent_index, parent);
                next_indexes.push(parent_index);
                partial_tree_map.insert(parent_index, parent);

                i += 1;
            }
        }

        original_indexes
            .iter()
            .map(|&i| get_proof::<H>(i, &partial_tree_map, self.depth as usize))
            .collect()
    }
}

// SERIALIZATION / DESERIALIZATION
// --------------------------------------------------------------------------------------------

impl<H: Hasher> Serializable for BatchMerkleProof<H> {
    /// Writes all internal proof nodes into the provided target.
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.depth);
        target.write_usize(self.nodes.len());

        for nodes in self.nodes.iter() {
            // record the number of nodes, and append all nodes to the proof buffer
            nodes.write_into(target);
        }
    }
}

impl<H: Hasher> Deserializable for BatchMerkleProof<H> {
    /// Parses internal nodes from the provided `source`, and constructs a batch Merkle proof
    /// from these nodes.
    ///
    /// # Errors
    /// Returns an error if:
    /// * `source` could not be deserialized into a valid set of internal nodes.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let depth = source.read_u8()?;
        let num_node_vectors = source.read_usize()?;

        let mut nodes = Vec::with_capacity(num_node_vectors);
        for _ in 0..num_node_vectors {
            // read the digests and add them to the node vector
            let digests = Vec::<_>::read_from(source)?;
            nodes.push(digests);
        }

        Ok(BatchMerkleProof { nodes, depth })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Two nodes are siblings if index of the left node is even and right node
/// immediately follows the left node.
fn are_siblings(left: usize, right: usize) -> bool {
    left & 1 == 0 && right - 1 == left
}

/// Computes the Merkle proof from the computed (partial) tree.
pub fn get_proof<H: Hasher>(
    index: usize,
    tree: &BTreeMap<usize, <H as Hasher>::Digest>,
    depth: usize,
) -> Result<MerkleTreeOpening<H>, MerkleTreeError> {
    let mut index = index + (1 << depth);
    let leaf = if let Some(leaf) = tree.get(&index) {
        *leaf
    } else {
        return Err(MerkleTreeError::InvalidProof);
    };

    let mut proof = vec![];
    while index > 1 {
        let leaf = if let Some(leaf) = tree.get(&(index ^ 1)) {
            *leaf
        } else {
            return Err(MerkleTreeError::InvalidProof);
        };

        proof.push(leaf);
        index >>= 1;
    }

    Ok((leaf, proof))
}
