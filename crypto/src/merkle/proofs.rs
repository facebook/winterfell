// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::MerkleTreeError, Hasher};
use utils::{
    collections::{BTreeMap, Vec},
    string::ToString,
    ByteReader, Deserializable, DeserializationError, Serializable,
};

// CONSTANTS
// ================================================================================================

pub(super) const MAX_PATHS: usize = 255;

// BATCH MERKLE PROOF
// ================================================================================================

/// Multiple Merkle paths aggregated into a single proof.
///
/// The aggregation is done in a way which removes all duplicate internal nodes, and thus,
/// it is possible to achieve non-negligible compression as compared to naively concatenating
/// individual Merkle paths. The algorithm is for aggregation is a variation of
/// [Octopus](https://eprint.iacr.org/2017/933).
///
/// Currently, at most 255 paths can be aggregated into a single proof. This limitation is
/// imposed primarily for serialization purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMerkleProof<H: Hasher> {
    /// The leaves being proven
    pub leaves: Vec<H::Digest>,
    /// Hashes of Merkle Tree proof values above the leaf layer
    pub nodes: Vec<Vec<H::Digest>>,
    /// Depth of the leaves
    pub depth: u8,
}

impl<H: Hasher> BatchMerkleProof<H> {
    /// Constructs a batch Merkle proof from individual Merkle authentication paths.
    ///
    /// # Panics
    /// Panics if:
    /// * No paths have been provided (i.e., `paths` is an empty slice).
    /// * More than 255 paths have been provided.
    /// * Number of paths is not equal to the number of indexes.
    /// * Not all paths have the same length.
    pub fn from_paths(paths: &[Vec<H::Digest>], indexes: &[usize]) -> BatchMerkleProof<H> {
        // TODO: optimize this to reduce amount of vector cloning.
        assert!(!paths.is_empty(), "at least one path must be provided");
        assert!(
            paths.len() <= MAX_PATHS,
            "number of paths cannot exceed {MAX_PATHS}"
        );
        assert_eq!(
            paths.len(),
            indexes.len(),
            "number of paths must equal number of indexes"
        );

        let depth = paths[0].len();

        // sort indexes in ascending order, and also re-arrange paths accordingly
        let mut path_map = BTreeMap::new();
        for (&index, path) in indexes.iter().zip(paths.iter().cloned()) {
            assert_eq!(depth, path.len(), "not all paths have the same length");
            path_map.insert(index, path);
        }
        let indexes = path_map.keys().cloned().collect::<Vec<_>>();
        let paths = path_map.values().cloned().collect::<Vec<_>>();
        path_map.clear();

        let mut leaves = vec![H::Digest::default(); indexes.len()];
        let mut nodes: Vec<Vec<H::Digest>> = Vec::with_capacity(indexes.len());

        // populate values and the first layer of proof nodes
        let mut i = 0;
        while i < indexes.len() {
            leaves[i] = paths[i][0];
            if indexes.len() > i + 1 && are_siblings(indexes[i], indexes[i + 1]) {
                leaves[i + 1] = paths[i][1];
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

            core::mem::swap(&mut path_map, &mut next_path_map);
        }

        BatchMerkleProof {
            leaves,
            nodes,
            depth: (depth - 1) as u8,
        }
    }

    /// Computes a node to which all Merkle paths aggregated in this proof resolve.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Number of provided indexes is greater than 255.
    /// * Any of the specified `indexes` is greater than or equal to the number of leaves in the
    ///   tree for which this batch proof was generated.
    /// * List of indexes contains duplicates.
    /// * The proof does not resolve to a single root.
    pub fn get_root(&self, indexes: &[usize]) -> Result<H::Digest, MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }
        if indexes.len() > MAX_PATHS {
            return Err(MerkleTreeError::TooManyLeafIndexes(
                MAX_PATHS,
                indexes.len(),
            ));
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
                    if self.leaves.len() <= index1 {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.leaves[index1];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                            proof_pointers.push(0);
                        }
                        None => {
                            if self.nodes[i].is_empty() {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.nodes[i][0];
                            proof_pointers.push(1);
                        }
                    }
                }
                None => {
                    if self.nodes[i].is_empty() {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.nodes[i][0];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                        }
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                    proof_pointers.push(1);
                }
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

    /// Computes the uncompressed Merkle paths which aggregate to this proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Number of provided indexes is greater than 255.
    /// * Number of provided indexes does not match the number of leaf nodes in the proof.
    pub fn into_paths(self, indexes: &[usize]) -> Result<Vec<Vec<H::Digest>>, MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }
        if indexes.len() > MAX_PATHS {
            return Err(MerkleTreeError::TooManyLeafIndexes(
                MAX_PATHS,
                indexes.len(),
            ));
        }
        if indexes.len() != self.leaves.len() {
            return Err(MerkleTreeError::InvalidProof);
        }

        let mut partial_tree_map = BTreeMap::new();

        for (&i, leaf) in indexes.iter().zip(self.leaves.iter()) {
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
                    if self.leaves.len() <= index1 {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.leaves[index1];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                            proof_pointers.push(0);
                        }
                        None => {
                            if self.nodes[i].is_empty() {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.nodes[i][0];
                            proof_pointers.push(1);
                        }
                    }
                }
                None => {
                    if self.nodes[i].is_empty() {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.nodes[i][0];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                        }
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                    proof_pointers.push(1);
                }
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
            .map(|&i| get_path::<H>(i, &partial_tree_map, self.depth as usize))
            .collect()
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts all internal proof nodes into a vector of bytes.
    ///
    /// # Panics
    /// Panics if:
    /// * The proof contains more than 255 Merkle paths.
    /// * The Merkle paths consist of more than 255 nodes.
    pub fn serialize_nodes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // record total number of node vectors
        assert!(self.nodes.len() <= u8::MAX as usize, "too many paths");
        result.push(self.nodes.len() as u8);

        // record each node vector as individual bytes
        for nodes in self.nodes.iter() {
            assert!(nodes.len() <= u8::MAX as usize, "too many nodes");
            // record the number of nodes, and append all nodes to the paths buffer
            result.push(nodes.len() as u8);
            for node in nodes.iter() {
                result.append(&mut node.to_bytes());
            }
        }

        result
    }

    /// Parses internal nodes from the provided `node_bytes`, and constructs a batch Merkle proof
    /// from these nodes, provided `leaves`, and provided tree `depth`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No leaves were provided (i.e., `leaves` is an empty slice).
    /// * Number of provided leaves is greater than 255.
    /// * Tree `depth` was set to zero.
    /// * `node_bytes` could not be deserialized into a valid set of internal nodes.
    pub fn deserialize<R: ByteReader>(
        node_bytes: &mut R,
        leaves: Vec<H::Digest>,
        depth: u8,
    ) -> Result<Self, DeserializationError> {
        if depth == 0 {
            return Err(DeserializationError::InvalidValue(
                "tree depth must be greater than zero".to_string(),
            ));
        }
        if leaves.is_empty() {
            return Err(DeserializationError::InvalidValue(
                "at lease one leaf must be provided".to_string(),
            ));
        }
        if leaves.len() > MAX_PATHS {
            return Err(DeserializationError::InvalidValue(format!(
                "number of leaves cannot exceed {}, but {} were provided",
                MAX_PATHS,
                leaves.len()
            )));
        }

        let num_node_vectors = node_bytes.read_u8()? as usize;
        let mut nodes = Vec::with_capacity(num_node_vectors);
        for _ in 0..num_node_vectors {
            // read the number of digests in the vector
            let num_digests = node_bytes.read_u8()? as usize;

            // read the digests and add them to the node vector
            let digests = H::Digest::read_batch_from(node_bytes, num_digests)?;
            nodes.push(digests);
        }

        Ok(BatchMerkleProof {
            leaves,
            nodes,
            depth,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Two nodes are siblings if index of the left node is even and right node
/// immediately follows the left node.
fn are_siblings(left: usize, right: usize) -> bool {
    left & 1 == 0 && right - 1 == left
}

/// Computes the Merkle path from the computed (partial) tree.
pub fn get_path<H: Hasher>(
    index: usize,
    tree: &BTreeMap<usize, <H as Hasher>::Digest>,
    depth: usize,
) -> Result<Vec<H::Digest>, MerkleTreeError> {
    let mut index = index + (1 << depth);
    let leaf = if let Some(leaf) = tree.get(&index) {
        *leaf
    } else {
        return Err(MerkleTreeError::InvalidProof);
    };

    let mut proof = vec![leaf];
    while index > 1 {
        let leaf = if let Some(leaf) = tree.get(&(index ^ 1)) {
            *leaf
        } else {
            return Err(MerkleTreeError::InvalidProof);
        };

        proof.push(leaf);
        index >>= 1;
    }

    Ok(proof)
}
