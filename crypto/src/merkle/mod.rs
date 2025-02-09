// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::slice;

mod proofs;
pub use proofs::BatchMerkleProof;

use crate::{Hasher, MerkleTreeError, VectorCommitment};

#[cfg(feature = "concurrent")]
pub mod concurrent;

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

/// A fully-balanced Merkle tree.
///
/// In this implementation, a Merkle tree consists of two types of nodes: leaves and internal nodes
/// (one of which is a tree root). All nodes must be instances of the digest specified by the
/// [Hasher] used to build the tree.
///
/// ```text
///       *        <- tree root
///     /   \
///    /     \
///   *       *    <- internal nodes
///  / \     / \
/// o   o   o   o  <- leaves
/// |   |   |   |
/// #   #   #   #  <- values
/// ```
///
/// A tree can be built from a slice of leaves using [MerkleTree::new()] function. Thus, the user
/// is responsible for performing the first level of hashing (i.e., hashing values into leaf
/// nodes). The number of leaves must always be a power of two so that the tree is fully balanced,
/// and a tree must contain at least two leaves.
///
/// The depth of a tree is zero-based. Thus, a tree with two leaves has depth 1, a tree with four
/// leaves has depth 2 etc.
///
/// When the crate is compiled with `concurrent` feature enabled, tree construction will be
/// performed in multiple threads (usually, as many threads as there are logical cores on the
/// machine). The number of threads can be configured via `RAYON_NUM_THREADS` environment variable.
///
/// To generate an inclusion proof for a given leaf, [MerkleTree::prove()] method can be used.
/// You can also use [MerkleTree::prove_batch()] method to generate inclusion proofs for multiple
/// leaves. The advantage of the batch method is that redundant internal nodes are removed from
/// the batch proof, thereby compressing it (we use a variation of the
/// [Octopus](https://eprint.iacr.org/2017/933) algorithm).
///
/// To verify proofs, [MerkleTree::verify()] and [MerkleTree::verify_batch()] functions can be
/// used respectively.
///
/// # Examples
/// ```
/// # use winter_crypto::{MerkleTree, Hasher, hashers::Blake3_256};
/// # use math::fields::f128::BaseElement;
/// type Blake3 = Blake3_256<BaseElement>;
///
/// // build a tree
/// let leaves = [
///     Blake3::hash(&[1u8]),
///     Blake3::hash(&[2u8]),
///     Blake3::hash(&[3u8]),
///     Blake3::hash(&[4u8]),
/// ];
/// let tree = MerkleTree::<Blake3>::new(leaves.to_vec()).unwrap();
/// assert_eq!(2, tree.depth());
/// assert_eq!(leaves, tree.leaves());
///
/// // generate a proof
/// let (leaf, proof) = tree.prove(2).unwrap();
/// assert_eq!(2, proof.len());
/// assert_eq!(leaves[2], leaf);
///
/// // verify proof
/// assert!(MerkleTree::<Blake3>::verify(*tree.root(), 2, leaf, &proof).is_ok());
/// assert!(MerkleTree::<Blake3>::verify(*tree.root(), 1, leaf, &proof).is_err());
/// ```
#[derive(Debug)]
pub struct MerkleTree<H: Hasher> {
    nodes: Vec<H::Digest>,
    leaves: Vec<H::Digest>,
}

/// Merkle tree opening consisting of a leaf value and a Merkle path leading from this leaf
/// up to the root (excluding the root itself).
pub type MerkleTreeOpening<H> = (<H as Hasher>::Digest, Vec<<H as Hasher>::Digest>);

// MERKLE TREE IMPLEMENTATION
// ================================================================================================

impl<H: Hasher> MerkleTree<H> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns new Merkle tree built from the provide leaves using hash function specified by the
    /// `H` generic parameter.
    ///
    /// When `concurrent` feature is enabled, the tree is built using multiple threads.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Fewer than two leaves were provided.
    /// * Number of leaves is not a power of two.
    pub fn new(leaves: Vec<H::Digest>) -> Result<Self, MerkleTreeError> {
        if leaves.len() < 2 {
            return Err(MerkleTreeError::TooFewLeaves(2, leaves.len()));
        }
        if !leaves.len().is_power_of_two() {
            return Err(MerkleTreeError::NumberOfLeavesNotPowerOfTwo(leaves.len()));
        }

        #[cfg(not(feature = "concurrent"))]
        let nodes = build_merkle_nodes::<H>(&leaves);

        #[cfg(feature = "concurrent")]
        let nodes = if leaves.len() <= concurrent::MIN_CONCURRENT_LEAVES {
            build_merkle_nodes::<H>(&leaves)
        } else {
            concurrent::build_merkle_nodes::<H>(&leaves)
        };

        Ok(MerkleTree { nodes, leaves })
    }

    /// Forms a MerkleTree from a list of nodes and leaves.
    ///
    /// Nodes are supplied as a vector where the root is stored at position 1.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Fewer than two leaves were provided.
    /// * Number of leaves is not a power of two.
    ///
    /// # Panics
    /// Panics if nodes doesn't have the same length as leaves.
    pub fn from_raw_parts(
        nodes: Vec<H::Digest>,
        leaves: Vec<H::Digest>,
    ) -> Result<Self, MerkleTreeError> {
        if leaves.len() < 2 {
            return Err(MerkleTreeError::TooFewLeaves(2, leaves.len()));
        }
        if !leaves.len().is_power_of_two() {
            return Err(MerkleTreeError::NumberOfLeavesNotPowerOfTwo(leaves.len()));
        }
        assert_eq!(nodes.len(), leaves.len());
        Ok(MerkleTree { nodes, leaves })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> &H::Digest {
        &self.nodes[1]
    }

    /// Returns depth of the tree.
    ///
    /// The depth of a tree is zero-based. Thus, a tree with two leaves has depth 1, a tree with
    /// four leaves has depth 2 etc.
    pub fn depth(&self) -> usize {
        self.leaves.len().ilog2() as usize
    }

    /// Returns leaf nodes of the tree.
    pub fn leaves(&self) -> &[H::Digest] {
        &self.leaves
    }

    // PROVING METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a Merkle proof to a leaf at the specified `index`.
    ///
    /// The leaf itself will be the first element of the returned tuple.
    ///
    /// # Errors
    /// Returns an error if the specified index is greater than or equal to the number of leaves
    /// in the tree.
    pub fn prove(&self, index: usize) -> Result<MerkleTreeOpening<H>, MerkleTreeError> {
        if index >= self.leaves.len() {
            return Err(MerkleTreeError::LeafIndexOutOfBounds(self.leaves.len(), index));
        }
        let leaf = self.leaves[index];
        let mut proof = vec![self.leaves[index ^ 1]];

        let mut index = (index + self.nodes.len()) >> 1;
        while index > 1 {
            proof.push(self.nodes[index ^ 1]);
            index >>= 1;
        }

        Ok((leaf, proof))
    }

    /// Computes Merkle proofs for the provided indexes, compresses the proofs into a single batch
    /// and returns the batch proof alongside the leaves at the provided indexes.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Any of the provided indexes are greater than or equal to the number of leaves in the tree.
    /// * List of indexes contains duplicates.
    pub fn prove_batch(
        &self,
        indexes: &[usize],
    ) -> Result<(Vec<H::Digest>, BatchMerkleProof<H>), MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }

        let index_map = map_indexes(indexes, self.depth())?;
        let indexes = normalize_indexes(indexes);
        let mut leaves = vec![H::Digest::default(); index_map.len()];
        let mut nodes: Vec<Vec<H::Digest>> = Vec::with_capacity(indexes.len());

        // populate the proof with leaf node values
        let n = self.leaves.len();
        let mut next_indexes: Vec<usize> = Vec::new();
        for index in indexes {
            let missing: Vec<H::Digest> = (index..index + 2)
                .flat_map(|i| {
                    let v = self.leaves[i];
                    if let Some(idx) = index_map.get(&i) {
                        leaves[*idx] = v;
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
        for _ in 1..self.depth() {
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

        Ok((leaves, BatchMerkleProof { depth: self.depth() as u8, nodes }))
    }

    // VERIFICATION METHODS
    // --------------------------------------------------------------------------------------------

    /// Checks whether the `proof` for the given `leaf` at the specified `index` is valid.
    ///
    /// # Errors
    /// Returns an error if the specified `proof` (which is a Merkle path) does not resolve to the
    /// specified `root`.
    pub fn verify(
        root: H::Digest,
        index: usize,
        leaf: H::Digest,
        proof: &[H::Digest],
    ) -> Result<(), MerkleTreeError> {
        let r = index & 1;
        let mut v = if r == 0 {
            H::merge(&[leaf, proof[0]])
        } else {
            H::merge(&[proof[0], leaf])
        };

        let mut index = (index + 2usize.pow((proof.len()) as u32)) >> 1;
        for &p in proof.iter().skip(1) {
            v = if index & 1 == 0 {
                H::merge(&[v, p])
            } else {
                H::merge(&[p, v])
            };
            index >>= 1;
        }

        if v != root {
            return Err(MerkleTreeError::InvalidProof);
        }
        Ok(())
    }

    /// Checks whether the batch `proof` contains Merkle proofs resolving to `root` for
    /// the provided `leaves` at the specified `indexes`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Any of the specified `indexes` is greater than or equal to the number of leaves in the
    ///   tree from which the batch proof was generated.
    /// * List of indexes contains duplicates.
    /// * Any of the proofs in the batch proof does not resolve to the specified `root`.
    pub fn verify_batch(
        root: &H::Digest,
        indexes: &[usize],
        leaves: &[H::Digest],
        proof: &BatchMerkleProof<H>,
    ) -> Result<(), MerkleTreeError> {
        if *root != proof.get_root(indexes, leaves)? {
            return Err(MerkleTreeError::InvalidProof);
        }
        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the internal nodes of a Merkle tree defined by the specified leaves.
///
/// The internal nodes are turned as a vector where the root is stored at position 1, its children
/// are stored at positions 2, 3, their children are stored at positions 4, 5, 6, 7 etc.
///
/// This function is exposed primarily for benchmarking purposes. It is not intended to be used
/// directly by the end users of the crate.
pub fn build_merkle_nodes<H: Hasher>(leaves: &[H::Digest]) -> Vec<H::Digest> {
    let n = leaves.len() / 2;

    // create un-initialized array to hold all intermediate nodes
    let mut nodes = unsafe { utils::uninit_vector::<H::Digest>(2 * n) };
    nodes[0] = H::Digest::default();

    // re-interpret leaves as an array of two leaves fused together
    let two_leaves = unsafe { slice::from_raw_parts(leaves.as_ptr() as *const [H::Digest; 2], n) };

    // build first row of internal nodes (parents of leaves)
    for (i, j) in (0..n).zip(n..nodes.len()) {
        nodes[j] = H::merge(&two_leaves[i]);
    }

    // re-interpret nodes as an array of two nodes fused together
    let two_nodes = unsafe { slice::from_raw_parts(nodes.as_ptr() as *const [H::Digest; 2], n) };

    // calculate all other tree nodes
    for i in (1..n).rev() {
        nodes[i] = H::merge(&two_nodes[i]);
    }

    nodes
}

fn map_indexes(
    indexes: &[usize],
    tree_depth: usize,
) -> Result<BTreeMap<usize, usize>, MerkleTreeError> {
    let num_leaves = 2usize.pow(tree_depth as u32);
    let mut map = BTreeMap::new();
    for (i, index) in indexes.iter().cloned().enumerate() {
        map.insert(index, i);
        if index >= num_leaves {
            return Err(MerkleTreeError::LeafIndexOutOfBounds(num_leaves, index));
        }
    }

    if indexes.len() != map.len() {
        return Err(MerkleTreeError::DuplicateLeafIndex);
    }

    Ok(map)
}

fn normalize_indexes(indexes: &[usize]) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for &index in indexes {
        set.insert(index - (index & 1));
    }
    set.into_iter().collect()
}

// VECTOR COMMITMENT IMPLEMENTATION
// ================================================================================================

impl<H: Hasher> VectorCommitment<H> for MerkleTree<H> {
    type Options = ();

    type Proof = Vec<H::Digest>;

    type MultiProof = BatchMerkleProof<H>;

    type Error = MerkleTreeError;

    fn with_options(items: Vec<H::Digest>, _options: Self::Options) -> Result<Self, Self::Error> {
        MerkleTree::new(items)
    }

    fn commitment(&self) -> H::Digest {
        *self.root()
    }

    fn domain_len(&self) -> usize {
        1 << self.depth()
    }

    fn get_proof_domain_len(proof: &Self::Proof) -> usize {
        1 << proof.len()
    }

    fn get_multiproof_domain_len(proof: &Self::MultiProof) -> usize {
        1 << proof.depth
    }

    fn open(&self, index: usize) -> Result<(H::Digest, Self::Proof), Self::Error> {
        self.prove(index)
    }

    fn open_many(
        &self,
        indexes: &[usize],
    ) -> Result<(Vec<H::Digest>, Self::MultiProof), Self::Error> {
        self.prove_batch(indexes)
    }

    fn verify(
        commitment: H::Digest,
        index: usize,
        item: H::Digest,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        MerkleTree::<H>::verify(commitment, index, item, proof)
    }

    fn verify_many(
        commitment: H::Digest,
        indexes: &[usize],
        items: &[H::Digest],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        MerkleTree::<H>::verify_batch(&commitment, indexes, items, proof)
    }
}
