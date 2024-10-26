// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree,
    math::{fields::f128::BaseElement, FieldElement},
};

use crate::{
    lamport::signature::PublicKey,
    utils::rescue::{Hash, Rescue128},
};

// AGGREGATED PUBLIC KEY
// ================================================================================================

pub struct AggPublicKey {
    keys: Vec<PublicKey>,
    tree: MerkleTree<Rescue128>,
}

impl AggPublicKey {
    pub fn new(mut keys: Vec<PublicKey>) -> Self {
        // sort keys in ascending order
        keys.sort();

        // convert keys to arrays of bytes; each key is hashed using Rescue hash function; the
        // initial hashing makes the AIR design a little simpler
        let mut leaves: Vec<Hash> = Vec::new();
        for key in keys.iter() {
            leaves.push(Rescue128::digest(&key.to_elements()));
        }

        // pad the list of keys with zero keys to make sure the number of leaves is greater than
        // the number of keys and is a power of two
        let num_leaves = if leaves.len().is_power_of_two() {
            (leaves.len() + 1).next_power_of_two()
        } else {
            leaves.len().next_power_of_two()
        };
        let zero_hash = Rescue128::digest(&[BaseElement::ZERO, BaseElement::ZERO]);
        for _ in leaves.len()..num_leaves {
            leaves.push(zero_hash);
        }

        // build a Merkle tree of all leaves
        let tree = MerkleTree::new(leaves).unwrap();

        AggPublicKey { keys, tree }
    }

    /// Returns a 32-byte representation of the aggregated public key.
    pub fn root(&self) -> Hash {
        *self.tree.root()
    }

    /// Returns the number of individual keys aggregated into this key.
    pub fn num_keys(&self) -> usize {
        self.keys.len()
    }

    /// Returns number of leaves in the aggregated public key; this will always be greater
    // than the number of individual keys.
    pub fn num_leaves(&self) -> usize {
        self.tree.leaves().len()
    }

    /// Returns an individual key at the specified index, if one exists.
    pub fn get_key(&self, index: usize) -> Option<PublicKey> {
        if index < self.keys.len() {
            Some(self.keys[index])
        } else {
            None
        }
    }

    /// Returns a Merkle path to the specified leaf.
    pub fn get_leaf_path(&self, index: usize) -> Vec<Hash> {
        let (leaf, path) = self.tree.prove(index).unwrap();
        let mut result = vec![leaf];
        result.extend_from_slice(&path);
        result
    }
}
