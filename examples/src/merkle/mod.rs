// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    utils::rescue::{Hash, Rescue128},
    Example, ExampleOptions,
};
use log::debug;
use prover::{
    self,
    crypto::{Hasher, MerkleTree},
    math::{fields::f128::BaseElement, utils::log2, FieldElement, StarkField},
    ProofOptions, StarkProof,
};
use std::time::Instant;
use verifier::{self, VerifierError};

mod air;
use air::{build_trace, MerkleAir, PublicInputs};

#[cfg(test)]
mod tests;

// MERKLE AUTHENTICATION PATH EXAMPLE
// ================================================================================================
pub fn get_example(options: ExampleOptions, tree_depth: usize) -> Box<dyn Example> {
    Box::new(MerkleExample::new(
        tree_depth,
        options.to_proof_options(28, 8),
    ))
}

pub struct MerkleExample {
    options: ProofOptions,
    tree_root: Hash,
    value: [BaseElement; 2],
    index: usize,
    path: Vec<Hash>,
}

impl MerkleExample {
    pub fn new(tree_depth: usize, options: ProofOptions) -> MerkleExample {
        assert!(
            (tree_depth + 1).is_power_of_two(),
            "tree depth must be one less than a power of 2"
        );
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index = (BaseElement::rand().as_int() % u128::pow(2, tree_depth as u32)) as usize;

        // build Merkle tree of the specified depth
        let now = Instant::now();
        let tree = build_merkle_tree(tree_depth, value, index);
        debug!(
            "Built Merkle tree of depth {} in {} ms",
            tree_depth,
            now.elapsed().as_millis(),
        );

        // compute Merkle path form the leaf specified by the index
        let now = Instant::now();
        let path = tree.prove(index);
        debug!(
            "Computed Merkle path from leaf {} to root {} in {} ms",
            index,
            hex::encode(tree.root()),
            now.elapsed().as_millis(),
        );

        MerkleExample {
            options,
            tree_root: *tree.root(),
            value,
            index,
            path,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for MerkleExample {
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for proving membership in a Merkle tree of depth {}\n\
            ---------------------",
            self.path.len()
        );
        let now = Instant::now();
        let trace = build_trace(self.value, &self.path, self.index);
        let trace_length = trace.len();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            tree_root: self.tree_root.to_elements(),
        };
        prover::prove::<MerkleAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            tree_root: self.tree_root.to_elements(),
        };
        verifier::verify::<MerkleAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let tree_root = self.tree_root.to_elements();
        let pub_inputs = PublicInputs {
            tree_root: [tree_root[1], tree_root[0]],
        };
        verifier::verify::<MerkleAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_merkle_tree(depth: usize, value: [BaseElement; 2], index: usize) -> MerkleTree<Rescue128> {
    let num_leaves = usize::pow(2, depth as u32);
    let leaf_elements = BaseElement::prng_vector([1; 32], num_leaves * 2);
    let mut leaves = Vec::new();
    for i in (0..leaf_elements.len()).step_by(2) {
        leaves.push(Hash::new(leaf_elements[i], leaf_elements[i + 1]));
    }

    // TODO: should use Rescue128::hash_elements()
    let value = Hash::new(value[0], value[1]);
    leaves[index] = Rescue128::merge_many(&[value]);

    MerkleTree::new(leaves)
}
