// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::rescue::{
    self, CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS,
    STATE_WIDTH as HASH_STATE_WIDTH,
};
use crate::{
    utils::rescue::{Hash, Rescue128},
    Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Sha3_256,
};
use core::marker::PhantomData;
use log::debug;
use rand_utils::{rand_value, rand_vector};
use std::time::Instant;
use winterfell::{
    crypto::{DefaultRandomCoin, Digest, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField},
    ProofOptions, Prover, StarkProof, Trace, TraceTable, VerifierError,
};

mod air;
use air::{MerkleAir, PublicInputs};

mod prover;
use prover::MerkleProver;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 7;

// MERKLE AUTHENTICATION PATH EXAMPLE
// ================================================================================================
pub fn get_example(
    options: &ExampleOptions,
    tree_depth: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => Ok(Box::new(MerkleExample::<Blake3_192>::new(
            tree_depth, options,
        ))),
        HashFunction::Blake3_256 => Ok(Box::new(MerkleExample::<Blake3_256>::new(
            tree_depth, options,
        ))),
        HashFunction::Sha3_256 => Ok(Box::new(MerkleExample::<Sha3_256>::new(
            tree_depth, options,
        ))),
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct MerkleExample<H: ElementHasher> {
    options: ProofOptions,
    tree_root: Hash,
    value: [BaseElement; 2],
    index: usize,
    path: Vec<Hash>,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MerkleExample<H> {
    pub fn new(tree_depth: usize, options: ProofOptions) -> Self {
        assert!(
            (tree_depth + 1).is_power_of_two(),
            "tree depth must be one less than a power of 2"
        );
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index =
            (rand_value::<BaseElement>().as_int() % u128::pow(2, tree_depth as u32)) as usize;

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
        let path = tree.prove(index).unwrap();
        debug!(
            "Computed Merkle path from leaf {} to root {} in {} ms",
            index,
            hex::encode(tree.root().as_bytes()),
            now.elapsed().as_millis(),
        );

        MerkleExample {
            options,
            tree_root: *tree.root(),
            value,
            index,
            path,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for MerkleExample<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for proving membership in a Merkle tree of depth {}\n\
            ---------------------",
            self.path.len()
        );
        // create the prover
        let prover = MerkleProver::<H>::new(self.options.clone());

        // generate the execution trace
        let now = Instant::now();
        let trace = prover.build_trace(self.value, &self.path, self.index);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            trace_length.ilog2(),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            tree_root: self.tree_root.to_elements(),
        };
        winterfell::verify::<MerkleAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let tree_root = self.tree_root.to_elements();
        let pub_inputs = PublicInputs {
            tree_root: [tree_root[1], tree_root[0]],
        };
        winterfell::verify::<MerkleAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_merkle_tree(depth: usize, value: [BaseElement; 2], index: usize) -> MerkleTree<Rescue128> {
    let num_leaves = usize::pow(2, depth as u32);
    let leaf_elements: Vec<BaseElement> = rand_vector(num_leaves * 2);
    let mut leaves = Vec::new();
    for i in (0..leaf_elements.len()).step_by(2) {
        leaves.push(Hash::new(leaf_elements[i], leaf_elements[i + 1]));
    }

    leaves[index] = Rescue128::digest(&value);
    MerkleTree::new(leaves).unwrap()
}
