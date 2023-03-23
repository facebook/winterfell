// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use structopt::StructOpt;
use winterfell::{
    crypto::hashers::{GriffinJive64_256, Rp64_256, RpJive64_256},
    math::fields::f128::BaseElement,
    FieldExtension, ProofOptions, StarkProof, VerifierError,
};

pub mod fibonacci;
#[cfg(feature = "std")]
pub mod lamport;
#[cfg(feature = "std")]
pub mod merkle;
pub mod rescue;
#[cfg(feature = "std")]
pub mod rescue_raps;
pub mod utils;
pub mod vdf;

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

pub type Blake3_192 = winterfell::crypto::hashers::Blake3_192<BaseElement>;
pub type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;
pub type Sha3_256 = winterfell::crypto::hashers::Sha3_256<BaseElement>;

pub trait Example {
    fn prove(&self) -> StarkProof;
    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError>;
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError>;
}

// EXAMPLE OPTIONS
// ================================================================================================

#[derive(StructOpt, Debug)]
#[structopt(name = "winterfell", about = "Winterfell examples")]
pub struct ExampleOptions {
    #[structopt(subcommand)]
    pub example: ExampleType,

    /// Hash function used in the protocol
    #[structopt(short = "h", long = "hash_fn", default_value = "blake3_256")]
    hash_fn: String,

    /// Number of queries to include in a proof
    #[structopt(short = "q", long = "queries")]
    num_queries: Option<usize>,

    /// Blowup factor for low degree extension
    #[structopt(short = "b", long = "blowup")]
    blowup_factor: Option<usize>,

    /// Grinding factor for query seed
    #[structopt(short = "g", long = "grinding", default_value = "16")]
    grinding_factor: u32,

    /// Field extension degree for composition polynomial
    #[structopt(short = "e", long = "field_extension", default_value = "1")]
    field_extension: u32,

    /// Folding factor for FRI protocol
    #[structopt(short = "f", long = "folding", default_value = "8")]
    folding_factor: usize,
}

impl ExampleOptions {
    pub fn to_proof_options(&self, q: usize, b: usize) -> (ProofOptions, HashFunction) {
        let num_queries = self.num_queries.unwrap_or(q);
        let blowup_factor = self.blowup_factor.unwrap_or(b);
        let field_extension = match self.field_extension {
            1 => FieldExtension::None,
            2 => FieldExtension::Quadratic,
            3 => FieldExtension::Cubic,
            val => panic!("'{val}' is not a valid field extension option"),
        };

        let hash_fn = match self.hash_fn.as_str() {
            "blake3_192" => HashFunction::Blake3_192,
            "blake3_256" => HashFunction::Blake3_256,
            "sha3_256" => HashFunction::Sha3_256,
            "rp64_256" => HashFunction::Rp64_256,
            "rp_jive64_256" => HashFunction::RpJive64_256,
            "griffin_jive64_256" => HashFunction::GriffinJive64_256,
            val => panic!("'{val}' is not a valid hash function option"),
        };

        (
            ProofOptions::new(
                num_queries,
                blowup_factor,
                self.grinding_factor,
                field_extension,
                self.folding_factor,
                31,
            ),
            hash_fn,
        )
    }

    /// Returns security level of the input proof in bits.
    pub fn get_proof_security_level(&self, proof: &StarkProof, conjectured: bool) -> usize {
        let security_level = match self.hash_fn.as_str() {
            "blake3_192" => proof.security_level::<Blake3_192>(conjectured),
            "blake3_256" => proof.security_level::<Blake3_256>(conjectured),
            "sha3_256" => proof.security_level::<Sha3_256>(conjectured),
            "rp64_256" => proof.security_level::<Rp64_256>(conjectured),
            "rp_jive64_256" => proof.security_level::<RpJive64_256>(conjectured),
            "griffin_jive64_256" => proof.security_level::<GriffinJive64_256>(conjectured),
            val => panic!("'{val}' is not a valid hash function option"),
        };

        security_level as usize
    }
}

#[derive(StructOpt, Debug)]
//#[structopt(about = "available examples")]
pub enum ExampleType {
    /// Compute a Fibonacci sequence using trace table with 2 registers
    Fib {
        /// Length of Fibonacci sequence; must be a power of two
        #[structopt(short = "n", default_value = "1048576")]
        sequence_length: usize,
    },
    /// Compute a Fibonacci sequence using trace table with 8 registers
    Fib8 {
        /// Length of Fibonacci sequence; must be a power of two
        #[structopt(short = "n", default_value = "1048576")]
        sequence_length: usize,
    },
    /// Compute a multiplicative Fibonacci sequence using trace table with 2 registers
    Mulfib {
        /// Length of Fibonacci sequence; must be a power of two
        #[structopt(short = "n", default_value = "1048576")]
        sequence_length: usize,
    },
    /// Compute a multiplicative Fibonacci sequence using trace table with 8 registers
    Mulfib8 {
        /// Length of Fibonacci sequence; must be a power of two
        #[structopt(short = "n", default_value = "1048576")]
        sequence_length: usize,
    },
    /// Compute a Fibonacci sequence using trace table with 2 registers in `f64` field.
    FibSmall {
        /// Length of Fibonacci sequence; must be a power of two
        #[structopt(short = "n", default_value = "65536")]
        sequence_length: usize,
    },
    /// Execute a simple VDF function
    Vdf {
        /// Number of steps in the VDF function; must be a power of two
        #[structopt(short = "n", default_value = "1048576")]
        num_steps: usize,
    },
    /// Similar to the VDF example, but exempts an extra row from transition constraints.
    VdfExempt {
        /// Number of steps in the VDF function; must be one less than a power of two
        #[structopt(short = "n", default_value = "1048575")]
        num_steps: usize,
    },
    /// Compute a hash chain using Rescue hash function
    Rescue {
        /// Length of the hash chain; must be a power of two
        #[structopt(short = "n", default_value = "1024")]
        chain_length: usize,
    },
    /// Compute two hash chains absorbing sequences that are a permutation of each other
    #[cfg(feature = "std")]
    RescueRaps {
        /// Length of the hash chain; must be a power of two and at least 4
        #[structopt(short = "n", default_value = "1024")]
        chain_length: usize,
    },
    /// Compute a root of a Merkle path using Rescue hash function
    #[cfg(feature = "std")]
    Merkle {
        /// Depth of the Merkle tree; must be one less than a power of two
        #[structopt(short = "n", default_value = "7")]
        tree_depth: usize,
    },
    /// Compute an aggregate Lamport+ signature
    #[cfg(feature = "std")]
    LamportA {
        /// Number of signatures to aggregate; must be a power of two
        #[structopt(short = "n", default_value = "4")]
        num_signatures: usize,
    },
    /// Compute a threshold Lamport+ signature
    #[cfg(feature = "std")]
    LamportT {
        /// Number of signers; must be one less than a power of two
        #[structopt(short = "n", default_value = "3")]
        num_signers: usize,
    },
}

/// Defines a set of hash functions available for the provided examples. Some examples may not
/// support all listed hash functions.
///
/// Choice of a hash function has a direct impact on proof generation time, proof size, and proof
/// soundness. In general, sounds of the proof is bounded by the collision resistance of the hash
/// function used by the protocol.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashFunction {
    /// BLAKE3 hash function with 192 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 96 bits.
    Blake3_192,

    /// BLAKE3 hash function with 256 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    Blake3_256,

    /// SHA3 hash function with 256 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    Sha3_256,

    /// Rescue Prime hash function with 256 bit output. It only works in `f64` field.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    Rp64_256,

    /// Rescue Prime hash function with 256 bit output. It only works in `f64` field.
    /// This instance uses the Jive compression mode in Merkle trees.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    RpJive64_256,

    /// Griffin hash function with 256 bit output. It only works in `f64` field.
    /// This instance uses the Jive compression mode in Merkle trees.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    GriffinJive64_256,
}
