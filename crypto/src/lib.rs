// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains cryptographic primitives used in STARK proof generation and verification.
//! These include:
//!
//! * **Hash functions** - which are defined using the [Hasher] trait. The crate also contains two
//!   implementations of the trait for BLAKE3 and SHA3 hash functions.
//! * **Merkle trees** - which are used as a commitment scheme in the STARK protocol. The
//!   [MerkleTree] implementation supports concurrent tree construction as well as compact
//!   aggregation of Merkle paths implemented using a variation of the
//!   [Octopus](https://eprint.iacr.org/2017/933) algorithm.
//! * **PRNG** - which is used to generate pseudo-random elements in a finite field. The
//!   [RandomCoin] implementation uses a cryptographic hash function to generate pseudo-random
//!   elements form a seed.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod hash;
pub use hash::{Digest, ElementHasher, Hasher};
pub mod hashers {
    //! Contains implementations of currently supported hash functions.

    pub use super::hash::Blake3_192;
    pub use super::hash::Blake3_256;
    pub use super::hash::GriffinJive64_256;
    pub use super::hash::Rp62_248;
    pub use super::hash::Rp64_256;
    pub use super::hash::RpJive64_256;
    pub use super::hash::Sha3_256;
}

mod merkle;
pub use merkle::{build_merkle_nodes, BatchMerkleProof, MerkleTree};

#[cfg(feature = "concurrent")]
pub use merkle::concurrent;

mod random;
pub use random::{DefaultRandomCoin, RandomCoin};

mod errors;
pub use errors::{MerkleTreeError, RandomCoinError};
