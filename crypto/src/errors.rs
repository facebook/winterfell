// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// MERKLE TREE ERROR
// ================================================================================================

/// Defines errors which can occur when using Merkle trees.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleTreeError {
    /// Fewer than two leaves were used to construct a Merkle tree.
    TooFewLeaves(usize, usize),
    /// Number of leaves for a Merkle tree was not a power of two.
    NumberOfLeavesNotPowerOfTwo(usize),
    /// A leaf index was greater than or equal to the number of leaves in the tree.
    LeafIndexOutOfBounds(usize, usize),
    /// A leaf index was included more than once in the list of indexes for a batch proof.
    DuplicateLeafIndex,
    /// No leaf indexes were provided for a batch Merkle proof.
    TooFewLeafIndexes,
    /// Too many leaf index were provided for a batch Merkle proof.
    TooManyLeafIndexes(usize, usize),
    /// Merkle proof is not valid for the specified position(s).
    InvalidProof,
}

impl fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewLeaves(expected, actual) => {
                write!(
                    f,
                    "a Merkle tree must contain at least {} leaves, but {} were provided",
                    expected, actual
                )
            }
            Self::NumberOfLeavesNotPowerOfTwo(num_leaves) => {
                write!(
                    f,
                    "number of leaves must be a power of two, but {} were provided",
                    num_leaves
                )
            }
            Self::LeafIndexOutOfBounds(expected, actual) => {
                write!(
                    f,
                    "a leaf index cannot exceed {}, but was {}",
                    expected, actual
                )
            }
            Self::DuplicateLeafIndex => {
                write!(f, "repeating indexes detected")
            }
            Self::TooFewLeafIndexes => {
                write!(f, "at least one leaf index must be provided")
            }
            Self::TooManyLeafIndexes(max_indexes, num_indexes) => {
                write!(
                    f,
                    "number of leaf indexes cannot exceed {}, but was {} provided",
                    max_indexes, num_indexes
                )
            }
            Self::InvalidProof => {
                write!(f, "Merkle proof is invalid")
            }
        }
    }
}

// RANDOM COIN ERROR
// ================================================================================================

/// Defines errors which can occur when drawing values from a random coin.
#[derive(Debug, PartialEq, Eq)]
pub enum RandomCoinError {
    /// A valid element could not be drawn from the field after the specified number of tries.
    FailedToDrawFieldElement(usize),
    /// The required number of integer values could not be drawn from the specified domain after
    /// the specified number of tries.
    FailedToDrawIntegers(usize, usize, usize),
}

impl fmt::Display for RandomCoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToDrawFieldElement(num_tries) => {
                write!(
                    f,
                    "failed to generate a valid field element after {} tries",
                    num_tries
                )
            }
            Self::FailedToDrawIntegers(num_expected, num_actual, num_tries) => {
                write!(
                    f,
                    "needed to draw {} integers from a domain, but drew only {} after {} tries",
                    num_expected, num_actual, num_tries
                )
            }
        }
    }
}
