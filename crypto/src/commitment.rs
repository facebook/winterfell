// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::fmt::Debug;

use utils::{Deserializable, Serializable};

use crate::Hasher;

/// A vector commitment (VC) scheme.
///
/// This is a cryptographic primitive allowing one to commit, using a commitment string `com`, to
/// a vector of values (v_0, ..., v_{n-1}) such that one can later reveal the value at the i-th
/// position.
///
/// This is achieved by providing the value `v_i` together with a proof `proof_i` such that anyone
/// posessing `com` can be convinced, with high confidence, that the claim is true.
///
/// Vector commitment schemes usually have some batching properties in the sense that opening
/// proofs for a number of `(i, v_i)` can be batched together into one batch opening proof in order
/// to optimize both the proof size as well as the verification time.
///
/// The current implementation restricts both of the commitment string as well as the leaf values
/// to be `H::Digest` where `H` is a type parameter such that `H: Hasher`.
pub trait VectorCommitment<H: Hasher>: Sized {
    /// Options defining the VC i.e., public parameters.
    type Options: Default;
    /// Opening proof of some value at some position index.
    type Proof: Clone + Serializable + Deserializable;
    /// Batch opening proof of a number of {(i, v_i)}_{i ∈ S} for an index set.
    type MultiProof: Serializable + Deserializable;
    /// Error returned by the scheme.
    type Error: Debug;

    /// Creates a commitment to a vector of values (v_0, ..., v_{n-1}) using the default
    /// options.
    fn new(items: Vec<H::Digest>) -> Result<Self, Self::Error> {
        Self::with_options(items, Self::Options::default())
    }

    /// Creates a commitment to a vector of values (v_0, ..., v_{n-1}) given a set of
    /// options.
    fn with_options(items: Vec<H::Digest>, options: Self::Options) -> Result<Self, Self::Error>;

    /// Returns the commitment string to the committed values.
    fn commitment(&self) -> H::Digest;

    /// Returns the length of the vector committed to for `Self`.
    fn domain_len(&self) -> usize;

    /// Returns the length of the vector committed to for `Self::Proof`.
    fn get_proof_domain_len(proof: &Self::Proof) -> usize;

    /// Returns the length of the vector committed to for `Self::MultiProof`.
    fn get_multiproof_domain_len(proof: &Self::MultiProof) -> usize;

    /// Opens the value at a given index and provides a proof for the correctness of claimed value.
    fn open(&self, index: usize) -> Result<(H::Digest, Self::Proof), Self::Error>;

    /// Opens the values at a given index set and provides a proof for the correctness of claimed
    /// values.
    #[allow(clippy::type_complexity)]
    fn open_many(
        &self,
        indexes: &[usize],
    ) -> Result<(Vec<H::Digest>, Self::MultiProof), Self::Error>;

    /// Verifies that the claimed value is at the given index using a proof.
    fn verify(
        commitment: H::Digest,
        index: usize,
        item: H::Digest,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;

    /// Verifies that the claimed values are at the given set of indices using a batch proof.
    fn verify_many(
        commitment: H::Digest,
        indexes: &[usize],
        items: &[H::Digest],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error>;
}
