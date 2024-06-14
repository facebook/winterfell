use alloc::vec::Vec;
use core::fmt::Debug;

use utils::{Deserializable, Serializable};

/// A vector commitment (VC) scheme.
///
/// This is a cryptographic primitive allowing one to commit, using a commitment string `com`, to
/// a vector of values (v_0, ..., v_{n-1}) such that one can later reveal the value at the i-th
/// position.
/// This is achieved by providing the value `v_i` together with a proof `proof_i` such that anyone
/// posessing `com` can be convinced, with high confidence, that the claim is true.
///
/// Vector commitment schemes usually have some batching properties in the sense that opening
/// proofs for number of `(i, v_i)` can be batched together into one batch opening proof in order
/// to optimize both the proof size as well as the verification time.
pub trait VectorCommitment: Sized {
    /// Options defining the VC i.e., public parameters.
    type Options: Default;
    /// Values commited to.
    type Item: Clone + Serializable + Deserializable + Send;
    /// Commitment string.
    type Commitment: Copy + Serializable + Deserializable + From<Self::Item>;
    /// Opening proof of some value at some position index.
    type Proof: Clone + Serializable + Deserializable;
    /// Batch opening proof of a number of {(i, v_i)}_{i ∈ S} for an index set.
    type MultiProof: Serializable + Deserializable;
    /// Error returned by the scheme.
    type Error: Debug;

    /// Creates a commitment to a vector of values (v_0, ..., v_{n-1}) given a set of
    /// options.
    fn new(items: Vec<Self::Item>, options: Self::Options) -> Result<Self, Self::Error>;

    /// Returns the commitment string to the commited values.
    fn commitment(&self) -> Self::Commitment;

    /// Opens the value at a given index and provides a proof for the correctness of claimed value.
    fn open(&self, index: usize) -> Result<(Self::Item, Self::Proof), Self::Error>;

    #[allow(clippy::type_complexity)]
    /// Opens the values at a given index set and provides a proof for the correctness of claimed
    /// values.
    fn open_many(
        &self,
        indexes: &[usize],
    ) -> Result<(Vec<Self::Item>, Self::MultiProof), Self::Error>;

    /// Verifies that the claimed value is at the given index using a proof.
    fn verify(
        commitment: Self::Commitment,
        index: usize,
        item: Self::Item,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;

    /// Verifies that the claimed values are at the given set of indices using a batch proof.
    fn verify_many(
        commitment: Self::Commitment,
        indexes: &[usize],
        items: &[Self::Item],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error>;
}
