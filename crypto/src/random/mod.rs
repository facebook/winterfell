// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::RandomCoinError, ElementHasher, Hasher};
use math::{FieldElement, StarkField};
use utils::collections::Vec;

mod default;
pub use default::DefaultRandomCoin;

// RANDOM COIN TRAIT
// ================================================================================================

/// Pseudo-random element generator for finite fields.
///
/// A random coin can be used to draw elements uniformly at random from the specified base field
/// or from any extension of the base field.
///
/// Internally we use a cryptographic hash function (which is specified via the `H` type parameter),
/// to draw elements from the field.
pub trait RandomCoin {
    type BaseField: StarkField;
    type Hasher: Hasher + ElementHasher;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a new random coin instantiated with the provided `seed`.
    fn new(seed: &[Self::BaseField]) -> Self;

    /// Reseeds the coin with the specified data by setting the new seed to hash(`seed` || `data`).
    fn reseed(&mut self, data: <Self::Hasher as Hasher>::Digest);

    /// Reseeds the coin with the specified value by setting the new seed to hash(`seed` ||
    /// `value`).
    fn reseed_with_int(&mut self, value: u64);

    /// Returns the number of leading zeros in the seed if it is interpreted as an integer in
    /// big-endian byte order.
    fn leading_zeros(&self) -> u32;

    /// Computes hash(`seed` || `value`) and returns the number of leading zeros in the resulting
    /// value if it is interpreted as an integer in big-endian byte order.
    fn check_leading_zeros(&self, value: u64) -> u32;

    /// Returns the next pseudo-random field element.
    ///
    /// # Errors
    /// Returns an error if a valid field element could not be generated after 1000 calls to the
    /// PRNG.
    fn draw<E: FieldElement<BaseField = Self::BaseField>>(&mut self) -> Result<E, RandomCoinError>;

    /// Returns a vector of unique integers selected from the range [0, domain_size).
    ///
    /// # Errors
    /// Returns an error if the specified number of unique integers could not be generated
    /// after 1000 calls to the PRNG.
    ///
    /// # Panics
    /// Panics if:
    /// - `domain_size` is not a power of two.
    /// - `num_values` is greater than or equal to `domain_size`.
    fn draw_integers(
        &mut self,
        num_values: usize,
        domain_size: usize,
    ) -> Result<Vec<usize>, RandomCoinError>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the next pair of pseudo-random field elements.
    ///
    /// # Errors
    /// Returns an error if any of the field elements could not be generated after 100 calls to
    /// the PRNG;
    fn draw_pair<E>(&mut self) -> Result<(E, E), RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Ok((self.draw()?, self.draw()?))
    }
}
