// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use math::{FieldElement, StarkField};

use crate::{errors::RandomCoinError, Digest, ElementHasher, RandomCoin};

// DEFAULT RANDOM COIN IMPLEMENTATION
// ================================================================================================

/// Pseudo-random element generator for finite fields, which is a default implementation of the
/// RandomCoin trait.
///
/// A random coin can be used to draw elements uniformly at random from the specified base field
/// or from any extension of the base field.
///
/// Internally we use a cryptographic hash function (which is specified via the `H` type parameter),
/// to draw elements from the field. The coin works roughly as follows:
/// - The internal state of the coin consists of a `seed` and a `counter`. At instantiation time,
///   the `seed` is set to a hash of the provided bytes, and the `counter` is set to 0.
/// - To draw the next element, we increment the `counter` and compute hash(`seed` || `counter`). If
///   the resulting value is a valid field element, we return the result; otherwise we try again
///   until a valid element is found or the number of allowed tries is exceeded.
/// - We can also re-seed the coin with a new value. During the reseeding procedure, the seed is set
///   to hash(`old_seed` || `new_seed`), and the counter is reset to 0.
///
/// # Examples
/// ```
/// # use winter_crypto::{RandomCoin, DefaultRandomCoin, Hasher, hashers::Blake3_256};
/// # use math::fields::f128::BaseElement;
/// // initial elements for seeding the random coin
/// let seed = &[
///     BaseElement::new(1),
///     BaseElement::new(2),
///     BaseElement::new(3),
///     BaseElement::new(4),
/// ];
///
/// // instantiate a random coin using BLAKE3 as the hash function
/// let mut coin = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
///
/// // should draw different elements each time
/// let e1 = coin.draw::<BaseElement>().unwrap();
/// let e2 = coin.draw::<BaseElement>().unwrap();
/// assert_ne!(e1, e2);
///
/// let e3 = coin.draw::<BaseElement>().unwrap();
/// assert_ne!(e1, e3);
/// assert_ne!(e2, e3);
///
/// // should draw same elements for the same seed
/// let mut coin2 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
/// let mut coin1 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
/// let e1 = coin1.draw::<BaseElement>().unwrap();
/// let e2 = coin2.draw::<BaseElement>().unwrap();
/// assert_eq!(e1, e2);
///
/// // should draw different elements based on seed
/// let mut coin1 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
/// let seed = &[
///     BaseElement::new(2),
///     BaseElement::new(3),
///     BaseElement::new(4),
///     BaseElement::new(5),
/// ];
/// let mut coin2 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
/// let e1 = coin1.draw::<BaseElement>().unwrap();
/// let e2 = coin2.draw::<BaseElement>().unwrap();
/// assert_ne!(e1, e2);
/// ```
pub struct DefaultRandomCoin<H: ElementHasher> {
    seed: H::Digest,
    counter: u64,
}

impl<H: ElementHasher> DefaultRandomCoin<H> {
    /// Updates the state by incrementing the counter and returns hash(seed || counter)
    fn next(&mut self) -> H::Digest {
        self.counter += 1;
        H::merge_with_int(self.seed, self.counter)
    }
}

impl<B: StarkField, H: ElementHasher<BaseField = B>> RandomCoin for DefaultRandomCoin<H> {
    type BaseField = B;
    type Hasher = H;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new random coin instantiated with the provided `seed`.
    fn new(seed: &[Self::BaseField]) -> Self {
        let seed = H::hash_elements(seed);
        Self { seed, counter: 0 }
    }

    // RESEEDING
    // --------------------------------------------------------------------------------------------

    /// Reseeds the coin with the specified data by setting the new seed to hash(`seed` || `data`).
    ///
    /// # Examples
    /// ```
    /// # use winter_crypto::{RandomCoin, DefaultRandomCoin, Hasher, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// // initial elements for seeding the random coin
    /// let seed = &[
    ///     BaseElement::new(1),
    ///     BaseElement::new(2),
    ///     BaseElement::new(3),
    ///     BaseElement::new(4),
    /// ];
    ///
    /// let mut coin1 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
    /// let mut coin2 = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
    ///
    /// // should draw the same element form both coins
    /// let e1 = coin1.draw::<BaseElement>().unwrap();
    /// let e2 = coin2.draw::<BaseElement>().unwrap();
    /// assert_eq!(e1, e2);
    ///
    /// // after reseeding should draw different elements
    /// coin2.reseed(Blake3_256::<BaseElement>::hash(&[2, 3, 4, 5]));
    /// let e1 = coin1.draw::<BaseElement>().unwrap();
    /// let e2 = coin2.draw::<BaseElement>().unwrap();
    /// assert_ne!(e1, e2);
    /// ```
    fn reseed(&mut self, data: H::Digest) {
        self.seed = H::merge(&[self.seed, data]);
        self.counter = 0;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Computes hash(`seed` || `value`) and returns the number of leading zeros in the resulting
    /// value if it is interpreted as an integer in big-endian byte order.
    fn check_leading_zeros(&self, value: u64) -> u32 {
        let new_seed = H::merge_with_int(self.seed, value);
        let bytes = new_seed.as_bytes();
        let seed_head = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        seed_head.trailing_zeros()
    }

    // DRAW METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the next pseudo-random field element.
    ///
    /// # Errors
    /// Returns an error if a valid field element could not be generated after 1000 calls to the
    /// PRNG.
    fn draw<E: FieldElement>(&mut self) -> Result<E, RandomCoinError> {
        for _ in 0..1000 {
            // get the next pseudo-random value and take the first ELEMENT_BYTES from it
            let value = self.next();
            let bytes = &value.as_bytes()[..E::ELEMENT_BYTES];

            // check if the bytes can be converted into a valid field element; if they can,
            // return; otherwise try again
            if let Some(element) = E::from_random_bytes(bytes) {
                return Ok(element);
            }
        }

        Err(RandomCoinError::FailedToDrawFieldElement(1000))
    }

    /// Returns a vector of integers selected from the range [0, domain_size) after reseeding
    /// the PRNG with the specified `nonce` by setting the new seed to hash(`seed` || `nonce`).
    ///
    /// # Errors
    /// Returns an error if the specified number of integers could not be generated after 1000
    /// calls to the PRNG.
    ///
    /// # Panics
    /// Panics if:
    /// - `domain_size` is not a power of two.
    /// - `num_values` is greater than or equal to `domain_size`.
    ///
    /// # Examples
    /// ```
    /// # use std::collections::HashSet;
    /// # use winter_crypto::{RandomCoin, DefaultRandomCoin, Hasher, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// // initial elements for seeding the random coin
    /// let seed = &[
    ///     BaseElement::new(1),
    ///     BaseElement::new(2),
    ///     BaseElement::new(3),
    ///     BaseElement::new(4),
    /// ];
    ///
    /// let mut coin = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(seed);
    ///
    /// let num_values = 20;
    /// let domain_size = 64;
    /// let nonce = 0;
    /// let values = coin.draw_integers(num_values, domain_size, nonce).unwrap();
    ///
    /// assert_eq!(num_values, values.len());
    ///
    /// for value in values {
    ///     assert!(value < domain_size);
    /// }
    /// ```
    fn draw_integers(
        &mut self,
        num_values: usize,
        domain_size: usize,
        nonce: u64,
    ) -> Result<Vec<usize>, RandomCoinError> {
        assert!(domain_size.is_power_of_two(), "domain size must be a power of two");
        assert!(num_values < domain_size, "number of values must be smaller than domain size");

        // reseed with nonce
        self.seed = H::merge_with_int(self.seed, nonce);
        self.counter = 0;

        // determine how many bits are needed to represent valid values in the domain
        let v_mask = (domain_size - 1) as u64;

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut values = Vec::new();
        for _ in 0..1000 {
            // get the next pseudo-random value and read the first 8 bytes from it
            let bytes: [u8; 8] = self.next().as_bytes()[..8].try_into().unwrap();

            // convert to integer and limit the integer to the number of bits which can fit
            // into the specified domain
            let value = (u64::from_le_bytes(bytes) & v_mask) as usize;

            values.push(value);
            if values.len() == num_values {
                break;
            }
        }

        if values.len() < num_values {
            return Err(RandomCoinError::FailedToDrawIntegers(num_values, values.len(), 1000));
        }

        Ok(values)
    }
}
