// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::RandomCoinError, Digest, Hasher};
use core::{convert::TryInto, marker::PhantomData};
use math::{FieldElement, StarkField};
use utils::collections::Vec;

// RANDOM COIN
// ================================================================================================

/// Pseudo-random element generator for finite fields.
///
/// A random coin can be used to draws elements uniformly at random from the specified base field
// (which is specified via the `B` type parameter) or from any extension of the base field.
///
/// Internally we use a cryptographic hash function (which is specified via the `H` type parameter),
/// to draw elements from the field. The coin works roughly as follows:
/// - The internal state of the coin consists of a `seed` and a `counter`. At instantiation
///   time, the `seed` is set to a hash of the provided bytes, and the `counter` is set to 0.
/// - To draw the next element, we increment the `counter` and compute hash(`seed` || `counter`).
///   If the resulting value is a valid field element, we return the result; otherwise we try
///   again until a valid element is found or the number of allowed tries is exceeded.
/// - We can also re-seed the coin with a new value. During the reseeding procedure, the
///   seed is set to hash(`old_seed` || `new_seed`), and the counter is reset to 0.
///
/// # Examples
/// ```
/// # use winter_crypto::{RandomCoin, hashers::Blake3_256};
/// # use math::fields::f128::BaseElement;
/// // instantiate a random coin using BLAKE3 as the hash function
/// let mut coin = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
///
/// // should draw different elements each time
/// let e1 = coin.draw::<BaseElement>().unwrap();;
/// let e2 = coin.draw::<BaseElement>().unwrap();;
/// assert_ne!(e1, e2);
///
/// let e3 = coin.draw::<BaseElement>().unwrap();;
/// assert_ne!(e1, e3);
/// assert_ne!(e2, e3);
///
/// // should draw same elements for the same seed
/// let mut coin1 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
/// let mut coin2 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
/// let e1 = coin1.draw::<BaseElement>().unwrap();;
/// let e2 = coin2.draw::<BaseElement>().unwrap();;
/// assert_eq!(e1, e2);
///
/// // should draw different elements based on seed
/// let mut coin1 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
/// let mut coin2 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[2, 3, 4, 5]);
/// let e1 = coin1.draw::<BaseElement>().unwrap();;
/// let e2 = coin2.draw::<BaseElement>().unwrap();;
/// assert_ne!(e1, e2);
/// ```
pub struct RandomCoin<B, H>
where
    B: StarkField,
    H: Hasher,
{
    seed: H::Digest,
    counter: u64,
    _base_field: PhantomData<B>,
}

impl<B: StarkField, H: Hasher> RandomCoin<B, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new random coin instantiated with the provided `seed`.
    pub fn new(seed: &[u8]) -> Self {
        let seed = H::hash(seed);
        RandomCoin {
            seed,
            counter: 0,
            _base_field: PhantomData,
        }
    }

    // RESEEDING
    // --------------------------------------------------------------------------------------------

    /// Reseeds the coin with the specified data by setting the new seed to hash(`seed` || `data`).
    ///
    /// # Examples
    /// ```
    /// # use winter_crypto::{RandomCoin, Hasher, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// let mut coin1 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    /// let mut coin2 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    ///
    /// // should draw the same element form both coins
    /// let e1 = coin1.draw::<BaseElement>().unwrap();
    /// let e2 = coin2.draw::<BaseElement>().unwrap();;
    /// assert_eq!(e1, e2);
    ///
    /// // after reseeding should draw different elements
    /// coin2.reseed(Blake3_256::<BaseElement>::hash(&[2, 3, 4, 5]));
    /// let e1 = coin1.draw::<BaseElement>().unwrap();;
    /// let e2 = coin2.draw::<BaseElement>().unwrap();;
    /// assert_ne!(e1, e2);
    /// ```
    pub fn reseed(&mut self, data: H::Digest) {
        self.seed = H::merge(&[self.seed, data]);
        self.counter = 0;
    }

    /// Reseeds the coin with the specified value by setting the new seed to hash(`seed` ||
    /// `value`).
    ///
    /// # Examples
    /// ```
    /// # use winter_crypto::{RandomCoin, Hasher, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// let mut coin1 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    /// let mut coin2 = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    ///
    /// // should draw the same element form both coins
    /// let e1 = coin1.draw::<BaseElement>().unwrap();;
    /// let e2 = coin2.draw::<BaseElement>().unwrap();;
    /// assert_eq!(e1, e2);
    ///
    /// // after reseeding should draw different elements
    /// coin2.reseed_with_int(42);
    /// let e1 = coin1.draw::<BaseElement>().unwrap();;
    /// let e2 = coin2.draw::<BaseElement>().unwrap();;
    /// assert_ne!(e1, e2);
    /// ```
    pub fn reseed_with_int(&mut self, value: u64) {
        self.seed = H::merge_with_int(self.seed, value);
        self.counter = 0;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of leading zeros in the seed if it is interpreted as an integer in
    /// big-endian byte order.
    ///
    /// # Examples
    /// ```
    /// # use winter_crypto::{RandomCoin, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// let mut coin = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    ///
    /// let mut value = 0;
    /// while coin.check_leading_zeros(value) < 2 {
    ///     value += 1;
    /// }
    ///
    /// coin.reseed_with_int(value);
    /// assert!(coin.leading_zeros() >= 2);
    /// ```
    pub fn leading_zeros(&self) -> u32 {
        let bytes = self.seed.as_bytes();
        let seed_head = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        seed_head.trailing_zeros()
    }

    /// Computes hash(`seed` || `value`) and returns the number of leading zeros in the resulting
    /// value if it is interpreted as an integer in big-endian byte order.
    pub fn check_leading_zeros(&self, value: u64) -> u32 {
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
    pub fn draw<E>(&mut self) -> Result<E, RandomCoinError>
    where
        E: FieldElement<BaseField = B>,
    {
        for _ in 0..1000 {
            // get the next pseudo-random value and take the first ELEMENT_BYTES from it
            let value = self.next();
            let bytes = &value.as_bytes()[..E::ELEMENT_BYTES as usize];

            // check if the bytes can be converted into a valid field element; if they can,
            // return; otherwise try again
            if let Some(element) = E::from_random_bytes(bytes) {
                return Ok(element);
            }
        }

        Err(RandomCoinError::FailedToDrawFieldElement(1000))
    }

    /// Returns the next pair of pseudo-random field elements.
    ///
    /// # Errors
    /// Returns an error if any of the field elements could not be generated after 100 calls to
    /// the PRNG;
    pub fn draw_pair<E>(&mut self) -> Result<(E, E), RandomCoinError>
    where
        E: FieldElement<BaseField = B>,
    {
        Ok((self.draw()?, self.draw()?))
    }

    /// Returns the next triplet of pseudo-random field elements.
    ///
    /// # Errors
    /// Returns an error if any of the field elements could not be generated after 100 calls to
    /// the PRNG;
    pub fn draw_triple<E>(&mut self) -> Result<(E, E, E), RandomCoinError>
    where
        E: FieldElement<BaseField = B>,
    {
        Ok((self.draw()?, self.draw()?, self.draw()?))
    }

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
    ///
    /// # Examples
    /// ```
    /// # use std::collections::HashSet;
    /// # use winter_crypto::{RandomCoin, hashers::Blake3_256};
    /// # use math::fields::f128::BaseElement;
    /// let mut coin = RandomCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[1, 2, 3, 4]);
    ///
    /// let num_values = 20;
    /// let domain_size = 64;
    /// let values = coin.draw_integers(num_values, domain_size).unwrap();
    ///
    /// assert_eq!(num_values, values.len());
    ///
    /// let mut value_set = HashSet::new();
    /// for value in values {
    ///     assert!(value < domain_size);
    ///     assert!(value_set.insert(value));
    /// }
    /// ```
    pub fn draw_integers(
        &mut self,
        num_values: usize,
        domain_size: usize,
    ) -> Result<Vec<usize>, RandomCoinError> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            num_values < domain_size,
            "number of values must be smaller than domain size"
        );

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

            if values.contains(&value) {
                continue;
            }
            values.push(value);
            if values.len() == num_values {
                break;
            }
        }

        if values.len() < num_values {
            return Err(RandomCoinError::FailedToDrawIntegers(
                num_values,
                values.len(),
                1000,
            ));
        }

        Ok(values)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Updates the state by incrementing the counter and returns hash(seed || counter)
    fn next(&mut self) -> H::Digest {
        self.counter += 1;
        H::merge_with_int(self.seed, self.counter)
    }
}
