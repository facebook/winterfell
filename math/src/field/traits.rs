// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::SerializationError;
use core::{
    convert::TryFrom,
    fmt::{Debug, Display},
    ops::{
        Add, AddAssign, BitAnd, Div, DivAssign, Mul, MulAssign, Neg, Shl, Shr, ShrAssign, Sub,
        SubAssign,
    },
};
use utils::{AsBytes, Serializable};

// FIELD ELEMENT
// ================================================================================================

pub trait FieldElement:
    Copy
    + Clone
    + Debug
    + Display
    + Default
    + Send
    + Sync
    + Eq
    + PartialEq
    + Sized
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + DivAssign<Self>
    + Neg<Output = Self>
    + From<Self::BaseField>
    + From<u128>
    + From<u64>
    + From<u32>
    + From<u16>
    + From<u8>
    + for<'a> TryFrom<&'a [u8]>
    + AsBytes
    + Serializable
{
    type PositiveInteger: Debug
        + Copy
        + PartialEq
        + PartialOrd
        + ShrAssign
        + Shl<u32, Output = Self::PositiveInteger>
        + Shr<u32, Output = Self::PositiveInteger>
        + BitAnd<Output = Self::PositiveInteger>
        + From<u32>
        + From<u64>;

    type BaseField: StarkField;

    /// Number of bytes needed to encode an element
    const ELEMENT_BYTES: usize;

    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;

    // ALGEBRA
    // --------------------------------------------------------------------------------------------

    /// Returns this field element added to itself.
    fn double(self) -> Self {
        self + self
    }

    /// Returns this field element raised to power 2.
    fn square(self) -> Self {
        self * self
    }

    /// Returns this field element raised to power 3.
    fn cube(self) -> Self {
        self * self * self
    }

    /// Exponentiates this field element by `power` parameter.
    fn exp(self, power: Self::PositiveInteger) -> Self {
        let mut r = Self::ONE;
        let mut b = self;
        let mut p = power;

        let int_zero = Self::PositiveInteger::from(0u32);
        let int_one = Self::PositiveInteger::from(1u32);

        if p == int_zero {
            return Self::ONE;
        } else if b == Self::ZERO {
            return Self::ZERO;
        }

        while p > int_zero {
            if p & int_one == int_one {
                r *= b;
            }
            p >>= int_one;
            b = b.square();
        }

        r
    }

    /// Returns a multiplicative inverse of this field element. If this element is ZERO, ZERO is
    /// returned.
    fn inv(self) -> Self;

    /// Returns a conjugate of this field element.
    fn conjugate(&self) -> Self;

    // RANDOMNESS
    // --------------------------------------------------------------------------------------------

    /// Returns a cryptographically-secure random element drawn uniformly from the entire field.
    fn rand() -> Self;

    /// Returns a field element if the set of bytes forms a valid field element, otherwise returns
    /// None. The element is expected to be in canonical representation. This function is primarily
    /// intended for sampling random field elements from a hash function output.
    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts a vector of field elements into a vector of bytes. The elements may be in the
    /// internal representation rather than in the canonical representation. This conversion is
    /// intended to be zero-copy (i.e. by re-interpreting the underlying memory).
    fn elements_into_bytes(elements: Vec<Self>) -> Vec<u8>;

    /// Converts a list of elements into a list of bytes. The elements may be in the internal
    /// representation rather than in the canonical representation. This conversion is intended
    /// to be zero-copy (i.e. by re-interpreting the underlying memory).
    fn elements_as_bytes(elements: &[Self]) -> &[u8];

    /// Converts a list of bytes into a list of field elements. The elements are assumed to
    /// encoded in the internal representation rather than in the canonical representation. The
    /// conversion is intended to be zero-copy (i.e. by re-interpreting the underlying memory).
    ///
    /// An error is returned if:
    /// * Memory alignment of `bytes` does not match memory alignment of field element data.
    /// * Length of `bytes` does not divide into whole number of elements.
    ///
    /// # Safety
    /// This function is unsafe because it does not check whether underlying bytes represent valid
    /// field elements according to their internal representation.
    unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], SerializationError>;

    // INITIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns a vector initialized with all zero elements; specialized implementations of this
    /// function may be faster than the generic implementation.
    fn zeroed_vector(n: usize) -> Vec<Self> {
        vec![Self::ZERO; n]
    }

    /// Returns a vector of n pseudo-random elements drawn uniformly from the entire
    /// field based on the provided seed.
    fn prng_vector(seed: [u8; 32], n: usize) -> Vec<Self>;
}

// STARK FIELD
// ================================================================================================

pub trait StarkField: FieldElement<BaseField = Self> {
    /// Prime modulus of the field. Must be of the form k * 2^n + 1 (a Proth prime).
    /// This ensures that the field has high 2-adicity.
    const MODULUS: Self::PositiveInteger;

    /// The number of bits needed to represents `Self::MODULUS`.
    const MODULUS_BITS: u32;

    /// A multiplicative generator of the field.
    const GENERATOR: Self;

    /// Let Self::MODULUS = k * 2^n + 1; then, TWO_ADICITY is n.
    const TWO_ADICITY: u32;

    /// Let Self::MODULUS = k * 2^n + 1; then, TWO_ADIC_ROOT_OF_UNITY is 2^n root of unity
    /// computed as Self::GENERATOR^k.
    const TWO_ADIC_ROOT_OF_UNITY: Self;

    /// Returns the root of unity of order 2^n. Panics if the root of unity for
    /// the specified order does not exist in this field.
    fn get_root_of_unity(n: u32) -> Self {
        assert!(n != 0, "cannot get root of unity for n = 0");
        assert!(
            n <= Self::TWO_ADICITY,
            "order cannot exceed 2^{}",
            Self::TWO_ADICITY
        );
        let power = Self::PositiveInteger::from(1u32) << (Self::TWO_ADICITY - n);
        Self::TWO_ADIC_ROOT_OF_UNITY.exp(power)
    }

    /// Returns byte representation of the field modulus in little-endian byte order.
    fn get_modulus_le_bytes() -> Vec<u8>;

    /// Returns a canonical integer representation of the field element.
    fn as_int(&self) -> Self::PositiveInteger;
}
