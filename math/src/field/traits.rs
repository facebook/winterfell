// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{
    convert::TryFrom,
    fmt::{Debug, Display},
    ops::{
        Add, AddAssign, BitAnd, Div, DivAssign, Mul, MulAssign, Neg, Shl, Shr, ShrAssign, Sub,
        SubAssign,
    },
};
use utils::{
    collections::Vec, AsBytes, Deserializable, DeserializationError, Randomizable, Serializable,
};

// FIELD ELEMENT
// ================================================================================================
/// Defines an element in a finite field.
///
/// This trait defines basic arithmetic operations for elements in
/// [finite fields](https://en.wikipedia.org/wiki/Finite_field) (e.g. addition subtraction,
/// multiplication, division) as well as several convenience functions (e.g. double, square cube).
/// Moreover, it defines interfaces for serializing and deserializing field elements.
///
/// The elements could be in a prime field or an extension of a prime field. Currently, only
/// quadratic and cubic field extensions are supported.
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
    + From<u128>
    + From<u64>
    + From<u32>
    + From<u16>
    + From<u8>
    + for<'a> TryFrom<&'a [u8]>
    + ExtensionOf<<Self as FieldElement>::BaseField>
    + AsBytes
    + Randomizable
    + Serializable
    + Deserializable
{
    /// A type defining positive integers big enough to describe a field modulus for
    /// `Self::BaseField` with no loss of precision.
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

    /// Base field type for this finite field. For prime fields, `BaseField` should be set
    /// to `Self`.
    type BaseField: StarkField;

    /// Number of bytes needed to encode an element
    const ELEMENT_BYTES: usize;

    /// True if internal representation of the element is the same as its canonical representation.
    const IS_CANONICAL: bool;

    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;

    // ALGEBRA
    // --------------------------------------------------------------------------------------------

    /// Returns this field element added to itself.
    #[inline]
    #[must_use]
    fn double(self) -> Self {
        self + self
    }

    /// Returns this field element raised to power 2.
    #[inline]
    #[must_use]
    fn square(self) -> Self {
        self * self
    }

    /// Returns this field element raised to power 3.
    #[inline]
    #[must_use]
    fn cube(self) -> Self {
        self * self * self
    }

    /// Exponentiates this field element by `power` parameter.
    #[must_use]
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
    #[must_use]
    fn inv(self) -> Self;

    /// Returns a conjugate of this field element.
    #[must_use]
    fn conjugate(&self) -> Self;

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts a list of elements into a list of bytes.
    ///
    /// The elements may be in the internal representation rather than in the canonical
    /// representation. This conversion is intended to be zero-copy (i.e. by re-interpreting the
    /// underlying memory).
    fn elements_as_bytes(elements: &[Self]) -> &[u8];

    /// Converts a list of bytes into a list of field elements.
    ///
    /// The elements are assumed to encoded in the internal representation rather than in the
    /// canonical representation. The conversion is intended to be zero-copy (i.e. by
    /// re-interpreting the underlying memory).
    ///
    /// # Errors
    /// An error is returned if:
    /// * Memory alignment of `bytes` does not match memory alignment of field element data.
    /// * Length of `bytes` does not divide into whole number of elements.
    ///
    /// # Safety
    /// This function is unsafe because it does not check whether underlying bytes represent valid
    /// field elements according to their internal representation.
    unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError>;

    // UTILITIES
    // --------------------------------------------------------------------------------------------

    /// Returns a vector of length `n` initialized with all ZERO elements.
    ///
    /// Specialized implementations of this function may be faster than the generic implementation.
    fn zeroed_vector(n: usize) -> Vec<Self> {
        vec![Self::ZERO; n]
    }

    /// Converts a list of field elements into a list of elements in the underlying base field.
    ///
    /// For base STARK fields, the input and output lists are the same. For extension field, the
    /// output list will contain decompositions of each extension element into underlying base
    /// elements.
    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField];
}

// STARK FIELD
// ================================================================================================

/// Defines an element in a STARK-friendly finite field.
///
/// A STARK-friendly field is defined as a prime field with high two-addicity. That is, the
/// the modulus of the field should be a prime number of the form `k` * 2^`n` + 1 (a Proth prime),
/// where `n` is relatively large (e.g., greater than 32).
pub trait StarkField: FieldElement<BaseField = Self> {
    /// Prime modulus of the field. Must be of the form `k` * 2^`n` + 1 (a Proth prime).
    /// This ensures that the field has high 2-adicity.
    const MODULUS: Self::PositiveInteger;

    /// The number of bits needed to represents `Self::MODULUS`.
    const MODULUS_BITS: u32;

    /// A multiplicative generator of the field.
    const GENERATOR: Self;

    /// Let Self::MODULUS = `k` * 2^`n` + 1; then, TWO_ADICITY is `n`.
    const TWO_ADICITY: u32;

    /// Let Self::MODULUS = `k` * 2^`n` + 1; then, TWO_ADIC_ROOT_OF_UNITY is 2^`n` root of unity
    /// computed as Self::GENERATOR^`k`.
    const TWO_ADIC_ROOT_OF_UNITY: Self;

    /// Returns the root of unity of order 2^`n`.
    ///
    /// # Panics
    /// Panics if the root of unity for the specified order does not exist in this field.
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

    /// Returns a canonical integer representation of this field element.
    fn as_int(&self) -> Self::PositiveInteger;
}

// EXTENSIBLE FIELD
// ================================================================================================

/// Defines basic arithmetic in an extension of a StarkField of a given degree.
///
/// This trait defines how to perform multiplication and compute a Frobenius automorphisms of an
/// element in an extension of degree N for a given [StarkField]. It as assumed that an element in
/// degree N extension field can be represented by N field elements in the base field.
///
/// Implementation of this trait implicitly defines the irreducible polynomial over which the
/// extension field is defined.
pub trait ExtensibleField<const N: usize>: StarkField {
    /// Returns a product of `a` and `b` in the field defined by this extension.
    fn mul(a: [Self; N], b: [Self; N]) -> [Self; N];

    /// Returns a product of `a` and `b` in the field defined by this extension. `b` represents
    /// an element in the base field.
    fn mul_base(a: [Self; N], b: Self) -> [Self; N];

    /// Returns Frobenius automorphisms for `x` in the field defined by this extension.
    fn frobenius(x: [Self; N]) -> [Self; N];

    /// Returns true if this extension is supported for the underlying base field.
    fn is_supported() -> bool {
        true
    }
}

// EXTENSION OF
// ================================================================================================

/// Specifies that a field is an extension of another field.
///
/// Currently, this implies the following:
/// - An element in the base field can be converted into an element in the extension field.
/// - An element in the extension field can be multiplied by a base field element directly. This
///   can be used for optimization purposes as such multiplication could be much more efficient
///   than multiplication of two extension field elements.
pub trait ExtensionOf<E: FieldElement>: From<E> {
    fn mul_base(self, other: E) -> Self;
}

/// A field is always an extension of itself.
impl<E: FieldElement> ExtensionOf<E> for E {
    #[inline(always)]
    fn mul_base(self, other: E) -> Self {
        self * other
    }
}
