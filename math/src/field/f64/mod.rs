// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a 64-bit STARK-friendly prime field with modulus $2^{64} - 2^{32} + 1$.
//!
//! This field supports very fast modular arithmetic and has a number of other attractive
//! properties, including:
//! * Multiplication of two 32-bit values does not overflow field modulus.
//! * Field arithmetic in this field can be implemented using a few 32-bit addition, subtractions,
//!   and shifts.
//! * $8$ is the 64th root of unity which opens up potential for optimized FFT implementations.
//!
//! Internally, the values are stored in the range $[0, 2^{64})$ using `u64` as the backing type.

use super::{ExtensibleField, FieldElement, StarkField};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter},
    mem,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};
use utils::{
    collections::Vec, string::ToString, AsBytes, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Randomizable, Serializable,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

// Field modulus = 2^64 - 2^32 + 1
const M: u64 = 0xFFFFFFFF00000001;

// Epsilon = 2^32 - 1;
const E: u64 = 0xFFFFFFFF;

// 2^32 root of unity
const G: u64 = 1753635133440165772;

/// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = core::mem::size_of::<u64>();

// FIELD ELEMENT
// ================================================================================================

/// Represents base field element in the field.
///
/// Internal values are stored in the range [0, 2^64). The backing type is `u64`.
#[derive(Copy, Clone, Debug, Default)]
pub struct BaseElement(u64);

impl BaseElement {
    /// Creates a new field element from the provided `value`. If the value is greater than or
    /// equal to the field modulus, modular reduction is silently performed.
    pub const fn new(value: u64) -> Self {
        Self(value % M)
    }
}

impl FieldElement for BaseElement {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = Self::new(0);
    const ONE: Self = Self::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;
    const IS_CANONICAL: bool = false;

    #[inline]
    fn exp(self, power: Self::PositiveInteger) -> Self {
        let mut b = self;

        if power == 0 {
            return Self::ONE;
        } else if b == Self::ZERO {
            return Self::ZERO;
        }

        let mut r = if power & 1 == 1 { b } else { Self::ONE };
        for i in 1..64 - power.leading_zeros() {
            b = b.square();
            if (power >> i) & 1 == 1 {
                r *= b;
            }
        }

        r
    }

    #[inline]
    #[allow(clippy::many_single_char_names)]
    fn inv(self) -> Self {
        // compute base^(M - 2) using 72 multiplications
        // M - 2 = 0b1111111111111111111111111111111011111111111111111111111111111111

        // compute base^11
        let t2 = self.square() * self;

        // compute base^111
        let t3 = t2.square() * self;

        // compute base^111111 (6 ones)
        let t6 = exp_acc::<3>(t3, t3);

        // compute base^111111111111 (12 ones)
        let t12 = exp_acc::<6>(t6, t6);

        // compute base^111111111111111111111111 (24 ones)
        let t24 = exp_acc::<12>(t12, t12);

        // compute base^1111111111111111111111111111111 (31 ones)
        let t30 = exp_acc::<6>(t24, t6);
        let t31 = t30.square() * self;

        // compute base^111111111111111111111111111111101111111111111111111111111111111
        let t63 = exp_acc::<32>(t31, t31);

        // compute base^1111111111111111111111111111111011111111111111111111111111111111
        t63.square() * self
    }

    fn conjugate(&self) -> Self {
        Self(self.0)
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        // TODO: take endianness into account
        let p = elements.as_ptr();
        let len = elements.len() * Self::ELEMENT_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }

    unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError> {
        if bytes.len() % Self::ELEMENT_BYTES != 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "number of bytes ({}) does not divide into whole number of field elements",
                bytes.len(),
            )));
        }

        let p = bytes.as_ptr();
        let len = bytes.len() / Self::ELEMENT_BYTES;

        if (p as usize) % mem::align_of::<u64>() != 0 {
            return Err(DeserializationError::InvalidValue(
                "slice memory alignment is not valid for this field element type".to_string(),
            ));
        }

        Ok(slice::from_raw_parts(p as *const Self, len))
    }

    fn zeroed_vector(n: usize) -> Vec<Self> {
        // this uses a specialized vector initialization code which requests zero-filled memory
        // from the OS; unfortunately, this works only for built-in types and we can't use
        // Self::ZERO here as much less efficient initialization procedure will be invoked.
        // We also use u64 to make sure the memory is aligned correctly for our element size.
        let result = vec![0u64; n];

        // translate a zero-filled vector of u64s into a vector of base field elements
        let mut v = core::mem::ManuallyDrop::new(result);
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    }

    #[inline]
    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        elements
    }
}

impl StarkField for BaseElement {
    /// sage: MODULUS = 2^64 - 2^32 + 1 \
    /// sage: GF(MODULUS).is_prime_field() \
    /// True \
    /// sage: GF(MODULUS).order() \
    /// 18446744069414584321
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = 64;

    /// sage: GF(MODULUS).primitive_element() \
    /// 7
    const GENERATOR: Self = Self::new(7);

    /// sage: is_odd((MODULUS - 1) / 2^32) \
    /// True
    const TWO_ADICITY: u32 = 32;

    /// sage: k = (MODULUS - 1) / 2^32 \
    /// sage: GF(MODULUS).primitive_element()^k \
    /// 1753635133440165772
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(G);

    fn get_modulus_le_bytes() -> Vec<u8> {
        M.to_le_bytes().to_vec()
    }

    #[inline]
    fn as_int(&self) -> Self::PositiveInteger {
        // since the internal value of the element can be in [0, 2^64) range, we do an extra check
        // here to convert it to the canonical form
        if self.0 >= M {
            self.0 - M
        } else {
            self.0
        }
    }
}

impl Randomizable for BaseElement {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl Display for BaseElement {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_int())
    }
}

// EQUALITY CHECKS
// ================================================================================================

impl PartialEq for BaseElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // since either of the elements can be in [0, 2^64) range, we first convert them to the
        // canonical form to ensure that they are in [0, M) range and then compare them.
        self.as_int() == other.as_int()
    }
}

impl Eq for BaseElement {}

// OVERLOADED OPERATORS
// ================================================================================================

impl Add for BaseElement {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        let (result, over) = self.0.overflowing_add(rhs.as_int());
        Self(result.wrapping_sub(M * (over as u64)))
    }
}

impl AddAssign for BaseElement {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for BaseElement {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        let (result, under) = self.0.overflowing_sub(rhs.as_int());
        Self(result.wrapping_add(M * (under as u64)))
    }
}

impl SubAssign for BaseElement {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for BaseElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let z = (self.0 as u128) * (rhs.0 as u128);
        Self(mod_reduce(z))
    }
}

impl MulAssign for BaseElement {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for BaseElement {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}

impl DivAssign for BaseElement {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for BaseElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        let v = self.as_int();
        if v == 0 {
            Self::ZERO
        } else {
            Self(M - v)
        }
    }
}

// QUADRATIC EXTENSION
// ================================================================================================

/// Defines a quadratic extension of the base field over an irreducible polynomial x<sup>2</sup> -
/// x + 2. Thus, an extension element is defined as α + β * φ, where φ is a root of this polynomial,
/// and α and β are base field elements.
impl ExtensibleField<2> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 2], b: [Self; 2]) -> [Self; 2] {
        // performs multiplication in the extension field using 3 multiplications, 3 additions,
        // and 2 subtractions in the base field. overall, a single multiplication in the extension
        // field is slightly faster than 5 multiplications in the base field.
        let a0b0 = a[0] * b[0];
        [
            a0b0 - (a[1] * b[1]).double(),
            (a[0] + a[1]) * (b[0] + b[1]) - a0b0,
        ]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 2], b: Self) -> [Self; 2] {
        // multiplying an extension field element by a base field element requires just 2
        // multiplications in the base field.
        [a[0] * b, a[1] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 2]) -> [Self; 2] {
        [x[0] + x[1], -x[1]]
    }
}

// CUBIC EXTENSION
// ================================================================================================

/// Defines a cubic extension of the base field over an irreducible polynomial x<sup>3</sup> -
/// x - 1. Thus, an extension element is defined as α + β * φ + γ * φ^2, where φ is a root of this
/// polynomial, and α, β and γ are base field elements.
impl ExtensibleField<3> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 3], b: [Self; 3]) -> [Self; 3] {
        // performs multiplication in the extension field using 6 multiplications, 9 additions,
        // and 4 subtractions in the base field. overall, a single multiplication in the extension
        // field is roughly equal to 12 multiplications in the base field.
        let a0b0 = a[0] * b[0];
        let a1b1 = a[1] * b[1];
        let a2b2 = a[2] * b[2];

        let a0b0_a0b1_a1b0_a1b1 = (a[0] + a[1]) * (b[0] + b[1]);
        let a0b0_a0b2_a2b0_a2b2 = (a[0] + a[2]) * (b[0] + b[2]);
        let a1b1_a1b2_a2b1_a2b2 = (a[1] + a[2]) * (b[1] + b[2]);

        let a0b0_minus_a1b1 = a0b0 - a1b1;

        let a0b0_a1b2_a2b1 = a1b1_a1b2_a2b1_a2b2 + a0b0_minus_a1b1 - a2b2;
        let a0b1_a1b0_a1b2_a2b1_a2b2 =
            a0b0_a0b1_a1b0_a1b1 + a1b1_a1b2_a2b1_a2b2 - a1b1.double() - a0b0;
        let a0b2_a1b1_a2b0_a2b2 = a0b0_a0b2_a2b0_a2b2 - a0b0_minus_a1b1;

        [
            a0b0_a1b2_a2b1,
            a0b1_a1b0_a1b2_a2b1_a2b2,
            a0b2_a1b1_a2b0_a2b2,
        ]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 3], b: Self) -> [Self; 3] {
        // multiplying an extension field element by a base field element requires just 3
        // multiplications in the base field.
        [a[0] * b, a[1] * b, a[2] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 3]) -> [Self; 3] {
        // coefficients were computed using SageMath
        [
            x[0] + BaseElement::new(10615703402128488253) * x[1]
                + BaseElement::new(6700183068485440220) * x[2],
            BaseElement::new(10050274602728160328) * x[1]
                + BaseElement::new(14531223735771536287) * x[2],
            BaseElement::new(11746561000929144102) * x[1]
                + BaseElement::new(8396469466686423992) * x[2],
        ]
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for BaseElement {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(value: u128) -> Self {
        Self(mod_reduce(value))
    }
}

impl From<u64> for BaseElement {
    /// Converts a 64-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<u32> for BaseElement {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        Self::new(value as u64)
    }
}

impl From<u16> for BaseElement {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        Self::new(value as u64)
    }
}

impl From<u8> for BaseElement {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        Self::new(value as u64)
    }
}

impl From<[u8; 8]> for BaseElement {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes are
    /// assumed to encode the element in the canonical representation in little-endian byte order.
    /// If the value is greater than or equal to the field modulus, modular reduction is silently
    /// performed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        Self::new(value)
    }
}

impl<'a> TryFrom<&'a [u8]> for BaseElement {
    type Error = DeserializationError;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to encode the element in the canonical
    /// representation in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < ELEMENT_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "not enough bytes for a full field element; expected {} bytes, but was {} bytes",
                ELEMENT_BYTES,
                bytes.len(),
            )));
        }
        if bytes.len() > ELEMENT_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "too many bytes for a field element; expected {} bytes, but was {} bytes",
                ELEMENT_BYTES,
                bytes.len(),
            )));
        }
        let value = bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| DeserializationError::UnknownError(format!("{}", error)))?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(BaseElement::new(value))
    }
}

impl AsBytes for BaseElement {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const BaseElement = self;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for BaseElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // convert from Montgomery representation into canonical representation
        target.write_u8_slice(&self.as_int().to_le_bytes());
    }
}

impl Deserializable for BaseElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(BaseElement::new(value))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Reduces a 128-bit value by M such that the output is in [0, 2^64) range.
///
/// Adapted from: <https://github.com/mir-protocol/plonky2/blob/main/src/field/goldilocks_field.rs>
#[inline(always)]
fn mod_reduce(x: u128) -> u64 {
    // assume x consists of four 32-bit values: a, b, c, d such that a contains 32 least
    // significant bits and d contains 32 most significant bits. we break x into corresponding
    // values as shown below
    let ab = x as u64;
    let cd = (x >> 64) as u64;
    let c = (cd as u32) as u64;
    let d = cd >> 32;

    // compute ab - d; because d may be greater than ab we need to handle potential underflow
    let (tmp0, under) = ab.overflowing_sub(d);
    let tmp0 = tmp0.wrapping_sub(E * (under as u64));

    // compute c * 2^32 - c; this is guaranteed not to underflow
    let tmp1 = (c << 32) - c;

    // add temp values and return the result; because each of the temp may be up to 64 bits,
    // we need to handle potential overflow
    let (result, over) = tmp0.overflowing_add(tmp1);
    result.wrapping_add(E * (over as u64))
}

/// Squares the base N number of times and multiplies the result by the tail value.
#[inline(always)]
fn exp_acc<const N: usize>(base: BaseElement, tail: BaseElement) -> BaseElement {
    let mut result = base;
    for _ in 0..N {
        result = result.square();
    }
    result * tail
}
