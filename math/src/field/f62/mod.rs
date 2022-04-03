// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a 62-bit STARK-friendly prime field with modulus $2^{62} - 111 \cdot 2^{39} + 1$.
//!
//! All operations in this field are implemented using Montgomery arithmetic. It supports very
//! fast modular arithmetic including branchless multiplication and addition. Base elements are
//! stored in the Montgomery form using `u64` as the backing type.

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

/// Field modulus = 2^62 - 111 * 2^39 + 1
const M: u64 = 4611624995532046337;

/// 2^128 mod M; this is used for conversion of elements into Montgomery representation.
const R2: u64 = 630444561284293700;

/// 2^192 mod M; this is used during element inversion.
const R3: u64 = 732984146687909319;

/// -M^{-1} mod 2^64; this is used during element multiplication.
const U: u128 = 4611624995532046335;

/// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = core::mem::size_of::<u64>();

// 2^39 root of unity
const G: u64 = 4421547261963328785;

// FIELD ELEMENT
// ================================================================================================

/// Represents base field element in the field.
///
/// Internal values are stored in Montgomery representation and can be in the range [0; 2M). The
/// backing type is `u64`.
#[derive(Copy, Clone, Debug, Default)]
pub struct BaseElement(u64);

impl BaseElement {
    /// Creates a new field element from the provided `value`; the value is converted into
    /// Montgomery representation.
    pub const fn new(value: u64) -> BaseElement {
        // multiply the value with R2 to convert to Montgomery representation; this is OK because
        // given the value of R2, the product of R2 and `value` is guaranteed to be in the range
        // [0, 4M^2 - 4M + 1)
        let z = mul(value, R2);
        BaseElement(z)
    }
}

impl FieldElement for BaseElement {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = BaseElement::new(0);
    const ONE: Self = BaseElement::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;
    const IS_CANONICAL: bool = false;

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

    fn inv(self) -> Self {
        BaseElement(inv(self.0))
    }

    fn conjugate(&self) -> Self {
        BaseElement(self.0)
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

    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        elements
    }
}

impl StarkField for BaseElement {
    /// sage: MODULUS = 2^62 - 111 * 2^39 + 1 \
    /// sage: GF(MODULUS).is_prime_field() \
    /// True \
    /// sage: GF(MODULUS).order() \
    /// 4611624995532046337
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = 62;

    /// sage: GF(MODULUS).primitive_element() \
    /// 3
    const GENERATOR: Self = BaseElement::new(3);

    /// sage: is_odd((MODULUS - 1) / 2^39) \
    /// True
    const TWO_ADICITY: u32 = 39;

    /// sage: k = (MODULUS - 1) / 2^39 \
    /// sage: GF(MODULUS).primitive_element()^k \
    /// 4421547261963328785
    const TWO_ADIC_ROOT_OF_UNITY: Self = BaseElement::new(G);

    fn get_modulus_le_bytes() -> Vec<u8> {
        Self::MODULUS.to_le_bytes().to_vec()
    }

    #[inline]
    fn as_int(&self) -> Self::PositiveInteger {
        // convert from Montgomery representation by multiplying by 1
        let result = mul(self.0, 1);
        // since the result of multiplication can be in [0, 2M), we need to normalize it
        normalize(result)
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
        // since either of the elements can be in [0, 2M) range, we normalize them first to be
        // in [0, M) range and then compare them.
        normalize(self.0) == normalize(other.0)
    }
}

impl Eq for BaseElement {}

// OVERLOADED OPERATORS
// ================================================================================================

impl Add for BaseElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(add(self.0, rhs.0))
    }
}

impl AddAssign for BaseElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for BaseElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(sub(self.0, rhs.0))
    }
}

impl SubAssign for BaseElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for BaseElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(mul(self.0, rhs.0))
    }
}

impl MulAssign for BaseElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for BaseElement {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Self(mul(self.0, inv(rhs.0)))
    }
}

impl DivAssign for BaseElement {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for BaseElement {
    type Output = Self;

    fn neg(self) -> Self {
        Self(sub(0, self.0))
    }
}

// QUADRATIC EXTENSION
// ================================================================================================

/// Defines a quadratic extension of the base field over an irreducible polynomial x<sup>2</sup> -
/// x - 1. Thus, an extension element is defined as α + β * φ, where φ is a root of this polynomial,
/// and α and β are base field elements.
impl ExtensibleField<2> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 2], b: [Self; 2]) -> [Self; 2] {
        let z = a[0] * b[0];
        [z + a[1] * b[1], (a[0] + a[1]) * (b[0] + b[1]) - z]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 2], b: Self) -> [Self; 2] {
        [a[0] * b, a[1] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 2]) -> [Self; 2] {
        [x[0] + x[1], -x[1]]
    }
}

// CUBIC EXTENSION
// ================================================================================================

/// Defines a cubic extension of the base field over an irreducible polynomial x<sup>3</sup> +
/// 2x + 2. Thus, an extension element is defined as α + β * φ + γ * φ^2, where φ is a root of this
/// polynomial, and α, β and γ are base field elements.
impl ExtensibleField<3> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 3], b: [Self; 3]) -> [Self; 3] {
        // performs multiplication in the extension field using 6 multiplications, 8 additions,
        // and 9 subtractions in the base field. overall, a single multiplication in the extension
        // field is roughly equal to 12 multiplications in the base field.
        let a0b0 = a[0] * b[0];
        let a1b1 = a[1] * b[1];
        let a2b2 = a[2] * b[2];

        let a0b0_a0b1_a1b0_a1b1 = (a[0] + a[1]) * (b[0] + b[1]);
        let minus_a0b0_a0b2_a2b0_minus_a2b2 = (a[0] - a[2]) * (b[2] - b[0]);
        let a1b1_minus_a1b2_minus_a2b1_a2b2 = (a[1] - a[2]) * (b[1] - b[2]);
        let a0b0_a1b1 = a0b0 + a1b1;

        let minus_2a1b2_minus_2a2b1 = (a1b1_minus_a1b2_minus_a2b1_a2b2 - a1b1 - a2b2).double();

        let a0b0_minus_2a1b2_minus_2a2b1 = a0b0 + minus_2a1b2_minus_2a2b1;
        let a0b1_a1b0_minus_2a1b2_minus_2a2b1_minus_2a2b2 =
            a0b0_a0b1_a1b0_a1b1 + minus_2a1b2_minus_2a2b1 - a2b2.double() - a0b0_a1b1;
        let a0b2_a1b1_a2b0_minus_2a2b2 = minus_a0b0_a0b2_a2b0_minus_a2b2 + a0b0_a1b1 - a2b2;
        [
            a0b0_minus_2a1b2_minus_2a2b1,
            a0b1_a1b0_minus_2a1b2_minus_2a2b1_minus_2a2b2,
            a0b2_a1b1_a2b0_minus_2a2b2,
        ]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 3], b: Self) -> [Self; 3] {
        [a[0] * b, a[1] * b, a[2] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 3]) -> [Self; 3] {
        // coefficients were computed using SageMath
        [
            x[0] + BaseElement::new(2061766055618274781) * x[1]
                + BaseElement::new(786836585661389001) * x[2],
            BaseElement::new(2868591307402993000) * x[1]
                + BaseElement::new(3336695525575160559) * x[2],
            BaseElement::new(2699230790596717670) * x[1]
                + BaseElement::new(1743033688129053336) * x[2],
        ]
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for BaseElement {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(value: u128) -> Self {
        // make sure the value is < 4M^2 - 4M + 1; this is overly conservative and a single
        // subtraction of (M * 2^65) should be enough, but this needs to be proven
        const M4: u128 = (2 * M as u128).pow(2) - 4 * (M as u128) + 1;
        const Q: u128 = (2 * M as u128).pow(2) - 4 * (M as u128);
        let mut v = value;
        while v >= M4 {
            v -= Q;
        }

        // apply similar reduction as during multiplication; as output we get z = v * R^{-1} mod M,
        // so we need to Montgomery-multiply it be R^3 to get z = v * R mod M
        let q = (((v as u64) as u128) * U) as u64;
        let z = v + (q as u128) * (M as u128);
        let z = mul((z >> 64) as u64, R3);
        BaseElement(z)
    }
}

impl From<u64> for BaseElement {
    /// Converts a 64-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(value: u64) -> Self {
        BaseElement::new(value)
    }
}

impl From<u32> for BaseElement {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<u16> for BaseElement {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<u8> for BaseElement {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<[u8; 8]> for BaseElement {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes are
    /// assumed to encode the element in the canonical representation in little-endian byte order.
    /// If the value is greater than or equal to the field modulus, modular reduction is silently
    /// performed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        BaseElement::new(value)
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

// FINITE FIELD ARITHMETIC
// ================================================================================================

/// Computes (a + b) reduced by M such that the output is in [0, 2M) range; a and b are assumed to
/// be in [0, 2M).
#[inline(always)]
fn add(a: u64, b: u64) -> u64 {
    let z = a + b;
    let q = (z >> 62) * M;
    z - q
}

/// Computes (a - b) reduced by M such that the output is in [0, 2M) range; a and b are assumed to
/// be in [0, 2M).
#[inline(always)]
fn sub(a: u64, b: u64) -> u64 {
    if a < b {
        2 * M - b + a
    } else {
        a - b
    }
}

/// Computes (a * b) reduced by M such that the output is in [0, 2M) range; a and b are assumed to
/// be in [0, 2M).
#[inline(always)]
const fn mul(a: u64, b: u64) -> u64 {
    let z = (a as u128) * (b as u128);
    let q = (((z as u64) as u128) * U) as u64;
    let z = z + (q as u128) * (M as u128);
    (z >> 64) as u64
}

/// Computes y such that (x * y) % M = 1 except for when when x = 0; in such a case, 0 is returned;
/// x is assumed to in [0, 2M) range, and the output will also be in [0, 2M) range.
#[inline(always)]
#[allow(clippy::many_single_char_names)]
fn inv(x: u64) -> u64 {
    if x == 0 {
        return 0;
    };

    let mut a: u128 = 0;
    let mut u: u128 = if x & 1 == 1 {
        x as u128
    } else {
        (x as u128) + (M as u128)
    };
    let mut v: u128 = M as u128;
    let mut d = (M as u128) - 1;

    while v != 1 {
        while v < u {
            u -= v;
            d += a;
            while u & 1 == 0 {
                if d & 1 == 1 {
                    d += M as u128;
                }
                u >>= 1;
                d >>= 1;
            }
        }

        v -= u;
        a += d;

        while v & 1 == 0 {
            if a & 1 == 1 {
                a += M as u128;
            }
            v >>= 1;
            a >>= 1;
        }
    }

    while a > (M as u128) {
        a -= M as u128;
    }

    mul(a as u64, R3)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Reduces any value in [0, 2M) range to [0, M) range
#[inline(always)]
fn normalize(value: u64) -> u64 {
    if value >= M {
        value - M
    } else {
        value
    }
}
