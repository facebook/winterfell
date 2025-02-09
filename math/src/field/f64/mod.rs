// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a 64-bit STARK-friendly prime field with modulus $2^{64} - 2^{32} + 1$
//! using Montgomery representation.
//!
//! Our implementation follows <https://eprint.iacr.org/2022/274.pdf> and is constant-time.
//!
//! This field supports very fast modular arithmetic and has a number of other attractive
//! properties, including:
//!
//! * Multiplication of two 32-bit values does not overflow field modulus.
//! * Field arithmetic in this field can be implemented using a few 32-bit addition, subtractions,
//!   and shifts.
//! * $8$ is the 64th root of unity which opens up potential for optimized FFT implementations.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::{Debug, Display, Formatter},
    mem,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use utils::{
    AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable,
    Serializable,
};

use super::{ExtensibleField, FieldElement, StarkField};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Field modulus = 2^64 - 2^32 + 1
const M: u64 = 0xffffffff00000001;

/// 2^128 mod M; this is used for conversion of elements into Montgomery representation.
const R2: u64 = 0xfffffffe00000001;

/// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = core::mem::size_of::<u64>();

// FIELD ELEMENT
// ================================================================================================

/// Represents base field element in the field using Montgomery representation.
///
/// Internal values represent x * R mod M where R = 2^64 mod M and x in [0, M).
/// The backing type is `u64` but the internal values are always in the range [0, M).
#[derive(Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u64", into = "u64"))]
pub struct BaseElement(u64);

impl BaseElement {
    /// Creates a new field element from the provided `value`; the value is converted into
    /// Montgomery representation.
    ///
    /// If the value is greater than or equal to the field modulus, modular reduction is
    /// silently performed.
    pub const fn new(value: u64) -> BaseElement {
        Self(mont_red_cst((value as u128) * (R2 as u128)))
    }

    /// Returns a new field element from the provided 'value'. Assumes that 'value' is already
    /// in canonical Montgomery form.
    pub const fn from_mont(value: u64) -> BaseElement {
        BaseElement(value)
    }

    /// Returns the non-canonical u64 inner value.
    pub const fn inner(&self) -> u64 {
        self.0
    }

    /// Returns canonical integer representation of this field element.
    #[inline(always)]
    pub const fn as_int(&self) -> u64 {
        mont_to_int(self.0)
    }

    /// Computes an exponentiation to the power 7. This is useful for computing Rescue-Prime
    /// S-Box over this field.
    #[inline(always)]
    pub fn exp7(self) -> Self {
        let x2 = self.square();
        let x4 = x2.square();
        let x3 = x2 * self;
        x3 * x4
    }

    /// Multiplies an element that is less than 2^32 by a field element. This implementation
    /// is faster as it avoids the use of Montgomery reduction.
    #[inline(always)]
    pub const fn mul_small(self, rhs: u32) -> Self {
        let s = (self.inner() as u128) * (rhs as u128);
        let s_hi = (s >> 64) as u64;
        let s_lo = s as u64;
        let z = (s_hi << 32) - s_hi;
        let (res, over) = s_lo.overflowing_add(z);

        BaseElement::from_mont(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64))
    }
}

impl FieldElement for BaseElement {
    type PositiveInteger = u64;
    type BaseField = Self;

    const EXTENSION_DEGREE: usize = 1;

    const ZERO: Self = Self::new(0);
    const ONE: Self = Self::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;
    const IS_CANONICAL: bool = false;

    // ALGEBRA
    // --------------------------------------------------------------------------------------------

    #[inline]
    fn double(self) -> Self {
        let ret = (self.0 as u128) << 1;
        let (result, over) = (ret as u64, (ret >> 64) as u64);
        Self(result.wrapping_sub(M * over))
    }

    #[inline]
    fn exp(self, power: Self::PositiveInteger) -> Self {
        let mut b: Self;
        let mut r = Self::ONE;
        for i in (0..64).rev() {
            r = r.square();
            b = r;
            b *= self;
            // Constant-time branching
            let mask = -(((power >> i) & 1 == 1) as i64) as u64;
            r.0 ^= mask & (r.0 ^ b.0);
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

    // BASE ELEMENT CONVERSIONS
    // --------------------------------------------------------------------------------------------

    fn base_element(&self, i: usize) -> Self::BaseField {
        match i {
            0 => *self,
            _ => panic!("element index must be 0, but was {i}"),
        }
    }

    fn slice_as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        elements
    }

    fn slice_from_base_elements(elements: &[Self::BaseField]) -> &[Self] {
        elements
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        // TODO: take endianness into account.
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

    /// Root of unity for domain of 2^32 elements. This root of unity is selected because
    /// it implies that the generator for domain of size 64 is 8. This is attractive because
    /// it allows replacing some multiplications with shifts (e.g., for NTT computations).
    ///
    /// sage: Fp = GF(MODULUS) \
    /// sage: g = Fp(7277203076849721926) \
    /// sage: g^(2^32) \
    /// 1 \
    /// sage: [int(g^(2^i) == 1) for i in range(1,32)]
    /// [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(7277203076849721926);

    fn get_modulus_le_bytes() -> Vec<u8> {
        M.to_le_bytes().to_vec()
    }

    #[inline]
    fn as_int(&self) -> Self::PositiveInteger {
        mont_to_int(self.0)
    }
}

impl Randomizable for BaseElement {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl Debug for BaseElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
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
        equals(self.0, other.0) == 0xffffffffffffffff
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
        // We compute a + b = a - (p - b).
        let (x1, c1) = self.0.overflowing_sub(M - rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        Self(x1.wrapping_sub(adj as u64))
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
        let (x1, c1) = self.0.overflowing_sub(rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        Self(x1.wrapping_sub(adj as u64))
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
        Self(mont_red_cst((self.0 as u128) * (rhs.0 as u128)))
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
        Self::ZERO - self
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
        [a0b0 - (a[1] * b[1]).double(), (a[0] + a[1]) * (b[0] + b[1]) - a0b0]
    }

    #[inline(always)]
    fn square(a: [Self; 2]) -> [Self; 2] {
        let a0 = a[0];
        let a1 = a[1];

        let a1_sq = a1.square();

        let out0 = a0.square() - a1_sq.double();
        let out1 = (a0 * a1).double() + a1_sq;

        [out0, out1]
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

        [a0b0_a1b2_a2b1, a0b1_a1b0_a1b2_a2b1_a2b2, a0b2_a1b1_a2b0_a2b2]
    }

    #[inline(always)]
    fn square(a: [Self; 3]) -> [Self; 3] {
        let a0 = a[0];
        let a1 = a[1];
        let a2 = a[2];

        let a2_sq = a2.square();
        let a1_a2 = a1 * a2;

        let out0 = a0.square() + a1_a2.double();
        let out1 = (a0 * a1 + a1_a2).double() + a2_sq;
        let out2 = (a0 * a2).double() + a1.square() + a2_sq;

        [out0, out1, out2]
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
            x[0] + Self::new(10615703402128488253) * x[1] + Self::new(6700183068485440220) * x[2],
            Self::new(10050274602728160328) * x[1] + Self::new(14531223735771536287) * x[2],
            Self::new(11746561000929144102) * x[1] + Self::new(8396469466686423992) * x[2],
        ]
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<bool> for BaseElement {
    fn from(value: bool) -> Self {
        Self::new(value.into())
    }
}

impl From<u8> for BaseElement {
    fn from(value: u8) -> Self {
        Self::new(value.into())
    }
}

impl From<u16> for BaseElement {
    fn from(value: u16) -> Self {
        Self::new(value.into())
    }
}

impl From<u32> for BaseElement {
    fn from(value: u32) -> Self {
        Self::new(value.into())
    }
}

impl TryFrom<u64> for BaseElement {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value >= M {
            Err(format!(
                "invalid field element: value {value} is greater than or equal to the field modulus"
            ))
        } else {
            Ok(Self::new(value))
        }
    }
}

impl TryFrom<u128> for BaseElement {
    type Error = String;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value >= M.into() {
            Err(format!(
                "invalid field element: value {value} is greater than or equal to the field modulus"
            ))
        } else {
            Ok(Self::new(value as u64))
        }
    }
}

impl TryFrom<usize> for BaseElement {
    type Error = String;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match u64::try_from(value) {
            Err(_) => Err(format!("invalid field element: value {value} does not fit in a u64")),
            Ok(v) => v.try_into(),
        }
    }
}

impl TryFrom<[u8; 8]> for BaseElement {
    type Error = String;

    fn try_from(bytes: [u8; 8]) -> Result<Self, Self::Error> {
        let value = u64::from_le_bytes(bytes);
        Self::try_from(value)
    }
}

impl TryFrom<&'_ [u8]> for BaseElement {
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
        let bytes: [u8; 8] = bytes.try_into().expect("slice to array conversion failed");
        bytes.try_into().map_err(DeserializationError::InvalidValue)
    }
}

impl TryFrom<BaseElement> for bool {
    type Error = String;

    fn try_from(value: BaseElement) -> Result<Self, Self::Error> {
        match value.as_int() {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(format!("Field element does not represent a boolean, got {}", v)),
        }
    }
}

impl TryFrom<BaseElement> for u8 {
    type Error = String;

    fn try_from(value: BaseElement) -> Result<Self, Self::Error> {
        value.as_int().try_into().map_err(|e| format!("{}", e))
    }
}

impl TryFrom<BaseElement> for u16 {
    type Error = String;

    fn try_from(value: BaseElement) -> Result<Self, Self::Error> {
        value.as_int().try_into().map_err(|e| format!("{}", e))
    }
}

impl TryFrom<BaseElement> for u32 {
    type Error = String;

    fn try_from(value: BaseElement) -> Result<Self, Self::Error> {
        value.as_int().try_into().map_err(|e| format!("{}", e))
    }
}

impl From<BaseElement> for u64 {
    fn from(value: BaseElement) -> Self {
        value.as_int()
    }
}

impl From<BaseElement> for u128 {
    fn from(value: BaseElement) -> Self {
        value.as_int().into()
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
// ================================================================================================

impl Serializable for BaseElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // convert from Montgomery representation into canonical representation
        target.write_bytes(&self.as_int().to_le_bytes());
    }

    fn get_size_hint(&self) -> usize {
        self.as_int().get_size_hint()
    }
}

impl Deserializable for BaseElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {value} is greater than or equal to the field modulus"
            )));
        }
        Ok(Self::new(value))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Squares the base N number of times and multiplies the result by the tail value.
#[inline(always)]
fn exp_acc<const N: usize>(base: BaseElement, tail: BaseElement) -> BaseElement {
    let mut result = base;
    for _ in 0..N {
        result = result.square();
    }
    result * tail
}

/// Montgomery reduction (variable time)
#[allow(dead_code)]
#[inline(always)]
const fn mont_red_var(x: u128) -> u64 {
    const NPRIME: u64 = 4294967297;
    let q = (((x as u64) as u128) * (NPRIME as u128)) as u64;
    let m = (q as u128) * (M as u128);
    let y = (((x as i128).wrapping_sub(m as i128)) >> 64) as i64;
    if x < m {
        (y + (M as i64)) as u64
    } else {
        y as u64
    }
}

/// Montgomery reduction (constant time)
#[inline(always)]
const fn mont_red_cst(x: u128) -> u64 {
    // See reference above for a description of the following implementation.
    let xl = x as u64;
    let xh = (x >> 64) as u64;
    let (a, e) = xl.overflowing_add(xl << 32);

    let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);

    let (r, c) = xh.overflowing_sub(b);
    r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)
}

// Converts a field element in Montgomery form to canonical form. That is, given x, it computes
// x/2^64 modulo M. This is exactly what mont_red_cst does only that it does it more efficiently
// using the fact that a field element in Montgomery form is stored as a u64 and thus one can
// use this to simplify mont_red_cst in this case.
#[inline(always)]
const fn mont_to_int(x: u64) -> u64 {
    let (a, e) = x.overflowing_add(x << 32);
    let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);

    let (r, c) = 0u64.overflowing_sub(b);
    r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)
}

/// Test of equality between two BaseField elements; return value is
/// 0xFFFFFFFFFFFFFFFF if the two values are equal, or 0 otherwise.
#[inline(always)]
fn equals(lhs: u64, rhs: u64) -> u64 {
    let t = lhs ^ rhs;
    !((((t | t.wrapping_neg()) as i64) >> 63) as u64)
}
