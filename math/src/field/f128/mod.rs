// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a 128-bit STARK-friendly prime field with modulus $2^{128} - 45 \cdot 2^{40} + 1$.
//!
//! Operations in this field are implemented using Barret reduction and are stored in their
//! canonical form using `u128` as the backing type. However, this field was not chosen with any
//! significant thought given to performance, and the implementations of most operations are
//! sub-optimal as well.

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

// Field modulus = 2^128 - 45 * 2^40 + 1
const M: u128 = 340282366920938463463374557953744961537;

// 2^40 root of unity
const G: u128 = 23953097886125630542083529559205016746;

// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = core::mem::size_of::<u128>();

// FIELD ELEMENT
// ================================================================================================

/// Represents a base field element.
///
/// Internal values are stored in their canonical form in the range [0, M). The backing type is
/// `u128`.
#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BaseElement(u128);

impl BaseElement {
    /// Creates a new field element from a u128 value. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed. This function can also be used
    /// to initialize constants.
    pub const fn new(value: u128) -> Self {
        BaseElement(if value < M { value } else { value - M })
    }
}

impl FieldElement for BaseElement {
    type PositiveInteger = u128;
    type BaseField = Self;

    const EXTENSION_DEGREE: usize = 1;

    const ZERO: Self = BaseElement(0);
    const ONE: Self = BaseElement(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    // ALGEBRA
    // --------------------------------------------------------------------------------------------

    fn inv(self) -> Self {
        BaseElement(inv(self.0))
    }

    fn conjugate(&self) -> Self {
        BaseElement(self.0)
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

        if (p as usize) % mem::align_of::<u128>() != 0 {
            return Err(DeserializationError::InvalidValue(
                "slice memory alignment is not valid for this field element type".to_string(),
            ));
        }

        Ok(slice::from_raw_parts(p as *const Self, len))
    }
}

impl StarkField for BaseElement {
    /// sage: MODULUS = 2^128 - 45 * 2^40 + 1 \
    /// sage: GF(MODULUS).is_prime_field() \
    /// True \
    /// sage: GF(MODULUS).order() \
    /// 340282366920938463463374557953744961537
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = 128;

    /// sage: GF(MODULUS).primitive_element() \
    /// 3
    const GENERATOR: Self = BaseElement(3);

    /// sage: is_odd((MODULUS - 1) / 2^40) \
    /// True
    const TWO_ADICITY: u32 = 40;

    /// sage: k = (MODULUS - 1) / 2^40 \
    /// sage: GF(MODULUS).primitive_element()^k \
    /// 23953097886125630542083529559205016746
    const TWO_ADIC_ROOT_OF_UNITY: Self = BaseElement(G);

    fn get_modulus_le_bytes() -> Vec<u8> {
        Self::MODULUS.to_le_bytes().to_vec()
    }

    #[inline]
    fn as_int(&self) -> Self::PositiveInteger {
        self.0
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
        write!(f, "{}", self.0)
    }
}

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
        [x[0] + x[1], Self::ZERO - x[1]]
    }
}

// CUBIC EXTENSION
// ================================================================================================

/// Cubic extension for this field is not implemented as quadratic extension already provides
/// sufficient security level.
impl ExtensibleField<3> for BaseElement {
    fn mul(_a: [Self; 3], _b: [Self; 3]) -> [Self; 3] {
        unimplemented!()
    }

    #[inline(always)]
    fn mul_base(_a: [Self; 3], _b: Self) -> [Self; 3] {
        unimplemented!()
    }

    #[inline(always)]
    fn frobenius(_x: [Self; 3]) -> [Self; 3] {
        unimplemented!()
    }

    fn is_supported() -> bool {
        false
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u64> for BaseElement {
    /// Converts a 64-bit value into a field element.
    fn from(value: u64) -> Self {
        BaseElement(value as u128)
    }
}

impl From<u32> for BaseElement {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        BaseElement(value as u128)
    }
}

impl From<u16> for BaseElement {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        BaseElement(value as u128)
    }
}

impl From<u8> for BaseElement {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        BaseElement(value as u128)
    }
}

impl TryFrom<u128> for BaseElement {
    type Error = String;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value >= M {
            Err(format!(
                "invalid field element: value {value} is greater than or equal to the field modulus"
            ))
        } else {
            Ok(Self::new(value))
        }
    }
}

impl TryFrom<&'_ [u8]> for BaseElement {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value =
            bytes.try_into().map(u128::from_le_bytes).map_err(|error| format!("{error}"))?;
        if value >= M {
            return Err(format!(
                "cannot convert bytes into a field element: \
                value {value} is greater or equal to the field modulus"
            ));
        }
        Ok(BaseElement(value))
    }
}

impl AsBytes for BaseElement {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const BaseElement = self;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, BaseElement::ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for BaseElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_le_bytes());
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for BaseElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u128()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {value} is greater than or equal to the field modulus"
            )));
        }
        Ok(BaseElement(value))
    }
}

// FINITE FIELD ARITHMETIC
// ================================================================================================

/// Computes (a + b) % m; a and b are assumed to be valid field elements.
fn add(a: u128, b: u128) -> u128 {
    let z = M - b;
    if a < z {
        M - z + a
    } else {
        a - z
    }
}

/// Computes (a - b) % m; a and b are assumed to be valid field elements.
fn sub(a: u128, b: u128) -> u128 {
    if a < b {
        M - b + a
    } else {
        a - b
    }
}

/// Computes (a * b) % m; a and b are assumed to be valid field elements.
fn mul(a: u128, b: u128) -> u128 {
    let (x0, x1, x2) = mul_128x64(a, (b >> 64) as u64); // x = a * b_hi
    let (mut x0, mut x1, x2) = mul_reduce(x0, x1, x2); // x = x - (x >> 128) * m
    if x2 == 1 {
        // if there was an overflow beyond 128 bits, subtract
        // modulus from the result to make sure it fits into
        // 128 bits; this can potentially be removed in favor
        // of checking overflow later
        let (t0, t1) = sub_modulus(x0, x1); // x = x - m
        x0 = t0;
        x1 = t1;
    }

    let (y0, y1, y2) = mul_128x64(a, b as u64); // y = a * b_lo

    let (mut y1, carry) = add64_with_carry(y1, x0, 0); // y = y + (x << 64)
    let (mut y2, y3) = add64_with_carry(y2, x1, carry);
    if y3 == 1 {
        // if there was an overflow beyond 192 bits, subtract
        // modulus * 2^64 from the result to make sure it fits
        // into 192 bits; this can potentially replace the
        // previous overflow check (but needs to be proven)
        let (t0, t1) = sub_modulus(y1, y2); // y = y - (m << 64)
        y1 = t0;
        y2 = t1;
    }

    let (mut z0, mut z1, z2) = mul_reduce(y0, y1, y2); // z = y - (y >> 128) * m

    // make sure z is smaller than m
    if z2 == 1 || (z1 == (M >> 64) as u64 && z0 >= (M as u64)) {
        let (t0, t1) = sub_modulus(z0, z1); // z = z - m
        z0 = t0;
        z1 = t1;
    }

    ((z1 as u128) << 64) + (z0 as u128)
}

/// Computes y such that (x * y) % m = 1 except for when when x = 0; in such a case,
/// 0 is returned; x is assumed to be a valid field element.
fn inv(x: u128) -> u128 {
    if x == 0 {
        return 0;
    };

    // initialize v, a, u, and d variables
    let mut v = M;
    let (mut a0, mut a1, mut a2) = (0, 0, 0);
    let (mut u0, mut u1, mut u2) = if x & 1 == 1 {
        // u = x
        (x as u64, (x >> 64) as u64, 0)
    } else {
        // u = x + m
        add_192x192(x as u64, (x >> 64) as u64, 0, M as u64, (M >> 64) as u64, 0)
    };
    // d = m - 1
    let (mut d0, mut d1, mut d2) = ((M as u64) - 1, (M >> 64) as u64, 0);

    // compute the inverse
    while v != 1 {
        while u2 > 0 || ((u0 as u128) + ((u1 as u128) << 64)) > v {
            // u > v
            // u = u - v
            let (t0, t1, t2) = sub_192x192(u0, u1, u2, v as u64, (v >> 64) as u64, 0);
            u0 = t0;
            u1 = t1;
            u2 = t2;

            // d = d + a
            let (t0, t1, t2) = add_192x192(d0, d1, d2, a0, a1, a2);
            d0 = t0;
            d1 = t1;
            d2 = t2;

            while u0 & 1 == 0 {
                if d0 & 1 == 1 {
                    // d = d + m
                    let (t0, t1, t2) = add_192x192(d0, d1, d2, M as u64, (M >> 64) as u64, 0);
                    d0 = t0;
                    d1 = t1;
                    d2 = t2;
                }

                // u = u >> 1
                u0 = (u0 >> 1) | ((u1 & 1) << 63);
                u1 = (u1 >> 1) | ((u2 & 1) << 63);
                u2 >>= 1;

                // d = d >> 1
                d0 = (d0 >> 1) | ((d1 & 1) << 63);
                d1 = (d1 >> 1) | ((d2 & 1) << 63);
                d2 >>= 1;
            }
        }

        // v = v - u (u is less than v at this point)
        v -= (u0 as u128) + ((u1 as u128) << 64);

        // a = a + d
        let (t0, t1, t2) = add_192x192(a0, a1, a2, d0, d1, d2);
        a0 = t0;
        a1 = t1;
        a2 = t2;

        while v & 1 == 0 {
            if a0 & 1 == 1 {
                // a = a + m
                let (t0, t1, t2) = add_192x192(a0, a1, a2, M as u64, (M >> 64) as u64, 0);
                a0 = t0;
                a1 = t1;
                a2 = t2;
            }

            v >>= 1;

            // a = a >> 1
            a0 = (a0 >> 1) | ((a1 & 1) << 63);
            a1 = (a1 >> 1) | ((a2 & 1) << 63);
            a2 >>= 1;
        }
    }

    // a = a mod m
    let mut a = (a0 as u128) + ((a1 as u128) << 64);
    while a2 > 0 || a >= M {
        let (t0, t1, t2) = sub_192x192(a0, a1, a2, M as u64, (M >> 64) as u64, 0);
        a0 = t0;
        a1 = t1;
        a2 = t2;
        a = (a0 as u128) + ((a1 as u128) << 64);
    }

    a
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline]
fn mul_128x64(a: u128, b: u64) -> (u64, u64, u64) {
    let z_lo = ((a as u64) as u128) * (b as u128);
    let z_hi = (a >> 64) * (b as u128);
    let z_hi = z_hi + (z_lo >> 64);
    (z_lo as u64, z_hi as u64, (z_hi >> 64) as u64)
}

#[inline]
fn mul_reduce(z0: u64, z1: u64, z2: u64) -> (u64, u64, u64) {
    let (q0, q1, q2) = mul_by_modulus(z2);
    let (z0, z1, z2) = sub_192x192(z0, z1, z2, q0, q1, q2);
    (z0, z1, z2)
}

#[inline]
fn mul_by_modulus(a: u64) -> (u64, u64, u64) {
    let a_lo = (a as u128).wrapping_mul(M);
    let a_hi = if a == 0 { 0 } else { a - 1 };
    (a_lo as u64, (a_lo >> 64) as u64, a_hi)
}

#[inline]
fn sub_modulus(a_lo: u64, a_hi: u64) -> (u64, u64) {
    let mut z = 0u128.wrapping_sub(M);
    z = z.wrapping_add(a_lo as u128);
    z = z.wrapping_add((a_hi as u128) << 64);
    (z as u64, (z >> 64) as u64)
}

#[inline]
fn sub_192x192(a0: u64, a1: u64, a2: u64, b0: u64, b1: u64, b2: u64) -> (u64, u64, u64) {
    let z0 = (a0 as u128).wrapping_sub(b0 as u128);
    let z1 = (a1 as u128).wrapping_sub((b1 as u128) + (z0 >> 127));
    let z2 = (a2 as u128).wrapping_sub((b2 as u128) + (z1 >> 127));
    (z0 as u64, z1 as u64, z2 as u64)
}

#[inline]
fn add_192x192(a0: u64, a1: u64, a2: u64, b0: u64, b1: u64, b2: u64) -> (u64, u64, u64) {
    let z0 = (a0 as u128) + (b0 as u128);
    let z1 = (a1 as u128) + (b1 as u128) + (z0 >> 64);
    let z2 = (a2 as u128) + (b2 as u128) + (z1 >> 64);
    (z0 as u64, z1 as u64, z2 as u64)
}

#[inline]
const fn add64_with_carry(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}
