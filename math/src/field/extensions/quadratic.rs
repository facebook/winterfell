// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{FieldElement, StarkField};
use core::{
    convert::TryFrom,
    fmt::{Debug, Display, Formatter},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};
use utils::{
    collections::Vec,
    string::{String, ToString},
    AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

// QUADRATIC EXTENSION FIELD
// ================================================================================================

/// Represents an element in a quadratic extensions field defined as F\[x\]/(x^2-x-1).
///
/// The extension element is α + β * φ, where φ is a root of the polynomial x^2 - x - 1, and α
/// and β are base field elements.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct QuadExtensionA<B: StarkField>(B, B);

impl<B: StarkField> QuadExtensionA<B> {
    /// Converts a vector of base elements into a vector of elements in a quadratic extension
    /// field by fusing two adjacent base elements together. The output vector is half the length
    /// of the source vector.
    fn base_to_quad_vector(source: Vec<B>) -> Vec<Self> {
        debug_assert!(
            source.len() % 2 == 0,
            "source vector length must be divisible by two, but was {}",
            source.len()
        );
        let mut v = core::mem::ManuallyDrop::new(source);
        let p = v.as_mut_ptr();
        let len = v.len() / 2;
        let cap = v.capacity() / 2;
        unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    }
}

impl<B: StarkField> FieldElement for QuadExtensionA<B> {
    type PositiveInteger = B::PositiveInteger;
    type BaseField = B;

    const ELEMENT_BYTES: usize = B::ELEMENT_BYTES * 2;
    const IS_CANONICAL: bool = B::IS_CANONICAL;
    const ZERO: Self = Self(B::ZERO, B::ZERO);
    const ONE: Self = Self(B::ONE, B::ZERO);

    fn inv(self) -> Self {
        if self == Self::ZERO {
            return Self::ZERO;
        }
        #[allow(clippy::suspicious_operation_groupings)]
        let denom = (self.0 * self.0) + (self.0 * self.1) - (self.1 * self.1);
        let denom_inv = denom.inv();
        Self((self.0 + self.1) * denom_inv, self.1.neg() * denom_inv)
    }

    fn conjugate(&self) -> Self {
        Self(self.0 + self.1, B::ZERO - self.1)
    }

    #[cfg(feature = "std")]
    fn rand() -> Self {
        Self(B::rand(), B::rand())
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(&bytes[..Self::ELEMENT_BYTES as usize]).ok()
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                elements.as_ptr() as *const u8,
                elements.len() * Self::ELEMENT_BYTES,
            )
        }
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

        // make sure the bytes are aligned on the boundary consistent with base element alignment
        if (p as usize) % Self::BaseField::ELEMENT_BYTES != 0 {
            return Err(DeserializationError::InvalidValue(
                "slice memory alignment is not valid for this field element type".to_string(),
            ));
        }

        Ok(slice::from_raw_parts(p as *const Self, len))
    }

    fn zeroed_vector(n: usize) -> Vec<Self> {
        // get twice the number of base elements, and re-interpret them as quad field elements
        let result = B::zeroed_vector(n * 2);
        Self::base_to_quad_vector(result)
    }

    #[cfg(feature = "std")]
    fn prng_vector(seed: [u8; 32], n: usize) -> Vec<Self> {
        // get twice the number of base elements, and re-interpret them as quad field elements
        let result = B::prng_vector(seed, n * 2);
        Self::base_to_quad_vector(result)
    }

    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        let ptr = elements.as_ptr();
        let len = elements.len() * 2;
        unsafe { slice::from_raw_parts(ptr as *const Self::BaseField, len) }
    }
}

impl<B: StarkField> Display for QuadExtensionA<B> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "({}, {})", self.0, self.1)
    }
}

// OVERLOADED OPERATORS
// ------------------------------------------------------------------------------------------------

impl<B: StarkField> Add for QuadExtensionA<B> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<B: StarkField> AddAssign for QuadExtensionA<B> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<B: StarkField> Sub for QuadExtensionA<B> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<B: StarkField> SubAssign for QuadExtensionA<B> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<B: StarkField> Mul for QuadExtensionA<B> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let coef0_mul = self.0 * rhs.0;
        Self(
            coef0_mul + self.1 * rhs.1,
            (self.0 + self.1) * (rhs.0 + rhs.1) - coef0_mul,
        )
    }
}

impl<B: StarkField> MulAssign for QuadExtensionA<B> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl<B: StarkField> Div for QuadExtensionA<B> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}

impl<B: StarkField> DivAssign for QuadExtensionA<B> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl<B: StarkField> Neg for QuadExtensionA<B> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(B::ZERO - self.0, B::ZERO - self.1)
    }
}

// TYPE CONVERSIONS
// ------------------------------------------------------------------------------------------------

impl<B: StarkField> From<B> for QuadExtensionA<B> {
    fn from(e: B) -> Self {
        Self(e, B::ZERO)
    }
}

impl<B: StarkField> From<u128> for QuadExtensionA<B> {
    fn from(value: u128) -> Self {
        Self(B::from(value), B::ZERO)
    }
}

impl<B: StarkField> From<u64> for QuadExtensionA<B> {
    fn from(value: u64) -> Self {
        Self(B::from(value), B::ZERO)
    }
}

impl<B: StarkField> From<u32> for QuadExtensionA<B> {
    fn from(value: u32) -> Self {
        Self(B::from(value), B::ZERO)
    }
}

impl<B: StarkField> From<u16> for QuadExtensionA<B> {
    fn from(value: u16) -> Self {
        Self(B::from(value), B::ZERO)
    }
}

impl<B: StarkField> From<u8> for QuadExtensionA<B> {
    fn from(value: u8) -> Self {
        Self(B::from(value), B::ZERO)
    }
}

impl<'a, B: StarkField> TryFrom<&'a [u8]> for QuadExtensionA<B> {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < Self::ELEMENT_BYTES {
            return Err(
                "need more bytes in order to convert into extension field element".to_string(),
            );
        }
        let value0 = match B::try_from(&bytes[..B::ELEMENT_BYTES]) {
            Ok(val) => val,
            Err(_) => {
                return Err("could not convert into field element".to_string());
            }
        };
        let value1 = match B::try_from(&bytes[B::ELEMENT_BYTES..]) {
            Ok(val) => val,
            Err(_) => {
                return Err("could not convert into field element".to_string());
            }
        };
        Ok(Self(value0, value1))
    }
}

impl<B: StarkField> AsBytes for QuadExtensionA<B> {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const Self = self;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, Self::ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl<B: StarkField> Serializable for QuadExtensionA<B> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
    }
}

impl<B: StarkField> Deserializable for QuadExtensionA<B> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value0 = B::read_from(source)?;
        let value1 = B::read_from(source)?;
        Ok(Self(value0, value1))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{AsBytes, DeserializationError, FieldElement, QuadExtensionA, Vec};
    use crate::field::f128::BaseElement;

    // BASIC ALGEBRA
    // --------------------------------------------------------------------------------------------

    #[test]
    fn add() {
        // identity
        let r = QuadExtensionA::<BaseElement>::rand();
        assert_eq!(r, r + QuadExtensionA::<BaseElement>::ZERO);

        // test random values
        let r1 = QuadExtensionA::<BaseElement>::rand();
        let r2 = QuadExtensionA::<BaseElement>::rand();

        let expected = QuadExtensionA(r1.0 + r2.0, r1.1 + r2.1);
        assert_eq!(expected, r1 + r2);
    }

    #[test]
    fn sub() {
        // identity
        let r = QuadExtensionA::<BaseElement>::rand();
        assert_eq!(r, r - QuadExtensionA::<BaseElement>::ZERO);

        // test random values
        let r1 = QuadExtensionA::<BaseElement>::rand();
        let r2 = QuadExtensionA::<BaseElement>::rand();

        let expected = QuadExtensionA(r1.0 - r2.0, r1.1 - r2.1);
        assert_eq!(expected, r1 - r2);
    }

    #[test]
    fn mul() {
        // identity
        let r = QuadExtensionA::<BaseElement>::rand();
        assert_eq!(
            QuadExtensionA::<BaseElement>::ZERO,
            r * QuadExtensionA::<BaseElement>::ZERO
        );
        assert_eq!(r, r * QuadExtensionA::<BaseElement>::ONE);

        // test random values
        let r1 = QuadExtensionA::<BaseElement>::rand();
        let r2 = QuadExtensionA::<BaseElement>::rand();

        let expected = QuadExtensionA(
            r1.0 * r2.0 + r1.1 * r2.1,
            (r1.0 + r1.1) * (r2.0 + r2.1) - r1.0 * r2.0,
        );
        assert_eq!(expected, r1 * r2);
    }

    #[test]
    fn inv() {
        // identity
        assert_eq!(
            QuadExtensionA::<BaseElement>::ONE,
            QuadExtensionA::<BaseElement>::inv(QuadExtensionA::<BaseElement>::ONE)
        );
        assert_eq!(
            QuadExtensionA::<BaseElement>::ZERO,
            QuadExtensionA::<BaseElement>::inv(QuadExtensionA::<BaseElement>::ZERO)
        );

        // test random values
        let x = QuadExtensionA::<BaseElement>::prng_vector(build_seed(), 1000);
        for i in 0..x.len() {
            let y = QuadExtensionA::<BaseElement>::inv(x[i]);
            assert_eq!(QuadExtensionA::<BaseElement>::ONE, x[i] * y);
        }
    }

    #[test]
    fn conjugate() {
        let a = QuadExtensionA::<BaseElement>::rand();
        let b = a.conjugate();
        let expected = QuadExtensionA(a.0 + a.1, -a.1);
        assert_eq!(expected, b);
    }

    // INITIALIZATION
    // --------------------------------------------------------------------------------------------

    #[test]
    fn zeroed_vector() {
        let result = QuadExtensionA::<BaseElement>::zeroed_vector(4);
        assert_eq!(4, result.len());
        for element in result.into_iter() {
            assert_eq!(QuadExtensionA::<BaseElement>::ZERO, element);
        }
    }

    #[test]
    fn prng_vector() {
        let a = QuadExtensionA::<BaseElement>::prng_vector([0; 32], 4);
        assert_eq!(4, a.len());

        let b = QuadExtensionA::<BaseElement>::prng_vector([0; 32], 8);
        assert_eq!(8, b.len());

        for (&a, &b) in a.iter().zip(b.iter()) {
            assert_eq!(a, b);
        }

        let c = QuadExtensionA::<BaseElement>::prng_vector([1; 32], 4);
        for (&a, &c) in a.iter().zip(c.iter()) {
            assert_ne!(a, c);
        }
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    #[test]
    fn elements_as_bytes() {
        let source = vec![
            QuadExtensionA(BaseElement::new(1), BaseElement::new(2)),
            QuadExtensionA(BaseElement::new(3), BaseElement::new(4)),
        ];

        let expected: Vec<u8> = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(
            expected,
            QuadExtensionA::<BaseElement>::elements_as_bytes(&source)
        );
    }

    #[test]
    fn bytes_as_elements() {
        let bytes: Vec<u8> = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 5,
        ];

        let expected = vec![
            QuadExtensionA(BaseElement::new(1), BaseElement::new(2)),
            QuadExtensionA(BaseElement::new(3), BaseElement::new(4)),
        ];

        let result = unsafe { QuadExtensionA::<BaseElement>::bytes_as_elements(&bytes[..64]) };
        assert!(result.is_ok());
        assert_eq!(expected, result.unwrap());

        let result = unsafe { QuadExtensionA::<BaseElement>::bytes_as_elements(&bytes) };
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));

        let result = unsafe { QuadExtensionA::<BaseElement>::bytes_as_elements(&bytes[1..]) };
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
    }

    // UTILITIES
    // --------------------------------------------------------------------------------------------

    #[test]
    fn as_base_elements() {
        let elements = vec![
            QuadExtensionA(BaseElement::new(1), BaseElement::new(2)),
            QuadExtensionA(BaseElement::new(3), BaseElement::new(4)),
        ];

        let expected = vec![
            BaseElement::new(1),
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(4),
        ];

        assert_eq!(
            expected,
            QuadExtensionA::<BaseElement>::as_base_elements(&elements)
        );
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------
    fn build_seed() -> [u8; 32] {
        let mut result = [0; 32];
        let seed = QuadExtensionA::<BaseElement>::rand().as_bytes().to_vec();
        result.copy_from_slice(&seed);
        result
    }
}
