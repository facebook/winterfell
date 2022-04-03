// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    AsBytes, BaseElement, ByteReader, Deserializable, DeserializationError, FieldElement,
    StarkField, M,
};
use crate::field::{ExtensionOf, QuadExtension};
use core::convert::TryFrom;
use num_bigint::BigUint;
use rand_utils::{rand_value, rand_vector};
use utils::SliceReader;

// BASIC ALGEBRA
// ================================================================================================

#[test]
fn add() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(r, r + BaseElement::ZERO);

    // test addition within bounds
    assert_eq!(
        BaseElement::from(5u8),
        BaseElement::from(2u8) + BaseElement::from(3u8)
    );

    // test overflow
    let t = BaseElement::from(BaseElement::MODULUS - 1);
    assert_eq!(BaseElement::ZERO, t + BaseElement::ONE);
    assert_eq!(BaseElement::ONE, t + BaseElement::from(2u8));

    // test random values
    let r1: BaseElement = rand_value();
    let r2: BaseElement = rand_value();

    let expected = (r1.to_big_uint() + r2.to_big_uint()) % BigUint::from(M);
    let expected = BaseElement::from_big_uint(expected);
    assert_eq!(expected, r1 + r2);
}

#[test]
fn sub() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(r, r - BaseElement::ZERO);

    // test subtraction within bounds
    assert_eq!(
        BaseElement::from(2u8),
        BaseElement::from(5u8) - BaseElement::from(3u8)
    );

    // test underflow
    let expected = BaseElement::from(BaseElement::MODULUS - 2);
    assert_eq!(expected, BaseElement::from(3u8) - BaseElement::from(5u8));
}

#[test]
fn mul() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(BaseElement::ZERO, r * BaseElement::ZERO);
    assert_eq!(r, r * BaseElement::ONE);

    // test multiplication within bounds
    assert_eq!(
        BaseElement::from(15u8),
        BaseElement::from(5u8) * BaseElement::from(3u8)
    );

    // test overflow
    let m = BaseElement::MODULUS;
    let t = BaseElement::from(m - 1);
    assert_eq!(BaseElement::ONE, t * t);
    assert_eq!(BaseElement::from(m - 2), t * BaseElement::from(2u8));
    assert_eq!(BaseElement::from(m - 4), t * BaseElement::from(4u8));

    let t = (m + 1) / 2;
    assert_eq!(
        BaseElement::ONE,
        BaseElement::from(t) * BaseElement::from(2u8)
    );

    // test random values
    let v1: Vec<BaseElement> = rand_vector(1000);
    let v2: Vec<BaseElement> = rand_vector(1000);
    for i in 0..v1.len() {
        let r1 = v1[i];
        let r2 = v2[i];

        let expected = (r1.to_big_uint() * r2.to_big_uint()) % BigUint::from(M);
        let expected = BaseElement::from_big_uint(expected);

        if expected != r1 * r2 {
            assert_eq!(expected, r1 * r2, "failed for: {} * {}", r1, r2);
        }
    }
}

#[test]
fn inv() {
    // identity
    assert_eq!(BaseElement::ONE, BaseElement::inv(BaseElement::ONE));
    assert_eq!(BaseElement::ZERO, BaseElement::inv(BaseElement::ZERO));

    // test random values
    let x: Vec<BaseElement> = rand_vector(1000);
    for i in 0..x.len() {
        let y = BaseElement::inv(x[i]);
        assert_eq!(BaseElement::ONE, x[i] * y);
    }
}

#[test]
fn conjugate() {
    let a: BaseElement = rand_value();
    let b = a.conjugate();
    assert_eq!(a, b);
}

// ROOTS OF UNITY
// ================================================================================================

#[test]
fn get_root_of_unity() {
    let root_40 = BaseElement::get_root_of_unity(40);
    assert_eq!(
        BaseElement::from(23953097886125630542083529559205016746u128),
        root_40
    );
    assert_eq!(BaseElement::ONE, root_40.exp(u128::pow(2, 40)));

    let root_39 = BaseElement::get_root_of_unity(39);
    let expected = root_40.exp(2);
    assert_eq!(expected, root_39);
    assert_eq!(BaseElement::ONE, root_39.exp(u128::pow(2, 39)));
}

#[test]
fn test_g_is_2_exp_40_root() {
    let g = BaseElement::TWO_ADIC_ROOT_OF_UNITY;
    assert_eq!(g.exp(1u128 << 40), BaseElement::ONE);
}

// FIELD EXTENSIONS
// ================================================================================================

#[test]
fn quad_mul_base() {
    let a = <QuadExtension<BaseElement>>::new(rand_value(), rand_value());
    let b0 = rand_value();
    let b = <QuadExtension<BaseElement>>::new(b0, BaseElement::ZERO);

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

#[test]
fn elements_as_bytes() {
    let source = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let expected: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    assert_eq!(expected, BaseElement::elements_as_bytes(&source));
}

#[test]
fn bytes_as_elements() {
    let bytes: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 5,
    ];

    let expected = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[..64]) };
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());

    let result = unsafe { BaseElement::bytes_as_elements(&bytes) };
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[1..]) };
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

#[test]
fn read_elements_from() {
    let bytes: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    let expected = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    // fill whole target
    let mut reader = SliceReader::new(&bytes[..64]);
    let result = BaseElement::read_batch_from(&mut reader, 4);
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());
    assert_eq!(false, reader.has_more_bytes());

    // partial number of elements
    let mut reader = SliceReader::new(&bytes[..65]);
    let result = BaseElement::read_batch_from(&mut reader, 4);
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());
    assert_eq!(true, reader.has_more_bytes());

    // invalid element
    let mut reader = SliceReader::new(&bytes[16..]);
    let result = BaseElement::read_batch_from(&mut reader, 4);
    assert!(result.is_err());
    match result {
        Err(err) => {
            assert!(matches!(err, DeserializationError::InvalidValue(_)));
        }
        _ => (),
    }
}

// INITIALIZATION
// ================================================================================================

#[test]
fn zeroed_vector() {
    let result = BaseElement::zeroed_vector(4);
    assert_eq!(4, result.len());
    for element in result.into_iter() {
        assert_eq!(BaseElement::ZERO, element);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

impl BaseElement {
    pub fn to_big_uint(&self) -> BigUint {
        BigUint::from_bytes_le(self.as_bytes())
    }

    pub fn from_big_uint(value: BigUint) -> Self {
        let bytes = value.to_bytes_le();
        let mut buffer = [0u8; 16];
        buffer[0..bytes.len()].copy_from_slice(&bytes);
        BaseElement::try_from(buffer).unwrap()
    }
}
