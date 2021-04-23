// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::*;
use num_bigint::BigUint;

// BASIC ALGEBRA
// ================================================================================================

#[test]
fn add() {
    // identity
    let r = BaseElement::rand();
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
    let r1 = BaseElement::rand();
    let r2 = BaseElement::rand();

    let expected = (r1.to_big_uint() + r2.to_big_uint()) % BigUint::from(M);
    let expected = BaseElement::from_big_uint(expected);
    assert_eq!(expected, r1 + r2);
}

#[test]
fn sub() {
    // identity
    let r = BaseElement::rand();
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
    let r = BaseElement::rand();
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
    let v1 = BaseElement::prng_vector(build_seed(), 1000);
    let v2 = BaseElement::prng_vector(build_seed(), 1000);
    for i in 0..v1.len() {
        let r1 = v1[i];
        let r2 = v2[i];

        let expected = (r1.to_big_uint() * r2.to_big_uint()) % BigUint::from(M);
        let expected = BaseElement::from_big_uint(expected);

        if expected != r1 * r2 {
            println!("failed for: {} * {}", r1, r2);
            assert_eq!(expected, r1 * r2);
        }
    }
}

#[test]
fn inv() {
    // identity
    assert_eq!(BaseElement::ONE, BaseElement::inv(BaseElement::ONE));
    assert_eq!(BaseElement::ZERO, BaseElement::inv(BaseElement::ZERO));

    // test random values
    let x = BaseElement::prng_vector(build_seed(), 1000);
    for i in 0..x.len() {
        let y = BaseElement::inv(x[i]);
        assert_eq!(BaseElement::ONE, x[i] * y);
    }
}

#[test]
fn conjugate() {
    let a = BaseElement::rand();
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

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

#[test]
fn elements_into_bytes() {
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

    assert_eq!(expected, BaseElement::elements_into_bytes(source));
}

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
    assert_eq!(
        result,
        Err(SerializationError::NotEnoughBytesForWholeElements(65))
    );

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[1..]) };
    assert_eq!(result, Err(SerializationError::InvalidMemoryAlignment));
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

#[test]
fn prng_vector() {
    let a = BaseElement::prng_vector([0; 32], 4);
    assert_eq!(4, a.len());

    let b = BaseElement::prng_vector([0; 32], 8);
    assert_eq!(8, b.len());

    for (&a, &b) in a.iter().zip(b.iter()) {
        assert_eq!(a, b);
    }

    let c = BaseElement::prng_vector([1; 32], 4);
    for (&a, &c) in a.iter().zip(c.iter()) {
        assert_ne!(a, c);
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_seed() -> [u8; 32] {
    let mut result = [0; 32];
    let seed = BaseElement::rand().as_bytes().to_vec();
    result[..16].copy_from_slice(&seed);
    result
}

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
