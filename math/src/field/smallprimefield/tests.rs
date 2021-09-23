use crate::field::traits::{FieldElement, StarkField};
use core::convert::TryFrom;
use utils::{collections::Vec, AsBytes};

use super::BaseElement;
use num_bigint::BigUint;
use rand_utils::{rand_value, rand_vector};

type SmallFieldElement17 = BaseElement<17, 3, 4>;
type SmallFieldElement37 = BaseElement<37, 2, 2>;

#[test]
fn test_two_adicity_17() {
    assert!(4 == SmallFieldElement17::TWO_ADICITY, "Two-adicity of SmallFieldElement17 = {}", SmallFieldElement17::TWO_ADICITY);
}


#[test]
fn test_add_17() {
    // identity
    let r: SmallFieldElement17 = rand_value();
    assert_eq!(r, r + SmallFieldElement17::ZERO);

    // test addition within bounds
    assert_eq!(
        SmallFieldElement17::from(5u8),
        SmallFieldElement17::from(2u8) + SmallFieldElement17::from(3u8)
    );

    // test overflow
    let t = SmallFieldElement17::from(SmallFieldElement17::MODULUS - 1);
    assert_eq!(SmallFieldElement17::ZERO, t + SmallFieldElement17::ONE);
    assert_eq!(SmallFieldElement17::ONE, t + SmallFieldElement17::from(2u8));

    // test random values
    let r1: SmallFieldElement17 = rand_value();
    let r2: SmallFieldElement17 = rand_value();

    let expected =
        (r1.to_big_uint() + r2.to_big_uint()) % BigUint::from(SmallFieldElement17::MODULUS);
    let expected = SmallFieldElement17::from_big_uint(expected);
    assert_eq!(expected, r1 + r2);
}

#[test]
fn test_add_37() {
    // identity
    let r: SmallFieldElement37 = rand_value();
    assert_eq!(r, r + SmallFieldElement37::ZERO);

    // test addition within bounds
    assert_eq!(
        SmallFieldElement37::from(5u8),
        SmallFieldElement37::from(2u8) + SmallFieldElement37::from(3u8)
    );

    // test overflow
    let t = SmallFieldElement37::from(SmallFieldElement37::MODULUS - 1);
    assert_eq!(SmallFieldElement37::ZERO, t + SmallFieldElement37::ONE);
    assert_eq!(SmallFieldElement37::ONE, t + SmallFieldElement37::from(2u8));

    // test random values
    let r1: SmallFieldElement37 = rand_value();
    let r2: SmallFieldElement37 = rand_value();

    let expected =
        (r1.to_big_uint() + r2.to_big_uint()) % BigUint::from(SmallFieldElement37::MODULUS);
    let expected = SmallFieldElement37::from_big_uint(expected);
    assert_eq!(expected, r1 + r2);
}

#[test]
fn test_sub_17() {
    // identity
    let r: SmallFieldElement17 = rand_value();
    assert_eq!(r, r - SmallFieldElement17::ZERO);

    // test subtraction within bounds
    assert_eq!(
        SmallFieldElement17::from(2u8),
        SmallFieldElement17::from(5u8) - SmallFieldElement17::from(3u8)
    );

    // test underflow
    let expected = SmallFieldElement17::from(SmallFieldElement17::MODULUS - 2);
    assert_eq!(
        expected,
        SmallFieldElement17::from(3u8) - SmallFieldElement17::from(5u8)
    );
}

#[test]
fn test_sub_37() {
    // identity
    let r: SmallFieldElement37 = rand_value();
    assert_eq!(r, r - SmallFieldElement37::ZERO);

    // test subtraction within bounds
    assert_eq!(
        SmallFieldElement37::from(2u8),
        SmallFieldElement37::from(5u8) - SmallFieldElement37::from(3u8)
    );

    // test underflow
    let expected = SmallFieldElement37::from(SmallFieldElement37::MODULUS - 2);
    assert_eq!(
        expected,
        SmallFieldElement37::from(3u8) - SmallFieldElement37::from(5u8)
    );
}

#[test]
fn test_mul_17() {
    // identity
    let r: SmallFieldElement17 = rand_value();
    assert_eq!(SmallFieldElement17::ZERO, r * SmallFieldElement17::ZERO);
    assert_eq!(r, r * SmallFieldElement17::ONE);

    // test multiplication within bounds
    assert_eq!(
        SmallFieldElement17::from(6u8),
        SmallFieldElement17::from(2u8) * SmallFieldElement17::from(3u8)
    );

    // test overflow
    let m = SmallFieldElement17::MODULUS;
    let t = SmallFieldElement17::from(m - 1);
    assert_eq!(SmallFieldElement17::ONE, t * t);
    assert_eq!(
        SmallFieldElement17::from(m - 2),
        t * SmallFieldElement17::from(2u8)
    );
    assert_eq!(
        SmallFieldElement17::from(m - 4),
        t * SmallFieldElement17::from(4u8)
    );

    let t = (m + 1) / 2;
    assert_eq!(
        SmallFieldElement17::ONE,
        SmallFieldElement17::from(t) * SmallFieldElement17::from(2u8)
    );

    // test random values
    let v1: Vec<SmallFieldElement17> = rand_vector(50);
    let v2: Vec<SmallFieldElement17> = rand_vector(50);
    for i in 0..v1.len() {
        let r1 = v1[i];
        let r2 = v2[i];

        let expected =
            (r1.to_big_uint() * r2.to_big_uint()) % BigUint::from(SmallFieldElement17::MODULUS);
        let expected = SmallFieldElement17::from_big_uint(expected);

        if expected != r1 * r2 {
            println!("failed for: {} * {}", r1, r2);
            assert_eq!(expected, r1 * r2);
        }
    }
}

#[test]
fn test_mul_37() {
    // identity
    let r: SmallFieldElement37 = rand_value();
    assert_eq!(SmallFieldElement37::ZERO, r * SmallFieldElement37::ZERO);
    assert_eq!(r, r * SmallFieldElement37::ONE);

    // test multiplication within bounds
    assert_eq!(
        SmallFieldElement37::from(6u8),
        SmallFieldElement37::from(2u8) * SmallFieldElement37::from(3u8)
    );

    // test overflow
    let m = SmallFieldElement37::MODULUS;
    let t = SmallFieldElement37::from(m - 1);
    assert_eq!(SmallFieldElement37::ONE, t * t);
    assert_eq!(
        SmallFieldElement37::from(m - 2),
        t * SmallFieldElement37::from(2u8)
    );
    assert_eq!(
        SmallFieldElement37::from(m - 4),
        t * SmallFieldElement37::from(4u8)
    );

    let t = (m + 1) / 2;
    assert_eq!(
        SmallFieldElement37::ONE,
        SmallFieldElement37::from(t) * SmallFieldElement37::from(2u8)
    );

    // test random values
    let v1: Vec<SmallFieldElement37> = rand_vector(50);
    let v2: Vec<SmallFieldElement37> = rand_vector(50);
    for i in 0..v1.len() {
        let r1 = v1[i];
        let r2 = v2[i];

        let expected =
            (r1.to_big_uint() * r2.to_big_uint()) % BigUint::from(SmallFieldElement37::MODULUS);
        let expected = SmallFieldElement37::from_big_uint(expected);

        if expected != r1 * r2 {
            println!("failed for: {} * {}", r1, r2);
            assert_eq!(expected, r1 * r2);
        }
    }
}

#[test]
fn test_inv_17() {
    // identity
    assert_eq!(
        SmallFieldElement17::ONE,
        SmallFieldElement17::inv(SmallFieldElement17::ONE)
    );
    assert_eq!(
        SmallFieldElement17::ZERO,
        SmallFieldElement17::inv(SmallFieldElement17::ZERO)
    );

    // test random values
    let x: Vec<SmallFieldElement17> = rand_vector(5);
    for i in 0..x.len() {
        let y = SmallFieldElement17::inv(x[i]);
        assert!(x[i] == SmallFieldElement17::ZERO || SmallFieldElement17::ONE == x[i] * y);
    }
}

#[test]
fn test_inv_37() {
    // identity
    assert_eq!(
        SmallFieldElement37::ONE,
        SmallFieldElement37::inv(SmallFieldElement37::ONE)
    );
    assert_eq!(
        SmallFieldElement37::ZERO,
        SmallFieldElement37::inv(SmallFieldElement37::ZERO)
    );

    // test random values
    let x: Vec<SmallFieldElement37> = rand_vector(5);
    for i in 0..x.len() {
        let y = SmallFieldElement37::inv(x[i]);
        assert!(x[i] == SmallFieldElement37::ZERO || SmallFieldElement37::ONE == x[i] * y);
    }
}

#[test]
fn test_get_root_of_unity_17() {
    let root_16 = SmallFieldElement17::get_root_of_unity(16);
    assert_eq!(SmallFieldElement17::from(3u32), root_16);

    let powers: Vec<u32> = vec![3, 9, 10, 13, 5, 15, 11, 16, 14, 8, 7, 4, 12, 2, 6];
    for i in 1..16 {
        assert_eq!(
            SmallFieldElement17::from(powers[i - 1]),
            SmallFieldElement17::exp(root_16, i as u64)
        );
    }

    let root_2 = SmallFieldElement17::get_root_of_unity(2);

    let expected = SmallFieldElement17::exp(root_16, 8);
    assert_eq!(expected, root_2);
    assert_eq!(
        SmallFieldElement17::ONE,
        SmallFieldElement17::exp(root_2, 2)
    );
}

#[test]
fn test_get_root_of_unity_37() {
    let root_36 = SmallFieldElement37::get_root_of_unity(36);
    assert_eq!(SmallFieldElement37::from(2u32), root_36);

    let powers: Vec<u32> = vec![
        2, 4, 8, 16, 32, 27, 17, 34, 31, 25, 13, 26, 15, 30, 23, 9, 18, 36, 35, 33, 29, 21, 5, 10,
        20, 3, 6, 12, 24, 11, 22, 7, 14, 28, 19, 1,
    ];
    for i in 1..36 {
        assert_eq!(
            SmallFieldElement37::from(powers[i - 1]),
            SmallFieldElement37::exp(root_36, i as u64)
        );
    }

    let root_2 = SmallFieldElement37::get_root_of_unity(2);

    let expected = SmallFieldElement37::exp(root_36, 18);
    assert_eq!(expected, root_2);
    assert_eq!(
        SmallFieldElement37::ONE,
        SmallFieldElement37::exp(root_2, 2)
    );
}

#[test]
fn test_elt_as_bytes_37() {
    let expected = SmallFieldElement37::new(2);

    // should convert correctly
    let source: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(expected, SmallFieldElement37::from(source));
}

#[test]
fn test_array_from_bytes_37() {
    let source: &[SmallFieldElement37; 4] = &[
        SmallFieldElement37::new(1),
        SmallFieldElement37::new(2),
        SmallFieldElement37::new(3),
        SmallFieldElement37::new(4),
    ];

    // should convert correctly
    let expected: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0,
        0, 0,
    ];
    assert_eq!(expected, SmallFieldElement37::elements_as_bytes(source));
}

// HELPER FUNCTIONS
// ================================================================================================

impl<const M: u64, const G: u64, const T: u32> BaseElement<M, G, T> {
    pub fn to_big_uint(&self) -> BigUint {
        BigUint::from_bytes_le(&self.as_bytes())
    }

    pub fn from_big_uint(value: BigUint) -> Self {
        let bytes = value.to_bytes_le();
        let mut buffer = [0u8; 8];
        buffer[0..bytes.len()].copy_from_slice(&bytes);
        BaseElement::try_from(buffer).unwrap()
    }
}
