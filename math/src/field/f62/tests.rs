// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use num_bigint::BigUint;
use proptest::prelude::*;
use rand_utils::rand_value;

use super::{AsBytes, BaseElement, DeserializationError, FieldElement, Serializable, StarkField};
use crate::field::{CubeExtension, ExtensionOf, QuadExtension};

// MANUAL TESTS
// ================================================================================================

#[test]
fn add() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(r, r + BaseElement::ZERO);

    // test addition within bounds
    assert_eq!(BaseElement::from(5u8), BaseElement::from(2u8) + BaseElement::from(3u8));

    // test overflow
    let t = BaseElement::new(BaseElement::MODULUS - 1);
    assert_eq!(BaseElement::ZERO, t + BaseElement::ONE);
    assert_eq!(BaseElement::ONE, t + BaseElement::from(2u8));
}

#[test]
fn sub() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(r, r - BaseElement::ZERO);

    // test subtraction within bounds
    assert_eq!(BaseElement::from(2u8), BaseElement::from(5u8) - BaseElement::from(3u8));

    // test underflow
    let expected = BaseElement::new(BaseElement::MODULUS - 2);
    assert_eq!(expected, BaseElement::from(3u8) - BaseElement::from(5u8));
}

#[test]
fn mul() {
    // identity
    let r: BaseElement = rand_value();
    assert_eq!(BaseElement::ZERO, r * BaseElement::ZERO);
    assert_eq!(r, r * BaseElement::ONE);

    // test multiplication within bounds
    assert_eq!(BaseElement::from(15u8), BaseElement::from(5u8) * BaseElement::from(3u8));

    // test overflow
    let m = BaseElement::MODULUS;
    let t = BaseElement::new(m - 1);
    assert_eq!(BaseElement::ONE, t * t);
    assert_eq!(BaseElement::new(m - 2), t * BaseElement::from(2u8));
    assert_eq!(BaseElement::new(m - 4), t * BaseElement::from(4u8));

    #[allow(clippy::manual_div_ceil)]
    let t = (m + 1) / 2;
    assert_eq!(BaseElement::ONE, BaseElement::new(t) * BaseElement::from(2u8));
}

#[test]
fn exp() {
    let a = BaseElement::ZERO;
    assert_eq!(a.exp(0), BaseElement::ONE);
    assert_eq!(a.exp(1), BaseElement::ZERO);

    let a = BaseElement::ONE;
    assert_eq!(a.exp(0), BaseElement::ONE);
    assert_eq!(a.exp(1), BaseElement::ONE);
    assert_eq!(a.exp(3), BaseElement::ONE);

    let a: BaseElement = rand_value();
    assert_eq!(a.exp(3), a * a * a);
}

#[test]
fn inv() {
    // identity
    assert_eq!(BaseElement::ONE, BaseElement::inv(BaseElement::ONE));
    assert_eq!(BaseElement::ZERO, BaseElement::inv(BaseElement::ZERO));
}

#[test]
fn element_as_int() {
    let v = u64::MAX;
    let e = BaseElement::new(v);
    assert_eq!(v % super::M, e.as_int());
}

#[test]
fn equals() {
    let a = BaseElement::ONE;
    let b = BaseElement::new(super::M - 1) * BaseElement::new(super::M - 1);

    // elements are equal
    assert_eq!(a, b);
    assert_eq!(a.as_int(), b.as_int());
    assert_eq!(a.to_bytes(), b.to_bytes());

    // but their internal representation is not
    assert_ne!(a.0, b.0);
    assert_ne!(a.as_bytes(), b.as_bytes());
}

// QUADRATIC EXTENSION
// ------------------------------------------------------------------------------------------------

#[test]
fn quad_mul_base() {
    let a = <QuadExtension<BaseElement>>::new(rand_value(), rand_value());
    let b0 = rand_value();
    let b = <QuadExtension<BaseElement>>::new(b0, BaseElement::ZERO);

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

// CUBIC EXTENSION
// ------------------------------------------------------------------------------------------------

#[test]
fn cube_mul() {
    // identity
    let r: CubeExtension<BaseElement> = rand_value();
    assert_eq!(<CubeExtension<BaseElement>>::ZERO, r * <CubeExtension<BaseElement>>::ZERO);
    assert_eq!(r, r * <CubeExtension<BaseElement>>::ONE);

    // test multiplication within bounds
    let a = <CubeExtension<BaseElement>>::new(
        BaseElement::new(15),
        BaseElement::new(22),
        BaseElement::new(8),
    );
    let b = <CubeExtension<BaseElement>>::new(
        BaseElement::new(20),
        BaseElement::new(22),
        BaseElement::new(6),
    );
    let expected = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995532046021),
        BaseElement::new(58),
        BaseElement::new(638),
    );
    assert_eq!(expected, a * b);

    // test multiplication with overflow
    let a = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995532046322),
        BaseElement::new(1390),
        BaseElement::new(4611624995532037737),
    );
    let b = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995532046117),
        BaseElement::new(2305812497766022990),
        BaseElement::new(4611624995532046335),
    );
    let expected = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995528984997),
        BaseElement::new(2305812497762621006),
        BaseElement::new(1609515),
    );
    assert_eq!(expected, a * b);

    let a = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995532046319),
        BaseElement::new(4611624995532045209),
        BaseElement::new(4611624995532030347),
    );
    let b = <CubeExtension<BaseElement>>::new(
        BaseElement::new(4611624995532046117),
        BaseElement::new(200000476),
        BaseElement::new(4611624995077500937),
    );
    let expected = <CubeExtension<BaseElement>>::new(
        BaseElement::new(5370560804040),
        BaseElement::new(4611615826131194009),
        BaseElement::new(4611610241754952409),
    );
    assert_eq!(expected, a * b);
}

#[test]
fn cube_mul_base() {
    let a = <CubeExtension<BaseElement>>::new(rand_value(), rand_value(), rand_value());
    let b0 = rand_value();
    let b = <CubeExtension<BaseElement>>::new(b0, BaseElement::ZERO, BaseElement::ZERO);

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

// ROOTS OF UNITY
// ------------------------------------------------------------------------------------------------

#[test]
fn get_root_of_unity() {
    let root_39 = BaseElement::get_root_of_unity(39);
    assert_eq!(BaseElement::TWO_ADIC_ROOT_OF_UNITY, root_39);
    assert_eq!(BaseElement::ONE, root_39.exp(1u64 << 39));

    let root_38 = BaseElement::get_root_of_unity(38);
    let expected = root_39.exp(2);
    assert_eq!(expected, root_38);
    assert_eq!(BaseElement::ONE, root_38.exp(1u64 << 38));
}

// SERIALIZATION AND DESERIALIZATION
// ------------------------------------------------------------------------------------------------

#[test]
fn try_from_slice() {
    let bytes = vec![1, 0, 0, 0, 0, 0, 0, 0];
    let result = BaseElement::try_from(bytes.as_slice());
    assert!(result.is_ok());
    assert_eq!(1, result.unwrap().as_int());

    let bytes = vec![1, 0, 0, 0, 0, 0, 0];
    let result = BaseElement::try_from(bytes.as_slice());
    assert!(result.is_err());

    let bytes = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = BaseElement::try_from(bytes.as_slice());
    assert!(result.is_err());

    let bytes = vec![255, 255, 255, 255, 255, 255, 255, 255];
    let result = BaseElement::try_from(bytes.as_slice());
    assert!(result.is_err());
}

#[test]
fn elements_as_bytes() {
    let source = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let mut expected = vec![];
    expected.extend_from_slice(&source[0].0.to_le_bytes());
    expected.extend_from_slice(&source[1].0.to_le_bytes());
    expected.extend_from_slice(&source[2].0.to_le_bytes());
    expected.extend_from_slice(&source[3].0.to_le_bytes());

    assert_eq!(expected, BaseElement::elements_as_bytes(&source));
}

#[test]
fn bytes_as_elements() {
    let elements = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let mut bytes = vec![];
    bytes.extend_from_slice(&elements[0].0.to_le_bytes());
    bytes.extend_from_slice(&elements[1].0.to_le_bytes());
    bytes.extend_from_slice(&elements[2].0.to_le_bytes());
    bytes.extend_from_slice(&elements[3].0.to_le_bytes());
    bytes.extend_from_slice(&BaseElement::new(5).0.to_le_bytes());

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[..32]) };
    assert!(result.is_ok());
    assert_eq!(elements, result.unwrap());

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[..33]) };
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));

    let result = unsafe { BaseElement::bytes_as_elements(&bytes[1..33]) };
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

// RANDOMIZED TESTS
// ================================================================================================

proptest! {

    #[test]
    fn add_proptest(a in any::<u64>(), b in any::<u64>()) {
        let v1 = BaseElement::new(a);
        let v2 = BaseElement::new(b);
        let result = v1 + v2;

        let expected = (a % super::M + b % super::M) % super::M;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn sub_proptest(a in any::<u64>(), b in any::<u64>()) {
        let v1 = BaseElement::new(a);
        let v2 = BaseElement::new(b);
        let result = v1 - v2;

        let a = a % super::M;
        let b = b % super::M;
        let expected = if a < b { super::M - b + a } else { a - b };

        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn mul_proptest(a in any::<u64>(), b in any::<u64>()) {
        let v1 = BaseElement::new(a);
        let v2 = BaseElement::new(b);
        let result = v1 * v2;

        let expected = (((a as u128) * (b as u128)) % super::M as u128) as u64;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn exp_proptest(a in any::<u64>(), b in any::<u64>()) {
        let result = BaseElement::new(a).exp(b);

        let b = BigUint::from(b);
        let m = BigUint::from(super::M);
        let expected = BigUint::from(a).modpow(&b, &m).to_u64_digits()[0];
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn inv_proptest(a in any::<u64>()) {
        let a = BaseElement::new(a);
        let b = a.inv();

        let expected = if a == BaseElement::ZERO { BaseElement::ZERO } else { BaseElement::ONE };
        prop_assert_eq!(expected, a * b);
    }

    #[test]
    fn element_as_int_proptest(a in any::<u64>()) {
        let e = BaseElement::new(a);
        prop_assert_eq!(a % super::M, e.as_int());
    }

    // QUADRATIC EXTENSION
    // --------------------------------------------------------------------------------------------
    #[test]
    fn quad_mul_inv_proptest(a0 in any::<u64>(), a1 in any::<u64>()) {
        let a = QuadExtension::<BaseElement>::new(BaseElement::new(a0), BaseElement::new(a1));
        let b = a.inv();

        let expected = if a == QuadExtension::<BaseElement>::ZERO {
            QuadExtension::<BaseElement>::ZERO
        } else {
            QuadExtension::<BaseElement>::ONE
        };
        prop_assert_eq!(expected, a * b);
    }

    // CUBIC EXTENSION
    // --------------------------------------------------------------------------------------------
    #[test]
    fn cube_mul_inv_proptest(a0 in any::<u64>(), a1 in any::<u64>(), a2 in any::<u64>()) {
        let a = CubeExtension::<BaseElement>::new(BaseElement::new(a0), BaseElement::new(a1), BaseElement::new(a2));
        let b = a.inv();

        let expected = if a == CubeExtension::<BaseElement>::ZERO {
            CubeExtension::<BaseElement>::ZERO
        } else {
            CubeExtension::<BaseElement>::ONE
        };
        prop_assert_eq!(expected, a * b);
    }
}
