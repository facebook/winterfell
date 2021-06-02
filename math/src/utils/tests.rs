// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::SerializationError;
use crate::field::{f128::BaseElement, FieldElement};

// MATH FUNCTIONS
// ================================================================================================

#[test]
fn get_power_series() {
    let n = 1024 * 4; // big enough for concurrent series generation
    let b = BaseElement::from(3u8);

    let mut expected = vec![BaseElement::ZERO; n];
    for (i, value) in expected.iter_mut().enumerate() {
        *value = b.exp((i as u64).into());
    }

    let actual = super::get_power_series(b, n);
    assert_eq!(expected, actual);
}

#[test]
fn get_power_series_with_offset() {
    let n = 1024 * 4; // big enough for concurrent series generation
    let b = BaseElement::from(3u8);
    let s = BaseElement::from(7u8);

    let mut expected = vec![BaseElement::ZERO; n];
    for (i, value) in expected.iter_mut().enumerate() {
        *value = s * b.exp((i as u64).into());
    }

    let actual = super::get_power_series_with_offset(b, s, n);
    assert_eq!(expected, actual);
}

#[test]
fn add_in_place() {
    let n = 1024 * 4; // big enough for concurrent series generation
    let a = BaseElement::prng_vector([0; 32], n);
    let b = BaseElement::prng_vector([1; 32], n);

    let mut c = a.clone();
    super::add_in_place(&mut c, &b);

    for ((a, b), c) in a.into_iter().zip(b).zip(c) {
        assert_eq!(a + b, c);
    }
}

#[test]
fn mul_acc() {
    let n = 1024 * 4; // big enough for concurrent series generation
    let a = BaseElement::prng_vector([0; 32], n);
    let b = BaseElement::prng_vector([1; 32], n);
    let c = BaseElement::rand();

    let mut d = a.clone();
    super::mul_acc(&mut d, &b, c);

    for ((a, b), d) in a.into_iter().zip(b).zip(d) {
        assert_eq!(a + b * c, d);
    }
}

#[test]
fn batch_inversion() {
    let n = 1024 * 4; // big enough for concurrent inversion
    let a = BaseElement::prng_vector([1; 32], n);

    let b = super::batch_inversion(&a);
    for (&a, &b) in a.iter().zip(b.iter()) {
        assert_eq!(a.inv(), b);
    }
}

#[test]
fn log2() {
    assert_eq!(super::log2(1), 0);
    assert_eq!(super::log2(16), 4);
    assert_eq!(super::log2(1 << 20), 20);
    assert_eq!(super::log2(2usize.pow(20)), 20);
}

// VECTOR FUNCTIONS
// ================================================================================================

#[test]
fn uninit_vector() {
    let result = super::uninit_vector::<BaseElement>(16);
    assert_eq!(16, result.len());
    assert_eq!(16, result.capacity());
}

#[test]
fn remove_leading_zeros() {
    let a = vec![1u128, 2, 3, 4, 5, 6, 0, 0]
        .into_iter()
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    let b = super::remove_leading_zeros(&a);
    assert_eq!(6, b.len());
    assert_eq!(a[..6], b);

    let a = vec![0u128, 0, 0, 0]
        .into_iter()
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    let b = super::remove_leading_zeros(&a);
    assert_eq!(0, b.len());
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

#[test]
fn read_elements_into() {
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

    let mut elements = vec![BaseElement::ZERO; 4];

    // fill whole target
    let result = super::read_elements_into(&bytes[..64], &mut elements);
    assert!(result.is_ok());
    assert_eq!(4, result.unwrap());
    assert_eq!(expected, elements);

    // read only 2 elements
    elements.fill(BaseElement::ZERO); // clear the elements first
    let result = super::read_elements_into(&bytes[..32], &mut elements);
    assert!(result.is_ok());
    assert_eq!(2, result.unwrap());
    assert_eq!(expected[..2], elements[..2]);
    assert_eq!(BaseElement::ZERO, elements[2]);
    assert_eq!(BaseElement::ZERO, elements[3]);

    // partial number of elements
    let result = super::read_elements_into(&bytes[..65], &mut elements);
    assert_eq!(
        result,
        Err(SerializationError::NotEnoughBytesForWholeElements(65))
    );

    // destination too small
    let result = super::read_elements_into(&bytes, &mut elements);
    assert_eq!(result, Err(SerializationError::DestinationTooSmall(5, 4)));

    // invalid element
    let result = super::read_elements_into(&bytes[16..], &mut elements);
    assert_eq!(result, Err(SerializationError::FailedToReadElement(48)));
}

#[test]
fn read_elements_into_vec() {
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
    let result = super::read_elements_into_vec(&bytes[..64]);
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());

    // partial number of elements
    let result = super::read_elements_into_vec::<BaseElement>(&bytes[..65]);
    assert_eq!(
        result,
        Err(SerializationError::NotEnoughBytesForWholeElements(65))
    );

    // invalid element
    let result = super::read_elements_into_vec::<BaseElement>(&bytes[16..]);
    assert_eq!(result, Err(SerializationError::FailedToReadElement(48)));
}
