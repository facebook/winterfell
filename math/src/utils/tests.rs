// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::SerializationError;
use crate::field::{f128::BaseElement, FieldElement};

// MATH FUNCTIONS
// ================================================================================================

#[test]
fn get_power_series_with_offset() {
    let n = 1024 * 4; // big enough for concurrent series generation
    let b = BaseElement::from(3u8);
    let s = BaseElement::from(7u8);

    let expected = (0..n)
        .map(|p| s * b.exp((p as u64).into()))
        .collect::<Vec<_>>();

    let actual = super::get_power_series_with_offset(b, s, n);
    assert_eq!(expected, actual);
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
