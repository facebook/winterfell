// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Blake3_256, ElementHasher, Hasher};
use math::{fields::f62::BaseElement, FieldElement};
use rand_utils::rand_array;

#[test]
fn hash_padding() {
    let b1 = [1_u8, 2, 3];
    let b2 = [1_u8, 2, 3, 0];

    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Blake3_256::<BaseElement>::hash(&b1);
    let r2 = Blake3_256::<BaseElement>::hash(&b2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1: [BaseElement; 2] = rand_array();
    let e2 = [e1[0], e1[1], BaseElement::ZERO];

    // adding a zero element at the end of a list of elements should result in a different hash
    let r1 = Blake3_256::hash_elements(&e1);
    let r2 = Blake3_256::hash_elements(&e2);
    assert_ne!(r1, r2);
}
