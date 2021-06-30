// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::collections::HashSet;

use crate::{hash::Blake3_256, Hasher};
use math::fields::f128::BaseElement;

#[test]
fn draw_elements() {
    let mut coin = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);

    // should draw different elements each time
    let e1 = coin.draw::<BaseElement>();
    let e2 = coin.draw::<BaseElement>();
    assert_ne!(e1, e2);

    let e3 = coin.draw::<BaseElement>();
    assert_ne!(e1, e3);
    assert_ne!(e2, e3);

    // should draw different elements based on seed
    let mut coin1 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);
    let mut coin2 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[2, 3, 4, 5]);
    let e1 = coin1.draw::<BaseElement>();
    let e2 = coin2.draw::<BaseElement>();
    assert_ne!(e1, e2);
}

#[test]
fn reseed() {
    let mut coin1 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);
    let mut coin2 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);

    // should draw the same element form both coins
    let e1 = coin1.draw::<BaseElement>();
    let e2 = coin2.draw::<BaseElement>();
    assert_eq!(e1, e2);

    // after reseeding should draw different elements
    coin2.reseed(Blake3_256::hash(&[2, 3, 4, 5]));
    let e1 = coin1.draw::<BaseElement>();
    let e2 = coin2.draw::<BaseElement>();
    assert_ne!(e1, e2);

    // same as above but for reseed_with_int()

    let mut coin1 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);
    let mut coin2 = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);

    // after reseeding should draw different elements
    coin2.reseed_with_int(42);
    let e1 = coin1.draw::<BaseElement>();
    let e2 = coin2.draw::<BaseElement>();
    assert_ne!(e1, e2);
}

#[test]
fn leading_zeros() {
    let mut coin = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);

    let mut value = 0;
    while coin.check_leading_zeros(value) < 2 {
        value += 1;
    }

    coin.reseed_with_int(value);
    assert!(coin.leading_zeros() >= 2);
}

#[test]
fn draw_integers() {
    let mut coin = super::PublicCoin::<BaseElement, Blake3_256>::new(&[1, 2, 3, 4]);

    let num_values = 20;
    let domain_size = 64;
    let values = coin.draw_integers(num_values, domain_size);

    assert_eq!(num_values, values.len());

    let mut value_set = HashSet::new();
    for value in values {
        assert!(value < domain_size);
        assert!(value_set.insert(value));
    }
}
