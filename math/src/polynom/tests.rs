// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use super::remove_leading_zeros;
use crate::{
    field::{f128::BaseElement, FieldElement, StarkField},
    utils::get_power_series,
};

#[test]
fn eval() {
    let x = BaseElement::new(11269864713250585702u128);
    let poly: [BaseElement; 4] = [
        BaseElement::new(384863712573444386u128),
        BaseElement::new(7682273369345308472u128),
        BaseElement::new(13294661765012277990u128),
        BaseElement::new(16234810094004944758u128),
    ];

    assert_eq!(BaseElement::ZERO, super::eval(&poly[..0], x));

    // constant
    assert_eq!(poly[0], super::eval(&poly[..1], x));

    // degree 1
    assert_eq!(poly[0] + poly[1] * x, super::eval(&poly[..2], x));

    // degree 2
    let x2 = x.exp(2);
    assert_eq!(poly[0] + poly[1] * x + poly[2] * x2, super::eval(&poly[..3], x));

    // degree 3
    let x3 = x.exp(3);
    assert_eq!(poly[0] + poly[1] * x + poly[2] * x2 + poly[3] * x3, super::eval(&poly, x));
}

#[test]
fn add() {
    let poly1: [BaseElement; 3] = [
        BaseElement::new(384863712573444386u128),
        BaseElement::new(7682273369345308472u128),
        BaseElement::new(13294661765012277990u128),
    ];
    let poly2: [BaseElement; 3] = [
        BaseElement::new(9918505539874556741u128),
        BaseElement::new(16401861429499852246u128),
        BaseElement::new(12181445947541805654u128),
    ];

    // same degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly1[2] + poly2[2]];
    assert_eq!(pr, super::add(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly2[2]];
    assert_eq!(pr, super::add(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly1[2]];
    assert_eq!(pr, super::add(&poly1, &poly2[..2]));
}

#[test]
fn sub() {
    let poly1: [BaseElement; 3] = [
        BaseElement::new(384863712573444386u128),
        BaseElement::new(7682273369345308472u128),
        BaseElement::new(13294661765012277990u128),
    ];
    let poly2: [BaseElement; 3] = [
        BaseElement::new(9918505539874556741u128),
        BaseElement::new(16401861429499852246u128),
        BaseElement::new(12181445947541805654u128),
    ];

    // same degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], poly1[2] - poly2[2]];
    assert_eq!(pr, super::sub(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], -poly2[2]];
    assert_eq!(pr, super::sub(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], poly1[2]];
    assert_eq!(pr, super::sub(&poly1, &poly2[..2]));
}

#[test]
fn mul() {
    let poly1: [BaseElement; 3] = [
        BaseElement::new(384863712573444386u128),
        BaseElement::new(7682273369345308472u128),
        BaseElement::new(13294661765012277990u128),
    ];
    let poly2: [BaseElement; 3] = [
        BaseElement::new(9918505539874556741u128),
        BaseElement::new(16401861429499852246u128),
        BaseElement::new(12181445947541805654u128),
    ];

    // same degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[1] * poly2[1] + poly1[2] * poly2[0] + poly2[2] * poly1[0],
        poly1[2] * poly2[1] + poly2[2] * poly1[1],
        poly1[2] * poly2[2],
    ];
    assert_eq!(pr, super::mul(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[0] * poly2[2] + poly2[1] * poly1[1],
        poly1[1] * poly2[2],
    ];
    assert_eq!(pr, super::mul(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[2] * poly2[0] + poly2[1] * poly1[1],
        poly1[2] * poly2[1],
    ];
    assert_eq!(pr, super::mul(&poly1, &poly2[..2]));
}

#[test]
fn div() {
    let poly1 = vec![
        BaseElement::new(384863712573444386u128),
        BaseElement::new(7682273369345308472u128),
        BaseElement::new(13294661765012277990u128),
    ];
    let poly2 = vec![
        BaseElement::new(9918505539874556741u128),
        BaseElement::new(16401861429499852246u128),
        BaseElement::new(12181445947541805654u128),
    ];

    // divide degree 4 by degree 2
    let poly3 = super::mul(&poly1, &poly2);
    assert_eq!(poly1, super::div(&poly3, &poly2));

    // divide degree 3 by degree 2
    let poly3 = super::mul(&poly1[..2], &poly2);
    assert_eq!(poly1[..2].to_vec(), super::div(&poly3, &poly2));

    // divide degree 3 by degree 3
    let poly3 = super::mul_by_scalar(&poly1, BaseElement::new(11269864713250585702u128));
    assert_eq!(vec![BaseElement::new(11269864713250585702u128)], super::div(&poly3, &poly1));
}

#[test]
fn syn_div() {
    // ----- division by degree 1 polynomial ------------------------------------------------------

    // poly = (x + 2) * (x + 3)
    let poly = super::mul(
        &[BaseElement::from(2u8), BaseElement::ONE],
        &[BaseElement::from(3u8), BaseElement::ONE],
    );

    // divide by (x + 3), this divides evenly
    let result = super::syn_div(&poly, 1, -BaseElement::from(3u8));
    let expected = vec![BaseElement::from(2u8), BaseElement::ONE];
    assert_eq!(expected, remove_leading_zeros(&result));

    // poly = x^3 - 12x^2 - 42
    let poly = [
        -BaseElement::from(42u8),
        BaseElement::ZERO,
        -BaseElement::from(12u8),
        BaseElement::ONE,
    ];

    // divide by (x - 3), this does not divide evenly, but the remainder is ignored
    let result = super::syn_div(&poly, 1, BaseElement::from(3u8));
    let expected = vec![-BaseElement::from(27u8), -BaseElement::from(9u8), BaseElement::ONE];
    assert_eq!(expected, remove_leading_zeros(&result));

    // ----- division by high-degree polynomial ---------------------------------------------------

    // evaluations of a polynomial which evaluates to 0 at steps: 0, 4, 8, 12
    let ys: Vec<BaseElement> = vec![0u8, 1, 2, 3, 0, 5, 6, 7, 0, 9, 10, 11, 0, 13, 14, 15]
        .into_iter()
        .map(BaseElement::from)
        .collect();

    // build the domain
    let root = BaseElement::get_root_of_unity(ys.len().ilog2());
    let domain = get_power_series(root, ys.len());

    // build the polynomial
    let poly = super::interpolate(&domain, &ys, false);

    // build the divisor polynomial: (x^4 - 1)
    let z_poly = vec![
        -BaseElement::ONE,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ONE,
    ];

    let result = super::syn_div(&poly, 4, BaseElement::ONE);
    assert_eq!(poly, remove_leading_zeros(&super::mul(&result, &z_poly)));

    // ----- division by high-degree polynomial with non-unary constant ---------------------------

    // evaluations of a polynomial which evaluates to 0 at steps: 1, 5, 9, 13
    let ys: Vec<BaseElement> = vec![18u8, 0, 2, 3, 4, 0, 6, 7, 8, 0, 10, 11, 12, 0, 14, 15]
        .into_iter()
        .map(BaseElement::from)
        .collect();

    // build the polynomial
    let poly = super::interpolate(&domain, &ys, false);

    // build the divisor polynomial: (x^4 - g^4)
    let z_poly = vec![
        -root.exp(4),
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ONE,
    ];

    let result = super::syn_div(&poly, 4, root.exp(4));
    assert_eq!(poly, remove_leading_zeros(&super::mul(&result, &z_poly)));
}
