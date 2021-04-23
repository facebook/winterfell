// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::{
    field::{f128::BaseElement, FieldElement, StarkField},
    polynom,
    utils::get_power_series,
};

#[test]
fn eval() {
    let x = BaseElement::from(11269864713250585702u128);
    let poly: [BaseElement; 4] = [
        BaseElement::from(384863712573444386u128),
        BaseElement::from(7682273369345308472u128),
        BaseElement::from(13294661765012277990u128),
        BaseElement::from(16234810094004944758u128),
    ];
    assert_eq!(polynom::eval(&poly, x), super::eval(&poly, x));
}

#[test]
fn interpolate_batch() {
    let r = BaseElement::get_root_of_unity(4);
    let xs = super::to_quartic_vec(get_power_series(r, 16));
    let ys = super::to_quartic_vec(
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
            .into_iter()
            .map(BaseElement::from)
            .collect(),
    );

    let mut expected: Vec<[BaseElement; 4]> = vec![];
    for i in 0..xs.len() {
        let mut row = [BaseElement::ZERO; 4];
        row.copy_from_slice(&polynom::interpolate(&xs[i], &ys[i], false));
        expected.push(row);
    }

    assert_eq!(expected, super::interpolate_batch(&xs, &ys));
}

#[test]
fn evaluate_batch() {
    let x = BaseElement::rand();
    let polys: [[BaseElement; 4]; 4] = [
        [
            BaseElement::from(7956382178997078105u128),
            BaseElement::from(6172178935026293282u128),
            BaseElement::from(5971474637801684060u128),
            BaseElement::from(16793452009046991148u128),
        ],
        [
            BaseElement::from(7956382178997078109u128),
            BaseElement::from(15205743380705406848u128),
            BaseElement::from(12475269242634339237u128),
            BaseElement::from(194846859619262948u128),
        ],
        [
            BaseElement::from(7956382178997078113u128),
            BaseElement::from(12274564945409730015u128),
            BaseElement::from(5971474637801684060u128),
            BaseElement::from(1653291871389032149u128),
        ],
        [
            BaseElement::from(7956382178997078117u128),
            BaseElement::from(3241000499730616449u128),
            BaseElement::from(12475269242634339237u128),
            BaseElement::from(18251897020816760349u128),
        ],
    ];

    let expected = vec![
        polynom::eval(&polys[0], x),
        polynom::eval(&polys[1], x),
        polynom::eval(&polys[2], x),
        polynom::eval(&polys[3], x),
    ];
    assert_eq!(expected, super::evaluate_batch(&polys, x));
}

#[test]
fn to_quartic_vec() {
    let vector: Vec<BaseElement> = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        .into_iter()
        .map(BaseElement::from)
        .collect();
    let expected: Vec<[BaseElement; 4]> = vec![
        [
            BaseElement::from(1u8),
            BaseElement::from(2u8),
            BaseElement::from(3u8),
            BaseElement::from(4u8),
        ],
        [
            BaseElement::from(5u8),
            BaseElement::from(6u8),
            BaseElement::from(7u8),
            BaseElement::from(8u8),
        ],
        [
            BaseElement::from(9u8),
            BaseElement::from(10u8),
            BaseElement::from(11u8),
            BaseElement::from(12u8),
        ],
        [
            BaseElement::from(13u8),
            BaseElement::from(14u8),
            BaseElement::from(15u8),
            BaseElement::from(16u8),
        ],
    ];
    assert_eq!(expected, super::to_quartic_vec(vector));
}

#[test]
fn transpose() {
    let vector: Vec<BaseElement> = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        .into_iter()
        .map(BaseElement::from)
        .collect();
    let expected: Vec<[BaseElement; 4]> = vec![
        [
            BaseElement::from(1u8),
            BaseElement::from(5u8),
            BaseElement::from(9u8),
            BaseElement::from(13u8),
        ],
        [
            BaseElement::from(2u8),
            BaseElement::from(6u8),
            BaseElement::from(10u8),
            BaseElement::from(14u8),
        ],
        [
            BaseElement::from(3u8),
            BaseElement::from(7u8),
            BaseElement::from(11u8),
            BaseElement::from(15u8),
        ],
        [
            BaseElement::from(4u8),
            BaseElement::from(8u8),
            BaseElement::from(12u8),
            BaseElement::from(16u8),
        ],
    ];
    assert_eq!(expected, super::transpose(&vector, 1));

    let expected: Vec<[BaseElement; 4]> = vec![
        [
            BaseElement::from(1u8),
            BaseElement::from(5u8),
            BaseElement::from(9u8),
            BaseElement::from(13u8),
        ],
        [
            BaseElement::from(3u8),
            BaseElement::from(7u8),
            BaseElement::from(11u8),
            BaseElement::from(15u8),
        ],
    ];
    assert_eq!(expected, super::transpose(&vector, 2));
}
