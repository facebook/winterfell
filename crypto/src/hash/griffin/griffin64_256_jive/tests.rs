// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, ElementDigest, ElementHasher, FieldElement, GriffinJive64_256, Hasher, StarkField,
    INV_MDS, MDS, STATE_WIDTH,
};
use core::convert::TryInto;
use proptest::prelude::*;

use rand_utils::{rand_array, rand_value};

#[allow(clippy::needless_range_loop)]
#[test]
fn mds_inv_test() {
    let mut mul_result = [[BaseElement::new(0); STATE_WIDTH]; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            let result = {
                let mut result = BaseElement::new(0);
                for k in 0..STATE_WIDTH {
                    result += MDS[i][k] * INV_MDS[k][j]
                }
                result
            };
            mul_result[i][j] = result;
            if i == j {
                assert_eq!(result, BaseElement::new(1));
            } else {
                assert_eq!(result, BaseElement::new(0));
            }
        }
    }
}

#[test]
fn test_pow_d() {
    let mut e: BaseElement = rand_value();
    let e_copy = e;
    let e_exp = e.exp(7);
    super::pow_d(&mut e);
    assert_eq!(e, e_exp);
    super::pow_inv_d(&mut e);
    assert_eq!(e, e_copy);
}

#[test]
fn apply_permutation() {
    let mut state: [BaseElement; STATE_WIDTH] = [
        BaseElement::new(0),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
    ];

    GriffinJive64_256::apply_permutation(&mut state);

    // expected values are obtained by executing sage implementation code
    // available at https://github.com/Nashtare/griffin-hash
    let expected = vec![
        BaseElement::new(5100889723013202324),
        BaseElement::new(6905683344086677437),
        BaseElement::new(8236358786066512460),
        BaseElement::new(1729367862961866374),
        BaseElement::new(11501420603552582981),
        BaseElement::new(15040992847148175954),
        BaseElement::new(10400407304634768298),
        BaseElement::new(1197713229800045418),
    ];

    assert_eq!(expected, state);
}

#[test]
fn hash() {
    let state: [BaseElement; STATE_WIDTH] = [
        BaseElement::new(0),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
    ];

    let result = GriffinJive64_256::hash_elements(&state);

    // expected values are obtained by executing sage implementation code
    // available at https://github.com/Nashtare/griffin-hash
    let expected = vec![
        BaseElement::new(16887612651479285699),
        BaseElement::new(16469590207124000227),
        BaseElement::new(11134472952466778260),
        BaseElement::new(15455301814830509354),
    ];

    assert_eq!(expected, result.as_elements());
}

#[test]
fn hash_elements_vs_merge() {
    let elements: [BaseElement; 8] = rand_array();

    let digests: [ElementDigest; 2] = [
        ElementDigest::new(elements[..4].try_into().unwrap()),
        ElementDigest::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = GriffinJive64_256::merge(&digests);
    let h_result = GriffinJive64_256::hash_elements(&elements);

    // Because we use the Jive compression mode, `merge` and
    // `hash_elements` methods are incompatible.
    assert_ne!(m_result, h_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let seed = ElementDigest::new(rand_array());

    // ----- value fits into a field element ------------------------------------------------------
    let val: BaseElement = rand_value();
    let m_result = GriffinJive64_256::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = GriffinJive64_256::hash_elements(&elements);

    // Because we use the Jive compression mode, `merge` and
    // `hash_elements` methods are incompatible.
    assert_ne!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = BaseElement::MODULUS + 2;
    let m_result = GriffinJive64_256::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(BaseElement::new(val));
    elements.push(BaseElement::new(1));
    let h_result = GriffinJive64_256::hash_elements(&elements);

    // Because we use the Jive compression mode, `merge` and
    // `hash_elements` methods are incompatible.
    assert_ne!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = GriffinJive64_256::hash(&[1_u8, 2, 3]);
    let r2 = GriffinJive64_256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = GriffinJive64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1: [BaseElement; 2] = rand_array();
    let e2 = [e1[0], e1[1], BaseElement::ZERO];

    let r1 = GriffinJive64_256::hash_elements(&e1);
    let r2 = GriffinJive64_256::hash_elements(&e2);
    assert_ne!(r1, r2);
}

#[inline(always)]
fn apply_mds_naive(state: &mut [BaseElement; STATE_WIDTH]) {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];
    result.iter_mut().zip(MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += m * s;
        });
    });
    *state = result;
}

proptest! {
    #[test]
    fn mds_freq_proptest(a in any::<[u64; STATE_WIDTH]>()) {

        let mut v1 = [BaseElement::ZERO; STATE_WIDTH];
        let mut v2;

        for i in 0..STATE_WIDTH {
            v1[i] = BaseElement::new(a[i]);
        }
        v2 = v1;

        apply_mds_naive(&mut v1);
        GriffinJive64_256::apply_linear(&mut v2);

        prop_assert_eq!(v1, v2);
    }
}
