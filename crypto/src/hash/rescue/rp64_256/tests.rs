// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, ElementDigest, ElementHasher, FieldElement, Hasher, Rp64_256, StarkField, ALPHA,
    INV_ALPHA, INV_MDS, MDS, STATE_WIDTH,
};
use core::convert::TryInto;
use proptest::prelude::*;

use rand_utils::{rand_array, rand_value};

#[test]
fn mds_inv_test() {
    let mut mul_result = [[BaseElement::new(0); STATE_WIDTH]; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            let result = {
                let mut result = BaseElement::new(0);
                #[allow(clippy::needless_range_loop)]
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
fn test_alphas() {
    let e: BaseElement = rand_value();
    let e_exp = e.exp(ALPHA);
    assert_eq!(e, e_exp.exp(INV_ALPHA));
}

#[test]
fn test_sbox() {
    let state: [BaseElement; STATE_WIDTH] = rand_array();

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(ALPHA));

    let mut actual = state;
    Rp64_256::apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state: [BaseElement; STATE_WIDTH] = rand_array();

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

    let mut actual = state;
    Rp64_256::apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
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
        BaseElement::new(8),
        BaseElement::new(9),
        BaseElement::new(10),
        BaseElement::new(11),
    ];

    Rp64_256::apply_permutation(&mut state);

    // expected values are obtained by executing sage reference implementation code
    let expected = vec![
        BaseElement::new(11084501481526603421),
        BaseElement::new(6291559951628160880),
        BaseElement::new(13626645864671311919),
        BaseElement::new(18397438323058963117),
        BaseElement::new(7443014167353970324),
        BaseElement::new(17930833023906771425),
        BaseElement::new(4275355080008025761),
        BaseElement::new(7676681476902901785),
        BaseElement::new(3460534574143792217),
        BaseElement::new(11912731278641497187),
        BaseElement::new(8104899243369883110),
        BaseElement::new(674509706691634438),
    ];

    assert_eq!(expected, state);
}

#[test]
fn hash_elements_vs_merge() {
    let elements: [BaseElement; 8] = rand_array();

    let digests: [ElementDigest; 2] = [
        ElementDigest::new(elements[..4].try_into().unwrap()),
        ElementDigest::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rp64_256::merge(&digests);
    let h_result = Rp64_256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let seed = ElementDigest::new(rand_array());

    // ----- value fits into a field element ------------------------------------------------------
    let val: BaseElement = rand_value();
    let m_result = Rp64_256::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rp64_256::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = BaseElement::MODULUS + 2;
    let m_result = Rp64_256::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(BaseElement::new(val));
    elements.push(BaseElement::new(1));
    let h_result = Rp64_256::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rp64_256::hash(&[1_u8, 2, 3]);
    let r2 = Rp64_256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rp64_256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1: [BaseElement; 2] = rand_array();
    let e2 = [e1[0], e1[1], BaseElement::ZERO];

    let r1 = Rp64_256::hash_elements(&e1);
    let r2 = Rp64_256::hash_elements(&e2);
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
    fn mds_freq_proptest(a in any::<[u64;STATE_WIDTH]>()) {

        let mut v1 = [BaseElement::ZERO;STATE_WIDTH];
        let mut v2;

        for i in 0..STATE_WIDTH {
            v1[i] = BaseElement::new(a[i]);
        }
        v2 = v1;

        apply_mds_naive(&mut v1);
        Rp64_256::apply_mds(&mut v2);

        prop_assert_eq!(v1, v2);
    }
}
