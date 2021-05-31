// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[test]
fn group_vector_elements() {
    let n = 16;
    let a = (0..n).map(|v| v as u64).collect::<Vec<_>>();

    let b = super::group_vector_elements::<u64, 4>(a.clone());
    for i in 0..b.len() {
        for j in 0..4 {
            assert_eq!(a[i * 4 + j], b[i][j]);
        }
    }

    let b = super::group_vector_elements::<u64, 2>(a.clone());
    for i in 0..b.len() {
        for j in 0..2 {
            assert_eq!(a[i * 2 + j], b[i][j]);
        }
    }
}

#[test]
fn flatten_slice_elements() {
    let a = vec![[1, 2, 3, 4], [5, 6, 7, 8]];

    let b = super::flatten_slice_elements(&a);
    assert_eq!([1, 2, 3, 4, 5, 6, 7, 8], b);
}

#[test]
fn transpose_slice() {
    let n = 8;
    let a = (0..n).map(|v| v as u64).collect::<Vec<_>>();
    let b: Vec<[u64; 2]> = super::transpose_slice(&a);

    assert_eq!([[0, 4], [1, 5], [2, 6], [3, 7]].to_vec(), b);
}
