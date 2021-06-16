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

// DESERIALIZATION TESTS
// ================================================================================================

#[test]
fn read_u8() {
    let a = [1u8, 3, 5, 7];

    let mut pos = 0;
    assert_eq!(1, super::read_u8(&a, &mut pos).unwrap());
    assert_eq!(1, pos);

    pos += 1;
    assert_eq!(5, super::read_u8(&a, &mut pos).unwrap());
    assert_eq!(3, pos);

    pos = 4;
    assert!(super::read_u8(&a, &mut pos).is_err());
}

#[test]
fn read_u16() {
    let mut a = 12345u16.to_le_bytes().to_vec();
    a.append(&mut 23456u16.to_le_bytes().to_vec());

    let mut pos = 0;
    assert_eq!(12345, super::read_u16(&a, &mut pos).unwrap());
    assert_eq!(2, pos);

    assert_eq!(23456, super::read_u16(&a, &mut pos).unwrap());
    assert_eq!(4, pos);

    pos = 3;
    assert!(super::read_u16(&a, &mut pos).is_err());
}

#[test]
fn read_u32() {
    let mut a = 123456789u32.to_le_bytes().to_vec();
    a.append(&mut 2345678910u32.to_le_bytes().to_vec());

    let mut pos = 0;
    assert_eq!(123456789, super::read_u32(&a, &mut pos).unwrap());
    assert_eq!(4, pos);

    assert_eq!(2345678910, super::read_u32(&a, &mut pos).unwrap());
    assert_eq!(8, pos);

    pos = 6;
    assert!(super::read_u32(&a, &mut pos).is_err());
}

#[test]
fn read_u8_vec() {
    let a = [1u8, 2, 3, 4, 5, 6, 7, 8];

    let mut pos = 0;
    assert_eq!(vec![1, 2], super::read_u8_vec(&a, &mut pos, 2).unwrap());
    assert_eq!(2, pos);

    assert_eq!(vec![3, 4, 5], super::read_u8_vec(&a, &mut pos, 3).unwrap());
    assert_eq!(5, pos);

    assert_eq!(vec![6, 7], super::read_u8_vec(&a, &mut pos, 2).unwrap());
    assert_eq!(7, pos);

    assert_eq!(vec![8], super::read_u8_vec(&a, &mut pos, 1).unwrap());

    pos = 7;
    assert!(super::read_u8_vec(&a, &mut pos, 2).is_err());
}
