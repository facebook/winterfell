// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ByteReader, SliceReader};

// VECTOR UTILS TESTS
// ================================================================================================

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

// SLICE READER TESTS
// ================================================================================================

#[test]
fn read_u8() {
    let source = [1u8, 3, 5, 7];
    let mut a = SliceReader::new(&source);

    assert_eq!(1, a.read_u8().unwrap());
    assert_eq!(3, a.read_u8().unwrap());
    assert_eq!(5, a.read_u8().unwrap());
    assert_eq!(7, a.read_u8().unwrap());
    assert!(a.read_u8().is_err());
}

#[test]
fn read_u16() {
    let mut source = 12345u16.to_le_bytes().to_vec();
    source.append(&mut 23456u16.to_le_bytes().to_vec());
    let mut a = SliceReader::new(&source);

    assert_eq!(12345, a.read_u16().unwrap());
    assert_eq!(23456, a.read_u16().unwrap());
    assert!(a.read_u16().is_err());
}

#[test]
fn read_u32() {
    let mut source = 123456789u32.to_le_bytes().to_vec();
    source.append(&mut 2345678910u32.to_le_bytes().to_vec());
    let mut a = SliceReader::new(&source);

    assert_eq!(123456789, a.read_u32().unwrap());
    assert_eq!(2345678910, a.read_u32().unwrap());
    assert!(a.read_u32().is_err());
}

#[test]
fn read_u64() {
    let mut source = 12345678910u64.to_le_bytes().to_vec();
    source.append(&mut 234567891011u64.to_le_bytes().to_vec());
    let mut a = SliceReader::new(&source);

    assert_eq!(12345678910, a.read_u64().unwrap());
    assert_eq!(234567891011, a.read_u64().unwrap());
    assert!(a.read_u64().is_err());
}

#[test]
fn read_u8_vec() {
    let source = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut a = SliceReader::new(&source);

    assert_eq!(vec![1, 2], a.read_u8_vec(2).unwrap());
    assert_eq!(vec![3, 4, 5], a.read_u8_vec(3).unwrap());
    assert_eq!(vec![6, 7], a.read_u8_vec(2).unwrap());
    assert_eq!(vec![8], a.read_u8_vec(1).unwrap());
    assert!(a.read_u8_vec(2).is_err());
}
