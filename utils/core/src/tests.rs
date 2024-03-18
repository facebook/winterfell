// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ByteReader, ByteWriter, Serializable, SliceReader};
use alloc::vec::Vec;
use proptest::prelude::{any, proptest};

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

    assert_eq!(vec![1, 2], a.read_vec(2).unwrap());
    assert_eq!(vec![3, 4, 5], a.read_vec(3).unwrap());
    assert_eq!(vec![6, 7], a.read_vec(2).unwrap());
    assert_eq!(vec![8], a.read_vec(1).unwrap());
    assert!(a.read_vec(2).is_err());
}

// SERIALIZATION TESTS
// ================================================================================================

#[test]
fn write_serializable() {
    let mut target: Vec<u8> = Vec::new();

    123456u128.write_into(&mut target);
    assert_eq!(16, target.len());

    target.write(234567u128);
    assert_eq!(32, target.len());

    let mut reader = SliceReader::new(&target);
    assert_eq!(123456u128, reader.read_u128().unwrap());
    assert_eq!(234567u128, reader.read_u128().unwrap());
}

#[test]
fn write_serializable_usize() {
    let mut target: Vec<u8> = Vec::new();

    target.write(0usize);
    assert_eq!(1, target.len());
    target.write(1usize);
    assert_eq!(2, target.len());
    target.write(255usize);
    assert_eq!(4, target.len());
    target.write(234567usize);
    assert_eq!(7, target.len());
    target.write(usize::MAX);
    assert_eq!(16, target.len());

    let mut reader = SliceReader::new(&target);
    assert_eq!(0usize, reader.read_usize().unwrap());
    assert_eq!(1usize, reader.read_usize().unwrap());
    assert_eq!(255usize, reader.read_usize().unwrap());
    assert_eq!(234567usize, reader.read_usize().unwrap());
    assert_eq!(usize::MAX, reader.read_usize().unwrap());
}

#[test]
fn write_serializable_batch() {
    let mut target: Vec<u8> = Vec::new();

    let batch1 = vec![1u128, 2, 3, 4];
    target.write_many(&batch1);
    assert_eq!(64, target.len());

    let batch2 = [5u128, 6, 7, 8];
    target.write_many(batch2);
    assert_eq!(128, target.len());

    let mut reader = SliceReader::new(&target);
    for i in 1u128..9 {
        assert_eq!(i, reader.read_u128().unwrap());
    }
}

#[test]
fn write_serializable_array_batch() {
    let mut target: Vec<u8> = Vec::new();

    let batch1 = vec![[1u128, 2], [3, 4]];
    target.write_many(&batch1);
    assert_eq!(64, target.len());

    let batch2 = [[5u128, 6], [7, 8]];
    target.write_many(batch2);
    assert_eq!(128, target.len());

    let mut reader = SliceReader::new(&target);
    for i in 1u128..9 {
        assert_eq!(i, reader.read_u128().unwrap());
    }
}

// UTILS - RANDOMIZED - UINT SERIALIZATION AND DESERIALIZATION
// ================================================================================================
proptest! {
    #[test]
    fn usize_proptest(a in any::<usize>()) {
        let mut target: Vec<u8> = Vec::new();
        target.write(a);

        let mut reader = SliceReader::new(&target);
        assert_eq!(a, reader.read_usize().unwrap());
    }
}
