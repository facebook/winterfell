// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use proptest::prelude::{any, proptest};

use super::{ByteReader, ByteWriter, Serializable, SliceReader};

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

// SIZE HINT
// ================================================================================================

fn size_hint_matches_serialized_len<S: Serializable>(value: S) {
    let mut target = Vec::new();
    let size_hint = value.get_size_hint();
    target.write(value);
    assert_eq!(target.len(), size_hint);
}

fn size_hint_matches_serialized_len_unsized<S: Serializable + ?Sized>(value: &S) {
    let mut target = Vec::new();
    let size_hint = value.get_size_hint();
    value.write_into(&mut target);
    assert_eq!(target.len(), size_hint);
}

#[test]
fn size_hint_primitive_integers() {
    size_hint_matches_serialized_len(0u8);
    size_hint_matches_serialized_len(0u16);
    size_hint_matches_serialized_len(0u32);
    size_hint_matches_serialized_len(0u64);
    size_hint_matches_serialized_len(0u128);
    size_hint_matches_serialized_len(0usize);
    size_hint_matches_serialized_len(u32::MAX as usize);
    size_hint_matches_serialized_len(u64::MAX as usize);
}

#[test]
fn size_hint_tuples() {
    size_hint_matches_serialized_len((0u8,));
    size_hint_matches_serialized_len((0u8, 0u16));
    size_hint_matches_serialized_len((0u8, 0u16, 200u32));
    size_hint_matches_serialized_len((0u8, 0u16, 200u32, 300u64));
    size_hint_matches_serialized_len((0u8, 0u16, 200u32, 300u64));
}

#[test]
fn size_hint_arrays_and_slices() {
    size_hint_matches_serialized_len::<[u8; 0]>([]);
    size_hint_matches_serialized_len([3u8; 1]);
    size_hint_matches_serialized_len([50u32; 5]);

    size_hint_matches_serialized_len_unsized::<[u8]>(&[]);
    size_hint_matches_serialized_len_unsized::<[u8]>(&[0]);
    size_hint_matches_serialized_len_unsized::<[u8]>(&[0, 1, 2, 3]);
}

#[test]
fn size_hint_vector() {
    size_hint_matches_serialized_len::<Vec<u8>>(vec![]);
    size_hint_matches_serialized_len(vec![3u8; 1]);
    size_hint_matches_serialized_len(vec![50u32; 5]);
}

#[test]
fn size_hint_option() {
    size_hint_matches_serialized_len(Option::<u16>::None);
    size_hint_matches_serialized_len(Some(3u64));
}

#[test]
fn size_hint_string() {
    size_hint_matches_serialized_len("".to_owned());
    size_hint_matches_serialized_len("test_string".to_owned());

    size_hint_matches_serialized_len_unsized::<str>("");
    size_hint_matches_serialized_len_unsized::<str>("test_str");
}

#[test]
fn size_hint_btree() {
    size_hint_matches_serialized_len(BTreeMap::<alloc::string::String, u64>::new());

    let mut map = BTreeMap::new();
    map.insert("key".to_owned(), "value".to_owned());
    map.insert("key2".to_owned(), "value2".to_owned());
    size_hint_matches_serialized_len(map);

    size_hint_matches_serialized_len(BTreeSet::<alloc::string::String>::new());

    let mut set = BTreeSet::new();
    set.insert("value".to_owned());
    set.insert("value2".to_owned());
    size_hint_matches_serialized_len(set);
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
