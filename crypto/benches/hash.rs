// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use math::fields::f128::BaseElement;
use winter_crypto::{
    hashers::{Blake3_256, Sha3_256},
    Hasher,
};

type Blake3 = Blake3_256<BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

type Sha3 = Sha3_256<BaseElement>;
type Sha3Digest = <Sha3 as Hasher>::Digest;

pub fn blake3(c: &mut Criterion) {
    let v: [Blake3Digest; 2] = [Blake3::hash(&[1u8]), Blake3::hash(&[2u8])];
    c.bench_function("hash_blake3", |bench| {
        bench.iter(|| Blake3::merge(black_box(&v)))
    });
}

pub fn sha3(c: &mut Criterion) {
    let v: [Sha3Digest; 2] = [Sha3::hash(&[1u8]), Sha3::hash(&[2u8])];
    c.bench_function("hash_sha3", |bench| {
        bench.iter(|| Sha3::merge(black_box(&v)))
    });
}

criterion_group!(hash_group, blake3, sha3);
criterion_main!(hash_group);
