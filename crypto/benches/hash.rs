// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use math::fields::f128;
use winter_crypto::{
    hashers::{Blake3_256, Rp62_248, Rp64_256, Sha3_256},
    Hasher,
};

type Blake3 = Blake3_256<f128::BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

type Sha3 = Sha3_256<f128::BaseElement>;
type Sha3Digest = <Sha3 as Hasher>::Digest;

type Rp62_248Digest = <Rp62_248 as Hasher>::Digest;
type Rp64_256Digest = <Rp64_256 as Hasher>::Digest;

fn blake3(c: &mut Criterion) {
    let v: [Blake3Digest; 2] = [Blake3::hash(&[1u8]), Blake3::hash(&[2u8])];
    c.bench_function("hash_blake3", |bench| {
        bench.iter(|| Blake3::merge(black_box(&v)))
    });
}

fn sha3(c: &mut Criterion) {
    let v: [Sha3Digest; 2] = [Sha3::hash(&[1u8]), Sha3::hash(&[2u8])];
    c.bench_function("hash_sha3", |bench| {
        bench.iter(|| Sha3::merge(black_box(&v)))
    });
}

fn rescue248(c: &mut Criterion) {
    let v: [Rp62_248Digest; 2] = [Rp62_248::hash(&[1u8]), Rp62_248::hash(&[2u8])];
    c.bench_function("hash_rp62_248", |bench| {
        bench.iter(|| Rp62_248::merge(black_box(&v)))
    });
}

fn rescue256(c: &mut Criterion) {
    let v: [Rp64_256Digest; 2] = [Rp64_256::hash(&[1u8]), Rp64_256::hash(&[2u8])];
    c.bench_function("hash_rp64_256", |bench| {
        bench.iter(|| Rp64_256::merge(black_box(&v)))
    });
}

criterion_group!(hash_group, blake3, sha3, rescue248, rescue256);
criterion_main!(hash_group);
