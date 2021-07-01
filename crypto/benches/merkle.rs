// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::ThreadRng, thread_rng, RngCore};
use utils::uninit_vector;
use winter_crypto::{build_merkle_nodes, concurrent, hashers::Blake3_256};

pub fn merkle_tree_construction(c: &mut Criterion) {
    let mut merkle_group = c.benchmark_group("merkle tree construction");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let mut csprng: ThreadRng = thread_rng();

        let data: Vec<[u8; 32]> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                let mut v = [0u8; 32];
                csprng.fill_bytes(&mut v);
                res[i] = v;
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Blake3_256>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Blake3_256>(&i))
        });
    }
}

criterion_group!(merkle_group, merkle_tree_construction,);
criterion_main!(merkle_group);
