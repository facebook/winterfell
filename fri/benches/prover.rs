// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use math::{fft, fields::f128::BaseElement, FieldElement};
use rand_utils::rand_vector;
use winter_fri::{DefaultProverChannel, FriOptions, FriProver};

static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];
static BLOWUP_FACTOR: usize = 8;

pub fn build_layers(c: &mut Criterion) {
    let mut fri_group = c.benchmark_group("FRI prover");
    fri_group.sample_size(10);
    fri_group.measurement_time(Duration::from_secs(10));

    let options = FriOptions::new(BLOWUP_FACTOR, 4, 255);

    for &domain_size in &BATCH_SIZES {
        let evaluations = build_evaluations(domain_size);

        fri_group.bench_with_input(
            BenchmarkId::new("build_layers", domain_size),
            &evaluations,
            |b, e| {
                let mut prover =
                    FriProver::<_, _, _, MerkleTree<Blake3_256<BaseElement>>>::new(options.clone());
                b.iter_batched(
                    || e.clone(),
                    |evaluations| {
                        let mut channel = DefaultProverChannel::<
                            BaseElement,
                            Blake3_256<BaseElement>,
                            DefaultRandomCoin<Blake3_256<BaseElement>>,
                        >::new(domain_size, 32);
                        prover.build_layers(&mut channel, evaluations);
                        prover.reset();
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

criterion_group!(fri_prover_group, build_layers);
criterion_main!(fri_prover_group);

// HELPER FUNCTIONS
// ================================================================================================

fn build_evaluations(domain_size: usize) -> Vec<BaseElement> {
    let mut p: Vec<BaseElement> = rand_vector(domain_size / BLOWUP_FACTOR);
    p.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}
