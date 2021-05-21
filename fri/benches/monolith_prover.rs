// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::hash::Blake3_256;
use math::{
    fft,
    field::{f128::BaseElement, FieldElement, StarkField},
    utils::{get_power_series_with_offset, log2},
};
use std::time::Duration;
use winter_fri::{DefaultProverChannel, FriOptions, FriProver};

static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];
static BLOWUP_FACTOR: usize = 8;
static DOMAIN_OFFSET: BaseElement = BaseElement::GENERATOR;

pub fn build_layers(c: &mut Criterion) {
    let mut fri_group = c.benchmark_group("FRI prover");
    fri_group.sample_size(10);
    fri_group.measurement_time(Duration::from_secs(10));

    let options = FriOptions::new(BLOWUP_FACTOR, DOMAIN_OFFSET);

    for &domain_size in &BATCH_SIZES {
        let g = BaseElement::get_root_of_unity(log2(domain_size));
        let domain = get_power_series_with_offset(g, BaseElement::GENERATOR, domain_size);
        let evaluations = build_evaluations(domain_size);

        fri_group.bench_with_input(
            BenchmarkId::new("build_layers", domain_size),
            &evaluations,
            |b, e| {
                let mut prover = FriProver::new(options.clone());
                b.iter_batched(
                    || e.clone(),
                    |evaluations| {
                        let mut channel =
                            DefaultProverChannel::<Blake3_256, BaseElement>::new(domain_size, 32);
                        prover.build_layers(&mut channel, evaluations, &domain);
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
    let mut p = BaseElement::prng_vector([1; 32], domain_size / BLOWUP_FACTOR);
    p.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}
