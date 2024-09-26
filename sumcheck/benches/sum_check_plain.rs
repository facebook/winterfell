// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_192, DefaultRandomCoin, RandomCoin};
use math::{fields::f64::BaseElement, FieldElement};
use rand_utils::{rand_value, rand_vector};
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use winter_sumcheck::{
    sumcheck_prove_plain_batched, CircuitLayerPolys, EqFunction, MultiLinearPoly,
};

const LOG_POLY_SIZE: [usize; 2] = [18, 20];

fn sum_check_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sum-check prover plain");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &log_poly_size in LOG_POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("", log_poly_size), |b| {
            b.iter_batched(
                || {
                    let transcript =
                        DefaultRandomCoin::<Blake3_192<BaseElement>>::new(&[BaseElement::ZERO; 4]);
                    (setup_sum_check::<BaseElement>(log_poly_size, 4), transcript)
                },
                |(
                    (
                        claims,
                        evaluation_point,
                        r_batch,
                        inner_layers,
                        tensored_batching_randomness,
                        eq,
                    ),
                    transcript,
                )| {
                    let mut eq = eq;
                    let mut transcript = transcript;

                    sumcheck_prove_plain_batched(
                        &claims,
                        &evaluation_point,
                        r_batch,
                        inner_layers,
                        &mut eq,
                        &tensored_batching_randomness,
                        &mut transcript,
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn setup_sum_check<E: FieldElement>(
    log_size: usize,
    num_fractions: usize,
) -> (Vec<E>, Vec<E>, E, Vec<CircuitLayerPolys<E>>, Vec<E>, MultiLinearPoly<E>) {
    let n = 1 << (log_size + 1);

    // this will not generate the correct claim with overwhelming probability but should be fine
    // for benchmarking
    let evaluation_point = rand_vector(log_size);
    let r_batch: E = rand_value();
    let claims: Vec<E> = vec![rand_value(); num_fractions];

    let mut inner_layers = Vec::with_capacity(num_fractions);
    for _ in 0..num_fractions {
        let p: Vec<E> = rand_vector(n);
        let q: Vec<E> = rand_vector(n);
        let p = MultiLinearPoly::from_evaluations(p);
        let q = MultiLinearPoly::from_evaluations(q);
        let inner_layer = CircuitLayerPolys::from_mle(p, q);
        inner_layers.push(inner_layer)
    }
    let eq = MultiLinearPoly::from_evaluations(
        EqFunction::new(evaluation_point.clone().into()).evaluations(),
    );
    let tensored_batching_randomness =
        EqFunction::new(rand_vector::<E>(num_fractions).into()).evaluations();

    (
        claims,
        evaluation_point,
        r_batch,
        inner_layers,
        tensored_batching_randomness,
        eq,
    )
}

criterion_group!(group, sum_check_plain);
criterion_main!(group);
