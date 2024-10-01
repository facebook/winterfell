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
use winter_sumcheck::{sumcheck_prove_plain, EqFunction, MultiLinearPoly};
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
                    (setup_sum_check::<BaseElement>(log_poly_size), transcript)
                },
                |((claim, evaluation_point, r_batch, p, q, eq), transcript)| {
                    let mut eq = eq;
                    let mut transcript = transcript;
                    sumcheck_prove_plain(
                        claim,
                        &evaluation_point,
                        r_batch,
                        p,
                        q,
                        &mut eq,
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
) -> (E, Vec<E>, E, MultiLinearPoly<E>, MultiLinearPoly<E>, MultiLinearPoly<E>) {
    let n = 1 << (log_size + 1);
    let p: Vec<E> = rand_vector(n);
    let q: Vec<E> = rand_vector(n);

    // this will not generate the correct claim with overwhelming probability but should be fine
    // for benchmarking
    let rand_pt = rand_vector(log_size);
    let r_batch: E = rand_value();
    let claim: E = rand_value();
    let evaluation_point = rand_vector(log_size);

    let p = MultiLinearPoly::from_evaluations(p);
    let q = MultiLinearPoly::from_evaluations(q);
    let eq = MultiLinearPoly::from_evaluations(EqFunction::new(rand_pt.into()).evaluations());

    (claim, evaluation_point, r_batch, p, q, eq)
}

criterion_group!(group, sum_check_plain);
criterion_main!(group);
