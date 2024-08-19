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
                        DefaultRandomCoin::<Blake3_192<BaseElement>>::new(&vec![
                            BaseElement::ZERO;
                            4
                        ]);
                    (setup_sum_check::<BaseElement>(log_poly_size), transcript)
                },
                |((claim, r_batch, p0, p1, q0, q1, eq), transcript)| {
                    let mut p0 = p0;
                    let mut p1 = p1;
                    let mut q0 = q0;
                    let mut q1 = q1;
                    let mut eq = eq;
                    let mut transcript = transcript;

                    sumcheck_prove_plain(
                        claim,
                        r_batch,
                        &mut p0,
                        &mut p1,
                        &mut q0,
                        &mut q1,
                        &mut eq,
                        &mut transcript,
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn setup_sum_check<E: FieldElement>(
    log_size: usize,
) -> (
    E,
    E,
    MultiLinearPoly<E>,
    MultiLinearPoly<E>,
    MultiLinearPoly<E>,
    MultiLinearPoly<E>,
    MultiLinearPoly<E>,
) {
    let n = 1 << log_size;
    let p0: Vec<E> = rand_vector(n);
    let p1: Vec<E> = rand_vector(n);
    let q0: Vec<E> = rand_vector(n);
    let q1: Vec<E> = rand_vector(n);

    // this will not generate the correct claim with overwhelming probability but should be fine
    // for benchmarking
    let rand_pt = rand_vector(log_size);
    let r_batch: E = rand_value();
    let claim: E = rand_value();

    let p0 = MultiLinearPoly::from_evaluations(p0);
    let p1 = MultiLinearPoly::from_evaluations(p1);
    let q0 = MultiLinearPoly::from_evaluations(q0);
    let q1 = MultiLinearPoly::from_evaluations(q1);
    let eq = MultiLinearPoly::from_evaluations(EqFunction::new(rand_pt.into()).evaluations());

    (claim, r_batch, p0, p1, q0, q1, eq)
}

criterion_group!(group, sum_check_plain);
criterion_main!(group);
