// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use math::{
    fields::{f64::BaseElement, QuadExtension},
    polynom::{self, eval_many, syn_div_roots_in_place},
    ExtensionOf, StarkField,
};
use rand_utils::{rand_value, rand_vector};
use std::time::Duration;

const TRACE_LENS: [usize; 4] = [2_usize.pow(16), 2_usize.pow(18), 2_usize.pow(20), 2_usize.pow(22)];

fn polynomial_division_naive(c: &mut Criterion) {
    let mut group = c.benchmark_group("Naive polynomial division");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &trace_len in TRACE_LENS.iter() {
        group.bench_function(BenchmarkId::new("prover", trace_len), |b| {
            let poly: Vec<QuadExtension<BaseElement>> = rand_vector(trace_len);
            let z: QuadExtension<BaseElement> = rand_value();
            let log_trace_len = trace_len.ilog2();
            let g: BaseElement = BaseElement::get_root_of_unity(log_trace_len as u32);
            let mut xs = Vec::with_capacity(log_trace_len as usize + 1);

            // push z
            xs.push(z);

            // compute the values (z * g), (z * g^2), (z * g^4), ..., (z * g^(2^(v-1)))
            let mut g_exp = g;
            for _ in 0..log_trace_len {
                let x = z.mul_base(g_exp);
                xs.push(x);
                g_exp *= g_exp;
            }
            let ood_evaluations = eval_many(&poly, &xs);

            let p_s = polynom::interpolate(&xs, &ood_evaluations, true);
            let numerator = polynom::sub(&poly, &p_s);
            let z_s = polynom::get_zero_roots(&xs);

            b.iter_batched(
                || {
                    let numerator = numerator.clone();
                    let z_s = z_s.clone();
                    (numerator, z_s)
                },
                |(numerator, z_s)| polynom::div(&numerator, &z_s),
                BatchSize::SmallInput,
            )
        });
    }
}

fn polynomial_division_synthetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("Synthetic polynomial division");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &trace_len in TRACE_LENS.iter() {
        group.bench_function(BenchmarkId::new("prover", trace_len), |b| {
            let poly: Vec<QuadExtension<BaseElement>> = rand_vector(trace_len);
            let z: QuadExtension<BaseElement> = rand_value();
            let log_trace_len = trace_len.ilog2();
            let g: BaseElement = BaseElement::get_root_of_unity(log_trace_len as u32);
            let mut xs = Vec::with_capacity(log_trace_len as usize + 1);

            // push z
            xs.push(z);

            // compute the values (z * g), (z * g^2), (z * g^4), ..., (z * g^(2^(v-1)))
            let mut g_exp = g;
            for _ in 0..log_trace_len {
                let x = z.mul_base(g_exp);
                xs.push(x);
                g_exp *= g_exp;
            }
            let ood_evaluations = eval_many(&poly, &xs);

            let p_s = polynom::interpolate(&xs, &ood_evaluations, true);
            let numerator = polynom::sub(&poly, &p_s);

            b.iter_batched(
                || {
                    let numerator = numerator.clone();
                    let xs = xs.clone();
                    (numerator, xs)
                },
                |(mut numerator, xs)| syn_div_roots_in_place(&mut numerator, &xs),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(poly_division, polynomial_division_naive, polynomial_division_synthetic);
criterion_main!(poly_division);
