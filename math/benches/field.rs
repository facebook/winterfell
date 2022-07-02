// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{
    black_box, criterion_group, criterion_main,
    measurement::{Measurement, WallTime},
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
};
use rand_utils::{rand_array, rand_value, rand_vector};
use std::time::Duration;
use winter_math::{
    batch_inversion,
    fields::{f128, f62, f64},
    fields::{CubeExtension, QuadExtension},
    ExtensibleField, FieldElement, StarkField,
};

const SIZES: [usize; 3] = [262_144, 524_288, 1_048_576];

// BATCH INVERSION
// ================================================================================================

pub fn batch_inv(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_inv");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SIZES.iter() {
        let values = rand_vector::<f128::BaseElement>(size);

        group.bench_function(BenchmarkId::new("no_coeff", size), |bench| {
            bench.iter_with_large_drop(|| batch_inversion(&values));
        });
    }

    group.finish();
}

// SEQUENTIAL OPS
// ================================================================================================
pub fn field_ops<B>(c: &mut Criterion, field_name: &str)
where
    B: StarkField + ExtensibleField<2> + ExtensibleField<3>,
{
    let mut group = c.benchmark_group(format!("field/{}", field_name));

    // --- base field -----------------------------------------------------------------------------

    group.bench_function("add", |bench| {
        let x = rand_value::<B>();
        let y = rand_value::<B>();
        bench.iter(|| black_box(x) + black_box(y))
    });

    group.bench_function("double", |bench| {
        let x = rand_value::<B>();
        bench.iter(|| black_box(x).double())
    });

    group.bench_function("sub", |bench| {
        let x = rand_value::<B>();
        let y = rand_value::<B>();
        bench.iter(|| black_box(x) - black_box(y))
    });

    group.bench_function("mul", |bench| {
        let x = rand_value::<B>();
        let y = rand_value::<B>();
        bench.iter(|| black_box(x) * black_box(y))
    });

    group.bench_function("exp", |bench| {
        let x = rand_value::<B>();
        let y = rand_value::<B>().as_int();
        bench.iter(|| x.exp(y))
    });

    group.bench_function("inv", |bench| {
        let x = rand_value::<B>();
        bench.iter(|| x.inv())
    });

    batch_ops::<B, WallTime>(&mut group, "base");
    array_ops::<B, WallTime>(&mut group, "base");

    // --- quadratic extension --------------------------------------------------------------------

    if QuadExtension::<B>::is_supported() {
        group.bench_function("quad/add", |bench| {
            let x = rand_value::<QuadExtension<B>>();
            let y = rand_value::<QuadExtension<B>>();
            bench.iter(|| black_box(x) + black_box(y))
        });

        group.bench_function("quad/double", |bench| {
            let x = rand_value::<QuadExtension<B>>();
            bench.iter(|| black_box(x).double())
        });

        group.bench_function("quad/sub", |bench| {
            let x = rand_value::<QuadExtension<B>>();
            let y = rand_value::<QuadExtension<B>>();
            bench.iter(|| black_box(x) - black_box(y))
        });

        group.bench_function("quad/mul", |bench| {
            let x = rand_value::<QuadExtension<B>>();
            let y = rand_value::<QuadExtension<B>>();
            bench.iter(|| black_box(x) * black_box(y))
        });

        batch_ops::<QuadExtension<B>, WallTime>(&mut group, "quad");
        array_ops::<QuadExtension<B>, WallTime>(&mut group, "quad");
    }

    // --- cubic extension ------------------------------------------------------------------------

    if CubeExtension::<B>::is_supported() {
        group.bench_function("cube/add", |bench| {
            let x = rand_value::<CubeExtension<B>>();
            let y = rand_value::<CubeExtension<B>>();
            bench.iter(|| black_box(x) + black_box(y))
        });

        group.bench_function("cube/double", |bench| {
            let x = rand_value::<CubeExtension<B>>();
            bench.iter(|| black_box(x).double())
        });

        group.bench_function("cube/sub", |bench| {
            let x = rand_value::<CubeExtension<B>>();
            let y = rand_value::<CubeExtension<B>>();
            bench.iter(|| black_box(x) - black_box(y))
        });

        group.bench_function("cube/mul", |bench| {
            let x = rand_value::<CubeExtension<B>>();
            let y = rand_value::<CubeExtension<B>>();
            bench.iter(|| black_box(x) * black_box(y))
        });
    }
}

// ARRAY OPS
// ================================================================================================
pub fn array_ops<E: FieldElement, M: Measurement>(group: &mut BenchmarkGroup<M>, extension: &str) {
    group.bench_function(format!("{}/array/add", extension), |b| {
        b.iter_batched(
            || (rand_array::<E, 100>(), rand_array::<E, 100>()),
            |(mut x, y)| {
                for (x, y) in x.iter_mut().zip(y) {
                    *x += y;
                }
                x
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("{}/array/sub", extension), |b| {
        b.iter_batched(
            || (rand_array::<E, 100>(), rand_array::<E, 100>()),
            |(mut x, y)| {
                for (x, y) in x.iter_mut().zip(y) {
                    *x -= y;
                }
                x
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("{}/array/mul", extension), |b| {
        b.iter_batched(
            || (rand_array::<E, 100>(), rand_array::<E, 100>()),
            |(mut x, y)| {
                for (x, y) in x.iter_mut().zip(y) {
                    *x *= y;
                }
                x
            },
            BatchSize::SmallInput,
        )
    });
}

// BATCH OPS
// ================================================================================================
pub fn batch_ops<E: FieldElement, M: Measurement>(group: &mut BenchmarkGroup<M>, extension: &str) {
    group.bench_function(format!("{}/batch/add", extension), |b| {
        b.iter_batched(
            || {
                (
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                )
            },
            |(mut a, mut b, mut c, mut d)| {
                for _ in 0..25 {
                    let t0 = a + b;
                    let t1 = b + c;
                    let t2 = c + d;
                    let t3 = d + a;

                    a = t0;
                    b = t1;
                    c = t2;
                    d = t3;
                }
                (a, b, c, d)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("{}/batch/sub", extension), |b| {
        b.iter_batched(
            || {
                (
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                )
            },
            |(mut a, mut b, mut c, mut d)| {
                for _ in 0..25 {
                    let t0 = a - b;
                    let t1 = b - c;
                    let t2 = c - d;
                    let t3 = d - a;

                    a = t0;
                    b = t1;
                    c = t2;
                    d = t3;
                }
                (a, b, c, d)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("{}/batch/mul", extension), |b| {
        b.iter_batched(
            || {
                (
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                    rand_value::<E>(),
                )
            },
            |(mut a, mut b, mut c, mut d)| {
                for _ in 0..25 {
                    let t0 = a * b;
                    let t1 = b * c;
                    let t2 = c * d;
                    let t3 = d * a;

                    a = t0;
                    b = t1;
                    c = t2;
                    d = t3;
                }
                (a, b, c, d)
            },
            BatchSize::SmallInput,
        )
    });
}

// GENERIC BENCHMARK RUNNER
// ================================================================================================

fn bench_field_ops(c: &mut Criterion) {
    field_ops::<f62::BaseElement>(c, "f62");
    field_ops::<f64::BaseElement>(c, "f64");
    field_ops::<f128::BaseElement>(c, "f128");
}

// CRITERION BOILERPLATE
// ================================================================================================

criterion_group!(field_group, batch_inv, bench_field_ops);
criterion_main!(field_group);
