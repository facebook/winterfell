// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::{marker::PhantomData, time::Duration};

use air::{EvaluationFrame, LogUpGkrEvaluator, LogUpGkrOracle};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_192, DefaultRandomCoin, RandomCoin};
use math::{fields::f64::BaseElement, ExtensionOf, FieldElement};
use rand_utils::{rand_value, rand_vector};
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use winter_sumcheck::{sum_check_prove_higher_degree, MultiLinearPoly};

const LOG_POLY_SIZE: [usize; 2] = [18, 20];

fn sum_check_high_degree(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sum-check prover high degree");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &log_poly_size in LOG_POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("", log_poly_size), |b| {
            b.iter_batched(
                || {
                    let logup_randomness = rand_vector(1);
                    let evaluator = PlainLogUpGkrEval::<BaseElement>::default();
                    let transcript = DefaultRandomCoin::<Blake3_192<BaseElement>>::new(&vec![
                            BaseElement::ZERO;
                            4
                        ]);
                    (
                        setup_sum_check::<BaseElement>(log_poly_size),
                        evaluator,
                        logup_randomness,
                        transcript,
                    )
                },
                |(
                    (claim, r_batch, rand_pt, (ml0, ml1, ml2, ml3, ml4)),
                    evaluator,
                    logup_randomness,
                    transcript,
                )| {
                    let mut mls = vec![ml0, ml1, ml2, ml3, ml4];
                    let mut transcript = transcript;

                    sum_check_prove_higher_degree(
                        &evaluator,
                        rand_pt,
                        claim,
                        r_batch,
                        logup_randomness,
                        &mut mls,
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
    Vec<E>,
    (
        MultiLinearPoly<E>,
        MultiLinearPoly<E>,
        MultiLinearPoly<E>,
        MultiLinearPoly<E>,
        MultiLinearPoly<E>,
    ),
) {
    let n = 1 << log_size;
    let table = MultiLinearPoly::from_evaluations(rand_vector(n));
    let multiplicity = MultiLinearPoly::from_evaluations(rand_vector(n));
    let values_0 = MultiLinearPoly::from_evaluations(rand_vector(n));
    let values_1 = MultiLinearPoly::from_evaluations(rand_vector(n));
    let values_2 = MultiLinearPoly::from_evaluations(rand_vector(n));

    // this will not generate the correct claim with overwhelming probability but should be fine
    // for benchmarking
    let rand_pt: Vec<E> = rand_vector(log_size + 2);
    let r_batch: E = rand_value();
    let claim: E = rand_value();

    (claim, r_batch, rand_pt, (table, multiplicity, values_0, values_1, values_2))
}

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement> {
    _field: PhantomData<B>,
}

impl LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn get_oracles(&self) -> Vec<LogUpGkrOracle<Self::BaseField>> {
        let committed_0 = LogUpGkrOracle::CurrentRow(0);
        let committed_1 = LogUpGkrOracle::CurrentRow(1);
        let committed_2 = LogUpGkrOracle::CurrentRow(2);
        let committed_3 = LogUpGkrOracle::CurrentRow(3);
        let committed_4 = LogUpGkrOracle::CurrentRow(4);
        vec![committed_0, committed_1, committed_2, committed_3, committed_4]
    }

    fn get_num_rand_values(&self) -> usize {
        1
    }

    fn get_num_fractions(&self) -> usize {
        4
    }

    fn max_degree(&self) -> usize {
        3
    }

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, _periodic_values: &[E], query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        query.iter_mut().zip(frame.current().iter()).for_each(|(q, f)| *q = *f);
    }

    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        assert_eq!(numerator.len(), 4);
        assert_eq!(denominator.len(), 4);
        assert_eq!(query.len(), 5);
        numerator[0] = E::from(query[1]);
        numerator[1] = E::ONE;
        numerator[2] = E::ONE;
        numerator[3] = E::ONE;

        denominator[0] = rand_values[0] - E::from(query[0]);
        denominator[1] = -(rand_values[0] - E::from(query[2]));
        denominator[2] = -(rand_values[0] - E::from(query[3]));
        denominator[3] = -(rand_values[0] - E::from(query[4]));
    }
}

criterion_group!(group, sum_check_high_degree);
criterion_main!(group);
