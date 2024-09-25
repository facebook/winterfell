// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::{marker::PhantomData, time::Duration, vec::Vec};

use air::{
    Air, AirContext, Assertion, AuxRandElements, EvaluationFrame, LogUpGkrEvaluator,
    LogUpGkrOracle, ProofOptions, TraceInfo, TransitionConstraintDegree,
};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::RandomCoin;
use math::StarkField;
use winter_prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    matrix::ColMatrix,
    prove_gkr, Trace,
};

const TRACE_LENS: [usize; 4] = [2_usize.pow(18), 2_usize.pow(19), 2_usize.pow(20), 2_usize.pow(21)];

/// Simple benchmark for the GKR part of STARK with LogUp-GKR.
///
/// The main trace contains `5` columns and the LogUp relation is a simple one where we have:
///
/// 1. a table of values from `0` to `trace_len - 1`.
/// 2. a multiplicity column containing the number of look ups for each value in the table.
/// 3. three columns with values contained in the table above.
///
/// Given the above, the benchmark then gives an idea about the minimal overhead due to enabling
/// LogUp-GKR. The overhead could be bigger depending on the complexity of the LogUp relation.
fn prove_with_logup_gkr(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove LogUp-GKR");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &trace_len in TRACE_LENS.iter() {
        group.bench_function(BenchmarkId::new("", trace_len), |b| {
            let main_trace = LogUpGkrSimpleTrace::new(trace_len);
            let evaluator = PlainLogUpGkrEval::new();

            b.iter_batched(
                || (main_trace.clone(), evaluator.clone()),
                |(main_trace, evaluator)| {
                    let mut public_coin =
                        DefaultRandomCoin::<Blake3_256<BaseElement>>::new(&[BaseElement::ZERO; 4]);
                    prove_gkr::<BaseElement>(&main_trace, &evaluator, &mut public_coin)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(logup_gkr_group, prove_with_logup_gkr);
criterion_main!(logup_gkr_group);

// LogUpGkrSimple
// =================================================================================================

#[derive(Clone, Debug)]
struct LogUpGkrSimpleTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LogUpGkrSimpleTrace {
    fn new(trace_len: usize) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        // we create a column for the table we are looking values into. These are just the integers
        // from 0 to `trace_len`.
        let table: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();

        // we create three columns that contains values contained in `table`. For simplicity, we
        // look up only the values `0` or `1`, we look up the value `1` four times and the value `0`
        // `trace_len - 4` times.

        let mut values_0: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        for i in 0..4 {
            values_0[i + 4] = BaseElement::ONE;
        }

        let mut values_1: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        for i in 0..4 {
            values_1[i + 4] = BaseElement::ONE;
        }

        let mut values_2: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        for i in 0..4 {
            values_2[i + 4] = BaseElement::ONE;
        }

        // we create the multiplicity column
        let mut multiplicity: Vec<BaseElement> =
            (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        // we look up the value `1` four times in three columns
        multiplicity[1] = BaseElement::new(3 * 4);
        // we look up the value `0`  `trace_len - 4` in three columns
        multiplicity[0] = BaseElement::new(3 * trace_len as u64 - 3 * 4);

        Self {
            main_trace: ColMatrix::new(vec![table, multiplicity, values_0, values_1, values_2]),
            info: TraceInfo::new_multi_segment(5, 0, 0, trace_len, vec![], true),
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LogUpGkrSimpleTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main_trace
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = row_idx + 1;
        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx % self.len(), frame.next_mut());
    }
}

// AIR
// =================================================================================================

struct LogUpGkrSimpleAir {
    context: AirContext<BaseElement, ()>,
}

impl Air for LogUpGkrSimpleAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                _pub_inputs,
                vec![TransitionConstraintDegree::new(1)],
                vec![],
                1,
                0,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField, ()> {
        &self.context
    }

    fn evaluate_transition<E: math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];

        // increments by 1
        result[0] = next - current - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![]
    }

    fn get_logup_gkr_evaluator(
        &self,
    ) -> impl LogUpGkrEvaluator<BaseField = Self::BaseField, PublicInputs = Self::PublicInputs>
    {
        PlainLogUpGkrEval::new()
    }
}

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement + StarkField> {
    oracles: Vec<LogUpGkrOracle>,
    _field: PhantomData<B>,
}

impl<B: FieldElement + StarkField> PlainLogUpGkrEval<B> {
    pub fn new() -> Self {
        let committed_0 = LogUpGkrOracle::CurrentRow(0);
        let committed_1 = LogUpGkrOracle::CurrentRow(1);
        let committed_2 = LogUpGkrOracle::CurrentRow(2);
        let committed_3 = LogUpGkrOracle::CurrentRow(3);
        let committed_4 = LogUpGkrOracle::CurrentRow(4);
        let oracles = vec![committed_0, committed_1, committed_2, committed_3, committed_4];
        Self { oracles, _field: PhantomData }
    }
}

impl LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn get_oracles(&self) -> &[LogUpGkrOracle] {
        &self.oracles
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

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        query.iter_mut().zip(frame.current().iter()).for_each(|(q, f)| *q = *f)
    }

    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        _periodic_values: &[F],
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

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        E::ZERO
    }
}
