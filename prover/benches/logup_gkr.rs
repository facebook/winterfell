// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::{marker::PhantomData, time::Duration, vec::Vec};

use air::{
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients,
    EvaluationFrame, FieldExtension, LogUpGkrEvaluator, LogUpGkrOracle, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::MerkleTree;
use math::StarkField;
use winter_prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    matrix::ColMatrix,
    DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain, Trace, TracePolyTable,
};

const TRACE_LENS: [usize; 2] = [2_usize.pow(20), 2_usize.pow(21)];
const AUX_TRACE_WIDTH: usize = 2;

fn prove_with_lagrange_kernel(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove with Lagrange kernel column");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &trace_len in TRACE_LENS.iter() {
        group.bench_function(BenchmarkId::new("", trace_len), |b| {
            let trace = LogUpGkrSimple::new(trace_len, AUX_TRACE_WIDTH);
            let prover = LogUpGkrSimpleProver::new(AUX_TRACE_WIDTH);

            b.iter_batched(
                || trace.clone(),
                |trace| prover.prove(trace).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(lagrange_kernel_group, prove_with_lagrange_kernel);
criterion_main!(lagrange_kernel_group);

// LogUpGkrSimple
// =================================================================================================

#[derive(Clone, Debug)]
struct LogUpGkrSimple {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LogUpGkrSimple {
    fn new(trace_len: usize, aux_segment_width: usize) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        let table: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();
        let mut multiplicity: Vec<BaseElement> =
            (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        multiplicity[0] = BaseElement::new(3 * trace_len as u64 - 3 * 4);
        multiplicity[1] = BaseElement::new(3 * 4);

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

        Self {
            main_trace: ColMatrix::new(vec![table, multiplicity, values_0, values_1, values_2]),
            info: TraceInfo::new_multi_segment(5, aux_segment_width, 0, trace_len, vec![], true),
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LogUpGkrSimple {
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
// Prover
// ================================================================================================

struct LogUpGkrSimpleProver {
    aux_trace_width: usize,
    options: ProofOptions,
}

impl LogUpGkrSimpleProver {
    fn new(aux_trace_width: usize) -> Self {
        Self {
            aux_trace_width,
            options: ProofOptions::new(1, 8, 0, FieldExtension::Quadratic, 2, 1),
        }
    }
}

impl Prover for LogUpGkrSimpleProver {
    type BaseField = BaseElement;
    type Air = LogUpGkrSimpleAir;
    type Trace = LogUpGkrSimple;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Blake3_256<BaseElement>>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LogUpGkrSimpleAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>)
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_aux_trace<E>(&self, main_trace: &Self::Trace, _aux_rand_elements: &[E]) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let main_trace = main_trace.main_segment();

        let mut columns = Vec::new();

        let rand_summed = E::from(777_u32);
        for _ in 0..self.aux_trace_width {
            // building a dummy auxiliary column
            let column = main_trace
                .get_column(0)
                .iter()
                .map(|row_val| rand_summed.mul_base(*row_val))
                .collect();

            columns.push(column);
        }

        ColMatrix::new(columns)
    }
}
