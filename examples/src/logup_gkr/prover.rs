// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree, math::FieldElement, matrix::ColMatrix, Air, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultTraceLde, EvaluationFrame,
    LogUpGkrConstraintEvaluator, StarkDomain, Trace, TraceInfo, TracePolyTable,
};

use super::{
    air::LogUpGkrSimpleAir, BaseElement, DefaultRandomCoin, ElementHasher, PhantomData,
    ProofOptions, Prover,
};

pub(crate) struct LogUpGkrSimpleProver<H: ElementHasher<BaseField = BaseElement> + Sync + Send> {
    aux_trace_width: usize,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher<BaseField = BaseElement> + Sync + Send> LogUpGkrSimpleProver<H> {
    pub(crate) fn new(aux_trace_width: usize, options: ProofOptions) -> Self {
        Self {
            aux_trace_width,
            options,
            _hasher: PhantomData,
        }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 2 terms.
    pub fn build_trace(&self, trace_len: usize, aux_segment_width: usize) -> LogUpGkrSimpleTrace {
        LogUpGkrSimpleTrace::new(trace_len, aux_segment_width)
    }
}

impl<H: ElementHasher<BaseField = BaseElement> + Sync + Send> Prover for LogUpGkrSimpleProver<H> {
    type BaseField = BaseElement;
    type Air = LogUpGkrSimpleAir;
    type Trace = LogUpGkrSimpleTrace;
    type HashFn = H;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        LogUpGkrConstraintEvaluator<'a, LogUpGkrSimpleAir, E>;

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
        E: FieldElement<BaseField = Self::BaseField>,
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
        E: FieldElement<BaseField = Self::BaseField>,
    {
        LogUpGkrConstraintEvaluator::new(air, aux_rand_elements.unwrap(), composition_coefficients)
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

#[derive(Clone, Debug)]
pub(crate) struct LogUpGkrSimpleTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LogUpGkrSimpleTrace {
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
            info: TraceInfo::new_multi_segment(5, aux_segment_width, 1, trace_len, vec![], true),
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
