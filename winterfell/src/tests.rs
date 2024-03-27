// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::*;
use prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    matrix::ColMatrix,
};
use std::vec;
use std::vec::Vec;

#[test]
fn test_simple_lagrange_kernel_air() {
    let trace = LagrangeSimpleTrace::new();
    let prover = LagrangeSimpleProver::new();

    let proof = prover.prove(trace).unwrap();

    verify::<
        LagrangeKernelSimpleAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, (), &AcceptableOptions::MinConjecturedSecurity(0))
    .unwrap()
}

// LagrangeSimpleTrace
// ================================================================================================

struct LagrangeSimpleTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LagrangeSimpleTrace {
    const TRACE_LENGTH: usize = 8;

    fn new() -> Self {
        let col = vec![
            BaseElement::ZERO,
            BaseElement::from(1_u32),
            BaseElement::from(2_u32),
            BaseElement::from(3_u32),
            BaseElement::from(4_u32),
            BaseElement::from(5_u32),
            BaseElement::from(6_u32),
            BaseElement::from(7_u32),
        ];

        Self {
            main_trace: ColMatrix::new(vec![col]),
            info: TraceInfo::new_multi_segment(1, [2], [3], Self::TRACE_LENGTH, vec![]),
        }
    }
}

impl Trace for LagrangeSimpleTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<BaseElement> {
        &self.main_trace
    }

    fn build_aux_segment<E: FieldElement<BaseField = BaseElement>>(
        &mut self,
        aux_segments: &[ColMatrix<E>],
        _rand_elements: &[E],
        lagrange_rand_elements: Option<&[E]>,
    ) -> Option<ColMatrix<E>> {
        assert!(aux_segments.is_empty());

        let lagrange_rand_elements = lagrange_rand_elements.unwrap();

        let r0 = lagrange_rand_elements[0];
        let r1 = lagrange_rand_elements[1];
        let r2 = lagrange_rand_elements[2];

        let lagrange_col = vec![
            (E::ONE - r2) * (E::ONE - r1) * (E::ONE - r0),
            (E::ONE - r2) * (E::ONE - r1) * r0,
            (E::ONE - r2) * r1 * (E::ONE - r0),
            (E::ONE - r2) * r1 * r0,
            r2 * (E::ONE - r1) * (E::ONE - r0),
            r2 * (E::ONE - r1) * r0,
            r2 * r1 * (E::ONE - r0),
            r2 * r1 * r0,
        ];

        let dummy_col = vec![E::ZERO; 8];

        Some(ColMatrix::new(vec![lagrange_col, dummy_col]))
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<BaseElement>) {
        let next_row_idx = row_idx + 1;
        assert_ne!(next_row_idx, Self::TRACE_LENGTH);

        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }
}

// LagrangeMockAir
// ================================================================================================

/// An Air with one Lagrange kernel auxiliary column
struct LagrangeKernelSimpleAir {
    context: AirContext<BaseElement>,
}

impl Air for LagrangeKernelSimpleAir {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                vec![TransitionConstraintDegree::new(1)],
                1,
                1,
                Some(0),
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
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
        _aux_rand_elements: &AuxTraceRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxTraceRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![Assertion::single(1, 0, E::ZERO)]
    }
}

// LagrangeSimpleProver
// ================================================================================================

struct LagrangeSimpleProver {
    options: ProofOptions,
}

impl LagrangeSimpleProver {
    fn new() -> Self {
        Self {
            options: ProofOptions::new(1, 2, 0, FieldExtension::None, 2, 1),
        }
    }
}

impl Prover for LagrangeSimpleProver {
    type BaseField = BaseElement;
    type Air = LagrangeKernelSimpleAir;
    type Trace = LagrangeSimpleTrace;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LagrangeKernelSimpleAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
        ()
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
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[test]
fn test_complex_lagrange_kernel_air() {
    let trace = LagrangeComplexTrace::new(2_usize.pow(10), 2);
    let prover = LagrangeComplexProver::new();
    let proof = prover.prove(trace).unwrap();

    verify::<
        LagrangeKernelComplexAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, (), &AcceptableOptions::MinConjecturedSecurity(0))
    .unwrap()
}

// LagrangeComplexTrace
// =================================================================================================

#[derive(Clone, Debug)]
struct LagrangeComplexTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LagrangeComplexTrace {
    fn new(trace_len: usize, aux_segment_width: usize) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        let main_trace_col: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();

        let num_aux_segment_rands = trace_len.ilog2() as usize;

        Self {
            main_trace: ColMatrix::new(vec![main_trace_col]),
            info: TraceInfo::new_multi_segment(
                1,
                [aux_segment_width],
                [num_aux_segment_rands],
                trace_len,
                vec![],
            ),
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LagrangeComplexTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main_trace
    }

    /// Each non-Lagrange kernel segment will simply take the sum the random elements, and multiply
    /// by the main column
    fn build_aux_segment<E: FieldElement<BaseField = Self::BaseField>>(
        &mut self,
        aux_segments: &[ColMatrix<E>],
        rand_elements: &[E],
        lagrange_kernel_rand_elements: Option<&[E]>,
    ) -> Option<ColMatrix<E>> {
        assert!(aux_segments.is_empty());

        let mut columns = Vec::new();

        // first build the Lagrange kernel column
        {
            let r = lagrange_kernel_rand_elements.unwrap();

            let mut lagrange_col = Vec::with_capacity(self.len());

            for row_idx in 0..self.len() {
                let mut row_value = E::ONE;
                for (bit_idx, &r_i) in r.iter().enumerate() {
                    if row_idx & (1 << bit_idx) == 0 {
                        row_value *= E::ONE - r_i;
                    } else {
                        row_value *= r_i;
                    }
                }
                lagrange_col.push(row_value);
            }

            columns.push(lagrange_col);
        }

        // Then all other auxiliary columns
        let rand_summed = rand_elements.iter().fold(E::ZERO, |acc, &r| acc + r);
        for _ in 1..self.aux_trace_width() {
            // building a dummy auxiliary column
            let column = self
                .main_segment()
                .get_column(0)
                .iter()
                .map(|main_row_val| rand_summed.mul_base(*main_row_val))
                .collect();

            columns.push(column);
        }

        Some(ColMatrix::new(columns))
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = row_idx + 1;
        assert_ne!(next_row_idx, self.len());

        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }
}

// AIR
// =================================================================================================

struct LagrangeKernelComplexAir {
    context: AirContext<BaseElement>,
}

impl Air for LagrangeKernelComplexAir {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                vec![TransitionConstraintDegree::new(1)],
                1,
                1,
                Some(0),
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
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
        _aux_rand_elements: &AuxTraceRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxTraceRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![Assertion::single(1, 0, E::ZERO)]
    }
}

// LagrangeComplexProver
// ================================================================================================

struct LagrangeComplexProver {
    options: ProofOptions,
}

impl LagrangeComplexProver {
    fn new() -> Self {
        Self {
            options: ProofOptions::new(1, 2, 0, FieldExtension::None, 2, 1),
        }
    }
}

impl Prover for LagrangeComplexProver {
    type BaseField = BaseElement;
    type Air = LagrangeKernelComplexAir;
    type Trace = LagrangeComplexTrace;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LagrangeKernelComplexAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
        ()
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
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}
