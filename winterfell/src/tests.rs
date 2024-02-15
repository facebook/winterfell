use super::*;
use prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
};

#[test]
fn test_lagrange_kernel_air() {
    let trace = LagrangeMockTrace::new();
    let prover = LagrangeProver::new();

    let proof = prover.prove(trace).unwrap();

    assert!(verify::<
        LagrangeKernelMockAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, (), &AcceptableOptions::MinConjecturedSecurity(0))
    .is_ok());
}

// LagrangeMockTrace
// ================================================================================================

struct LagrangeMockTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LagrangeMockTrace {
    const TRACE_LENGTH: usize = 8;

    fn new() -> Self {
        let col = vec![BaseElement::ZERO; Self::TRACE_LENGTH];

        Self {
            main_trace: ColMatrix::new(vec![col]),
            info: TraceInfo::new_multi_segment(1, [1], [3], Some(0), Self::TRACE_LENGTH, vec![]),
        }
    }
}

impl Trace for LagrangeMockTrace {
    type BaseField = BaseElement;

    fn get_info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<BaseElement> {
        &self.main_trace
    }

    fn build_aux_segment<E: FieldElement<BaseField = BaseElement>>(
        &mut self,
        aux_segments: &[ColMatrix<E>],
        rand_elements: &[E],
    ) -> Option<ColMatrix<E>> {
        assert!(aux_segments.is_empty());

        let r0 = rand_elements[0];
        let r1 = rand_elements[1];
        let r2 = rand_elements[2];

        let col = vec![
            (E::ONE - r2) * (E::ONE - r1) * (E::ONE - r0),
            (E::ONE - r2) * (E::ONE - r1) * r0,
            (E::ONE - r2) * r1 * (E::ONE - r0),
            (E::ONE - r2) * r1 * r0,
            r2 * (E::ONE - r1) * (E::ONE - r0),
            r2 * (E::ONE - r1) * r0,
            r2 * r1 * (E::ONE - r0),
            r2 * r1 * r0,
        ];

        Some(ColMatrix::new(vec![col]))
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
struct LagrangeKernelMockAir {
    context: AirContext<BaseElement>,
}

impl Air for LagrangeKernelMockAir {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                Vec::new(),
                1,
                0,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
        // do nothing
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }

    fn lagrange_kernel_aux_column_idx(&self) -> Option<usize> {
        // apply the lagrange kernel constraints to first column
        Some(0)
    }
}

// LagrangeProver
// ================================================================================================

struct LagrangeProver {
    options: ProofOptions,
}

impl LagrangeProver {
    fn new() -> Self {
        Self {
            options: ProofOptions::new(1, 2, 0, FieldExtension::None, 2, 1),
        }
    }
}

impl Prover for LagrangeProver {
    type BaseField = BaseElement;
    type Air = LagrangeKernelMockAir;
    type Trace = LagrangeMockTrace;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LagrangeKernelMockAir, E>;

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
