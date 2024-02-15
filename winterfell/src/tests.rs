use super::*;
use prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, FieldElement},
};

#[test]
fn test_air() {
    // - Create trace with aux column lagrange (my own struct)
    // - Create prover (my own struct)
    // - Call prove() to generate `StarkProof`
    // - call `verify()` on the proof, and assert ok
}

// LagrangeMockTrace
// ================================================================================================

struct LagrangeMockTrace {}

impl Trace for LagrangeMockTrace {
    type BaseField = BaseElement;

    fn get_info(&self) -> &TraceInfo {
        todo!()
    }

    fn main_segment(&self) -> &matrix::ColMatrix<Self::BaseField> {
        todo!()
    }

    fn build_aux_segment<E: FieldElement<BaseField = Self::BaseField>>(
        &mut self,
        aux_segments: &[matrix::ColMatrix<E>],
        rand_elements: &[E],
    ) -> Option<matrix::ColMatrix<E>> {
        todo!()
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        todo!()
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
                0,
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
        Vec::new()
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
        main_trace: &matrix::ColMatrix<Self::BaseField>,
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
