use super::*;
use prover::math::fields::f64::BaseElement;

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
