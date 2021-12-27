use super::{BaseElement, ExecutionTrace, FibAir, FieldElement, ProofOptions, Prover, TRACE_WIDTH};

// FIBONACCI PROVER
// ================================================================================================

pub struct FibProver {
    options: ProofOptions,
}

impl FibProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 2 terms.
    pub fn build_trace(&self, sequence_length: usize) -> ExecutionTrace<BaseElement> {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        let mut trace = ExecutionTrace::new(TRACE_WIDTH, sequence_length / 2);
        trace.fill(
            |state| {
                state[0] = BaseElement::ONE;
                state[1] = BaseElement::ONE;
            },
            |_, state| {
                state[0] += state[1];
                state[1] += state[0];
            },
        );

        trace
    }
}

impl Prover for FibProver {
    type BaseField = BaseElement;
    type AIR = FibAir;

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
