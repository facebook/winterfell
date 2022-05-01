// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, FibAir, FieldElement, ProofOptions, Prover, Trace, TraceTable, TRACE_WIDTH,
};

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
    /// that each row advances the sequence by 1 term.
    pub fn build_trace(&self, sequence_length: usize) -> TraceTable<BaseElement> {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        let mut trace = TraceTable::new(TRACE_WIDTH, sequence_length);
        trace.update_row(0, &[BaseElement::ONE]);
        trace.update_row(1, &[BaseElement::ONE]);
        for i in 2..sequence_length {
            let prev1 = trace.get(0, i - 1);
            let prev2 = trace.get(0, i - 2);
            trace.update_row(i, &[prev1 + prev2]);
        }

        trace
    }
}

impl Prover for FibProver {
    type BaseField = BaseElement;
    type Air = FibAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(0, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
