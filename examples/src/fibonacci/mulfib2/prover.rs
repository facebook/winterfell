// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, MulFib2Air, ProofOptions, Prover, Trace, TraceTable};

// FIBONACCI PROVER
// ================================================================================================

pub struct MulFib2Prover {
    options: ProofOptions,
}

impl MulFib2Prover {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a multiplicative version of a Fibonacci sequence of
    /// the specified length such that each row advances the sequence by 2 terms.
    pub fn build_trace(&self, length: usize) -> TraceTable<BaseElement> {
        assert!(
            length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        let mut reg0 = vec![BaseElement::new(1)];
        let mut reg1 = vec![BaseElement::new(2)];

        for i in 0..(length / 2 - 1) {
            reg0.push(reg0[i] * reg1[i]);
            reg1.push(reg1[i] * reg0[i + 1]);
        }

        TraceTable::init(vec![reg0, reg1])
    }
}

impl Prover for MulFib2Prover {
    type BaseField = BaseElement;
    type Air = MulFib2Air;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(0, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
