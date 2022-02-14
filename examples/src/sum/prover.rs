// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, SumAir, FieldElement, ProofOptions, Prover, Trace, TraceTable,
};
use log::debug;

// Sumorial PROVER
// ================================================================================================

pub struct SumProver {
    options: ProofOptions,
}

impl SumProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 2 terms.
    pub fn build_trace(&self, sequence_length: usize) -> TraceTable<BaseElement> {
        debug!("building trace");
        // holds indexes
        let mut reg0 = vec![BaseElement::ZERO];
        let mut reg1 = vec![BaseElement::ZERO];

        for i in 1..sequence_length {
            let n0 = BaseElement::new(i.try_into().unwrap());
            let n1 = n0 + reg1[i-1];
            reg0.push(n0);
            reg1.push(n1);
        }

        TraceTable::init(vec![reg0, reg1])
    }
}

impl Prover for SumProver {
    type BaseField = BaseElement;
    type Air = SumAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        debug!("trace length is: {}", trace.length());
        trace.get(1, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
