// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, FactAir, FieldElement, ProofOptions, Prover, Trace, TraceTable,
};
use log::debug;

// Factorial PROVER
// ================================================================================================

pub struct FactProver {
    options: ProofOptions,
}

impl FactProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 2 terms.
    pub fn build_trace(&self, sequence_length: usize) -> TraceTable<BaseElement> {
        debug!("building trace");
        // holds indexes
        let mut reg0 = vec![BaseElement::ZERO , BaseElement::ONE];
        // holds results - start with 0! == 1
        let mut reg1 = vec![BaseElement::ONE, BaseElement::ONE];

        for i in 2..sequence_length {
            let n0 = BaseElement::new(i.try_into().unwrap());
            let n1 = n0 * reg1[i-1];
            reg0.push(n0);
            reg1.push(n1);
        }
        debug!("trace length is: {}", reg0.len());

        TraceTable::init(vec![reg0, reg1])
    }
}

impl Prover for FactProver {
    type BaseField = BaseElement;
    type Air = FactAir;
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
