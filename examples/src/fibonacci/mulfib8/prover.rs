// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, MulFib8Air, ProofOptions, Prover, Trace, TraceTable};

// FIBONACCI PROVER
// ================================================================================================

pub struct MulFib8Prover {
    options: ProofOptions,
}

impl MulFib8Prover {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a multiplicative version of a Fibonacci sequence of
    /// the specified length such that each row advances the sequence by 8 terms.
    pub fn build_trace(&self, length: usize) -> TraceTable<BaseElement> {
        assert!(
            length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        let mut reg0 = vec![BaseElement::new(1)];
        let mut reg1 = vec![BaseElement::new(2)];
        let mut reg2 = vec![reg0[0] * reg1[0]];
        let mut reg3 = vec![reg1[0] * reg2[0]];
        let mut reg4 = vec![reg2[0] * reg3[0]];
        let mut reg5 = vec![reg3[0] * reg4[0]];
        let mut reg6 = vec![reg4[0] * reg5[0]];
        let mut reg7 = vec![reg5[0] * reg6[0]];

        for i in 0..(length / 8 - 1) {
            reg0.push(reg6[i] * reg7[i]);
            reg1.push(reg7[i] * reg0[i + 1]);
            reg2.push(reg0[i + 1] * reg1[i + 1]);
            reg3.push(reg1[i + 1] * reg2[i + 1]);
            reg4.push(reg2[i + 1] * reg3[i + 1]);
            reg5.push(reg3[i + 1] * reg4[i + 1]);
            reg6.push(reg4[i + 1] * reg5[i + 1]);
            reg7.push(reg5[i + 1] * reg6[i + 1]);
        }

        TraceTable::init(vec![reg0, reg1, reg2, reg3, reg4, reg5, reg6, reg7])
    }
}

impl Prover for MulFib8Prover {
    type BaseField = BaseElement;
    type Air = MulFib8Air;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(6, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
