// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, ExecutionTrace, Fib8Air, FieldElement, ProofOptions, Prover};

// FIBONACCI PROVER
// ================================================================================================

pub struct Fib8Prover {
    options: ProofOptions,
}

impl Fib8Prover {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 8 terms.
    pub fn build_trace(&self, length: usize) -> ExecutionTrace<BaseElement> {
        assert!(
            length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        // initialize the trace with 7th and 8th terms of Fibonacci sequence (skipping the first 6)
        let n0 = BaseElement::ONE;
        let n1 = BaseElement::ONE;
        let n2 = n0 + n1;
        let n3 = n1 + n2;
        let n4 = n2 + n3;
        let n5 = n3 + n4;
        let n6 = n4 + n5;
        let n7 = n5 + n6;

        let mut reg0 = vec![n6];
        let mut reg1 = vec![n7];

        for i in 0..(length / 8 - 1) {
            let n0 = reg0[i] + reg1[i];
            let n1 = reg1[i] + n0;
            let n2 = n0 + n1;
            let n3 = n1 + n2;
            let n4 = n2 + n3;
            let n5 = n3 + n4;
            let n6 = n4 + n5;
            let n7 = n5 + n6;

            reg0.push(n6);
            reg1.push(n7);
        }

        ExecutionTrace::init(vec![reg0, reg1])
    }
}

impl Prover for Fib8Prover {
    type BaseField = BaseElement;
    type Air = Fib8Air;
    type Trace = ExecutionTrace<BaseElement>;

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
