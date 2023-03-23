// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, DefaultRandomCoin, ElementHasher, Fib8Air, FieldElement, PhantomData,
    ProofOptions, Prover, Trace, TraceTable,
};

// FIBONACCI PROVER
// ================================================================================================

pub struct Fib8Prover<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> Fib8Prover<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            _hasher: PhantomData,
        }
    }

    /// Builds an execution trace for computing a Fibonacci sequence of the specified length such
    /// that each row advances the sequence by 8 terms.
    pub fn build_trace(&self, length: usize) -> TraceTable<BaseElement> {
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

        TraceTable::init(vec![reg0, reg1])
    }
}

impl<H: ElementHasher> Prover for Fib8Prover<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = Fib8Air;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(1, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
