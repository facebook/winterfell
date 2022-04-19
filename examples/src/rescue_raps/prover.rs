// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    rescue::{self, STATE_WIDTH},
    BaseElement, FieldElement, ProofOptions, Prover, PublicInputs, RapTraceTable, RescueRapsAir,
    Trace, CYCLE_LENGTH, NUM_HASH_ROUNDS,
};

// RESCUE PROVER
// ================================================================================================

pub struct RescueRapsProver {
    options: ProofOptions,
}

impl RescueRapsProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(
        &self,
        seed: [BaseElement; 2],
        result: ([BaseElement; 2], [BaseElement; 2]),
        iterations: usize,
    ) -> RapTraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = iterations * CYCLE_LENGTH;
        let mut trace = RapTraceTable::new(2 * STATE_WIDTH, trace_length);

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = seed[0];
                state[1] = seed[1];
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;

                // initialize intermediary state of the computation
                state[4] = result.0[0];
                state[5] = result.0[1];
                state[6] = BaseElement::ZERO;
                state[7] = BaseElement::ZERO;
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // for the first 14 steps in every cycle, compute a single round of
                // Rescue hash; for the remaining 2 rounds, just carry over the values
                // in the first two registers of the two chains to the next step
                if (step % CYCLE_LENGTH) < NUM_HASH_ROUNDS {
                    rescue::apply_round_parallel(state, step);
                } else {
                    state[2] = BaseElement::ZERO;
                    state[3] = BaseElement::ZERO;

                    state[6] = BaseElement::ZERO;
                    state[7] = BaseElement::ZERO;
                }
            },
        );

        debug_assert_eq!(trace.get(0, trace_length - 1), trace.get(4, 0));
        debug_assert_eq!(trace.get(1, trace_length - 1), trace.get(5, 0));

        debug_assert_eq!(trace.get(4, trace_length - 1), result.1[0]);
        debug_assert_eq!(trace.get(5, trace_length - 1), result.1[1]);

        trace
    }
}

impl Prover for RescueRapsProver {
    type BaseField = BaseElement;
    type Air = RescueRapsAir;
    type Trace = RapTraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            seed: [trace.get(0, 0), trace.get(1, 0)],
            result: [trace.get(4, last_step), trace.get(5, last_step)],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
