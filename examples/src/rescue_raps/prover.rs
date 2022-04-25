// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    apply_rescue_round_parallel, rescue::STATE_WIDTH, BaseElement, FieldElement, ProofOptions,
    Prover, PublicInputs, RapTraceTable, RescueRapsAir, Trace, CYCLE_LENGTH, NUM_HASH_ROUNDS,
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
        seeds: &[[BaseElement; 2]],
        permuted_seeds: &[[BaseElement; 2]],
        result: [[BaseElement; 2]; 2],
    ) -> RapTraceTable<BaseElement> {
        debug_assert_eq!(seeds.len(), permuted_seeds.len());
        // allocate memory to hold the trace table
        let trace_length = seeds.len() * CYCLE_LENGTH;
        let mut trace = RapTraceTable::new(2 * STATE_WIDTH, trace_length);
        const END_INCLUSIVE_RANGE: usize = NUM_HASH_ROUNDS - 1;

        trace.fill(
            |state| {
                // initialize original chain
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = seeds[0][0];
                state[3] = seeds[0][1];

                // initialize permuted chain
                state[4] = BaseElement::ZERO;
                state[5] = BaseElement::ZERO;
                state[6] = permuted_seeds[0][0];
                state[7] = permuted_seeds[0][1];
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // for the first 14 steps in every cycle, compute a single round of
                // Rescue hash; for the remaining 2 rounds, carry over the values
                // in the first two registers of the two chains to the next step
                // and insert the additional seeds into the capacity registers
                match step % CYCLE_LENGTH {
                    0..=END_INCLUSIVE_RANGE => apply_rescue_round_parallel(state, step),
                    _ => {
                        let idx = step / CYCLE_LENGTH + 1;
                        // We don't have seeds for the final step once last hashing is done.
                        if idx < seeds.len() {
                            state[2] = seeds[idx][0];
                            state[3] = seeds[idx][1];

                            state[6] = permuted_seeds[idx][0];
                            state[7] = permuted_seeds[idx][1];
                        }
                    }
                };
            },
        );

        debug_assert_eq!(trace.get(0, trace_length - 1), result[0][0]);
        debug_assert_eq!(trace.get(1, trace_length - 1), result[0][1]);

        debug_assert_eq!(trace.get(4, trace_length - 1), result[1][0]);
        debug_assert_eq!(trace.get(5, trace_length - 1), result[1][1]);

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
            result: [
                [trace.get(0, last_step), trace.get(1, last_step)],
                [trace.get(4, last_step), trace.get(5, last_step)],
            ],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
