// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::{
    are_equal, is_binary, is_zero, not,
    rescue::{
        self, CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS,
        STATE_WIDTH as HASH_STATE_WIDTH,
    },
    EvaluationResult,
};
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable,
    TraceBuilder, TraceInfo, TraceTable, TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 7;

// MERKLE PATH VERIFICATION AIR
// ================================================================================================

pub struct PublicInputs {
    pub tree_root: [BaseElement; 2],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.tree_root[..]);
    }
}

pub struct MerkleAir {
    context: AirContext<BaseElement>,
    tree_root: [BaseElement; 2],
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::new(2),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        MerkleAir {
            context: AirContext::new(trace_info, degrees, options),
            tree_root: pub_inputs.tree_root,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into masks and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..];

        // when hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(
            result,
            &current[..HASH_STATE_WIDTH],
            &next[..HASH_STATE_WIDTH],
            ark,
            hash_flag,
        );

        // when hash_flag = 0, make sure accumulated hash is placed in the right place in the hash
        // state for the next round of hashing. Specifically: when index bit = 0 accumulated hash
        // must go into registers [0, 1], and when index bit = 0, it must go into registers [2, 3]
        let hash_init_flag = not(hash_flag);
        let bit = next[6];
        let not_bit = not(bit);
        result.agg_constraint(0, hash_init_flag, not_bit * are_equal(current[0], next[0]));
        result.agg_constraint(1, hash_init_flag, not_bit * are_equal(current[1], next[1]));
        result.agg_constraint(2, hash_init_flag, bit * are_equal(current[0], next[2]));
        result.agg_constraint(3, hash_init_flag, bit * are_equal(current[1], next[3]));

        // make sure capacity registers of the hash state are reset to zeros
        result.agg_constraint(4, hash_init_flag, is_zero(next[4]));
        result.agg_constraint(5, hash_init_flag, is_zero(next[5]));

        // finally, we always enforce that values in the bit register must be binary
        result[6] = is_binary(current[6]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // assert that Merkle path resolves to the tree root, and that hash capacity
        // registers (registers 4 and 5) are reset to ZERO every 8 steps
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, last_step, self.tree_root[0]),
            Assertion::single(1, last_step, self.tree_root[1]),
            Assertion::periodic(4, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(5, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![HASH_CYCLE_MASK.to_vec()];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

// TRACE GENERATOR
// ================================================================================================

pub struct MerkleTraceBuilder {
    trace_info: TraceInfo,
    value: [BaseElement; 2],
    branch: Vec<rescue::Hash>,
    index: usize,
}

impl MerkleTraceBuilder {
    pub fn new(value: [BaseElement; 2], branch: &[rescue::Hash], index: usize) -> Self {
        assert!(
            branch.len().is_power_of_two(),
            "branch length must be a power of 2"
        );

        // build trace info
        let trace_length = branch.len() * HASH_CYCLE_LEN;
        let trace_info = TraceInfo::new(TRACE_WIDTH, trace_length);

        // skip the first node of the branch because it will be computed in the trace as hash(value)
        Self {
            trace_info,
            value,
            branch: branch[1..].to_vec(),
            index,
        }
    }
}

impl TraceBuilder for MerkleTraceBuilder {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    fn build_trace(&self) -> TraceTable<Self::BaseField> {
        // allocate memory to hold the trace table
        let mut trace = unsafe { TraceTable::new_blank(TRACE_WIDTH, self.trace_info().length()) };

        // fill the trace with data
        let mut state = [BaseElement::ZERO; TRACE_WIDTH];
        self.init_state(&mut state, 0);
        trace.update_row(0, &mut state);

        for step in 0..trace.length() - 1 {
            self.update_state(&mut state, step, 0);
            trace.update_row(step + 1, &state);
        }

        // set index bit at the second step to one; this still results in a valid execution trace
        // because actual index bits are inserted into the trace after step 7, but it ensures
        // that there are no repeating patterns in the index bit register, and thus the degree
        // of the index bit constraint is stable.
        trace.set(6, 1, FieldElement::ONE);

        trace
    }

    /// Initializes first state of the computation.
    ///
    /// We don't care about segment index here because the trace consists of a single segment.
    /// Thus, `segment` parameter is always 0.
    fn init_state(&self, state: &mut [Self::BaseField], _segment: usize) {
        state[0] = self.value[0];
        state[1] = self.value[1];
        state[2..].fill(BaseElement::ZERO);
    }

    /// Executes the transition function for all steps.
    ///
    /// For the first 7 steps of each 8-step cycle, compute a single round of Rescue hash in
    /// registers [0..6]. On the 8th step, insert the next branch node into the trace in the
    /// positions defined by the next bit of the leaf index. If the bit is ZERO, the next node
    /// goes into registers [2, 3], if it is ONE, the node goes into registers [0, 1].
    ///
    /// We don't care about segment index here because the trace consists of a single segment.
    /// Thus, `segment` parameter is always 0.
    fn update_state(&self, state: &mut [Self::BaseField], step: usize, _segment: usize) {
        let cycle_num = step / HASH_CYCLE_LEN;
        let cycle_pos = step % HASH_CYCLE_LEN;

        if cycle_pos < NUM_HASH_ROUNDS {
            rescue::apply_round(&mut state[..HASH_STATE_WIDTH], step);
        } else {
            let branch_node = self.branch[cycle_num].to_elements();
            let index_bit = BaseElement::new(((self.index >> cycle_num) & 1) as u128);
            if index_bit == BaseElement::ZERO {
                // if index bit is zero, new branch node goes into registers [2, 3]; values in
                // registers [0, 1] (the accumulated hash) remain unchanged
                state[2] = branch_node[0];
                state[3] = branch_node[1];
            } else {
                // if index bit is one, accumulated hash goes into registers [2, 3],
                // and new branch nodes goes into registers [0, 1]
                state[2] = state[0];
                state[3] = state[1];
                state[0] = branch_node[0];
                state[1] = branch_node[1];
            }
            // reset the capacity registers of the state to ZERO
            state[4] = BaseElement::ZERO;
            state[5] = BaseElement::ZERO;

            state[6] = index_bit;
        }
    }

    fn get_pub_inputs(&self, trace: &TraceTable<Self::BaseField>) -> Self::PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            tree_root: [trace.get(0, last_step), trace.get(1, last_step)],
        }
    }
}

// MASKS
// ================================================================================================
const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];
