// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{rescue, BaseElement, FieldElement, HASH_CYCLE_LEN, HASH_STATE_WIDTH, TRACE_WIDTH};
use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use winterfell::{
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

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
            context: AirContext::new(trace_info, degrees, 4, options),
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
