// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use super::{
    rescue, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, MerkleAir, PhantomData,
    ProofOptions, Prover, PublicInputs, HASH_CYCLE_LEN, HASH_STATE_WIDTH, NUM_HASH_ROUNDS,
    TRACE_WIDTH,
};

// MERKLE PROVER
// ================================================================================================

pub struct MerkleProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MerkleProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    pub fn build_trace(
        &self,
        value: [BaseElement; 2],
        branch: &[rescue::Hash],
        index: usize,
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = branch.len() * HASH_CYCLE_LEN;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        // skip the first node of the branch because it will be computed in the trace as hash(value)
        let branch = &branch[1..];

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = value[0];
                state[1] = value[1];
                state[2..].fill(BaseElement::ZERO);
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // For the first 7 steps of each 8-step cycle, compute a single round of Rescue
                // hash in registers [0..6]. On the 8th step, insert the next branch node into the
                // trace in the positions defined by the next bit of the leaf index. If the bit is
                // ZERO, the next node goes into registers [2, 3], if it is ONE, the node goes into
                // registers [0, 1].

                let cycle_num = step / HASH_CYCLE_LEN;
                let cycle_pos = step % HASH_CYCLE_LEN;

                if cycle_pos < NUM_HASH_ROUNDS {
                    rescue::apply_round(&mut state[..HASH_STATE_WIDTH], step);
                } else {
                    let branch_node = branch[cycle_num].to_elements();
                    let index_bit = BaseElement::new(((index >> cycle_num) & 1) as u128);
                    if index_bit == BaseElement::ZERO {
                        // if index bit is zero, new branch node goes into registers [2, 3]; values
                        // in registers [0, 1] (the accumulated hash) remain unchanged
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
            },
        );

        // set index bit at the second step to one; this still results in a valid execution trace
        // because actual index bits are inserted into the trace after step 7, but it ensures
        // that there are no repeating patterns in the index bit register, and thus the degree
        // of the index bit constraint is stable.
        trace.set(6, 1, FieldElement::ONE);

        trace
    }
}

impl<H: ElementHasher> Prover for MerkleProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            tree_root: [trace.get(0, last_step), trace.get(1, last_step)],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}
