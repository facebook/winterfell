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
    BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, MulFib8Air, PhantomData,
    ProofOptions, Prover,
};

// FIBONACCI PROVER
// ================================================================================================

pub struct MulFib8Prover<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MulFib8Prover<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    /// Builds an execution trace for computing a multiplicative version of a Fibonacci sequence of
    /// the specified length such that each row advances the sequence by 8 terms.
    pub fn build_trace(&self, length: usize) -> TraceTable<BaseElement> {
        assert!(length.is_power_of_two(), "sequence length must be a power of 2");

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

impl<H: ElementHasher> Prover for MulFib8Prover<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = MulFib8Air;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(6, last_step)
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
