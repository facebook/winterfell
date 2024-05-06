// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::*;
use air::LagrangeKernelRandElements;
use prover::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, RandomCoin},
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    matrix::ColMatrix,
};
use std::vec;
use std::vec::Vec;

const AUX_TRACE_WIDTH: usize = 2;

#[test]
fn test_complex_lagrange_kernel_air() {
    let trace = LagrangeComplexTrace::new(2_usize.pow(10), AUX_TRACE_WIDTH);

    let prover = LagrangeComplexProver::new(AUX_TRACE_WIDTH);

    let proof = prover.prove(trace).unwrap();

    verify::<
        LagrangeKernelComplexAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, (), &AcceptableOptions::MinConjecturedSecurity(0))
    .unwrap()
}

// LagrangeComplexTrace
// =================================================================================================

#[derive(Clone, Debug)]
struct LagrangeComplexTrace {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LagrangeComplexTrace {
    fn new(trace_len: usize, aux_segment_width: usize) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        let main_trace_col: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();

        Self {
            main_trace: ColMatrix::new(vec![main_trace_col]),
            info: TraceInfo::new_multi_segment(1, aux_segment_width, 0, trace_len, vec![]),
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LagrangeComplexTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main_trace
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = row_idx + 1;
        assert_ne!(next_row_idx, self.len());

        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }
}

// AIR
// =================================================================================================

#[derive(Debug, Clone, Default)]
struct DummyAuxProofVerifier;

impl AuxProofVerifier for DummyAuxProofVerifier {
    // `AuxProof` is log(trace_len) for this dummy example, so that the verifier knows how many aux
    // random variables to generate
    type AuxProof = usize;
    type Error = VerifierError;

    fn verify<E, Hasher>(
        &self,
        aux_proof: usize,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<LagrangeKernelRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: crypto::ElementHasher<BaseField = E::BaseField>,
    {
        let log_trace_len = aux_proof;
        let lagrange_kernel_rand_elements: LagrangeKernelRandElements<E> = {
            let mut rand_elements = Vec::with_capacity(log_trace_len);
            for _ in 0..log_trace_len {
                rand_elements.push(public_coin.draw().unwrap());
            }

            LagrangeKernelRandElements::new(rand_elements)
        };

        Ok(lagrange_kernel_rand_elements)
    }
}

struct LagrangeKernelComplexAir {
    context: AirContext<BaseElement>,
}

impl Air for LagrangeKernelComplexAir {
    type BaseField = BaseElement;
    // `AuxProof` is log(trace_len) for this dummy example, so that the verifier knows how many aux
    // random variables to generate
    type AuxProof = usize;
    type AuxProofVerifier = DummyAuxProofVerifier;

    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                vec![TransitionConstraintDegree::new(1)],
                1,
                1,
                Some(0),
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];

        // increments by 1
        result[0] = next - current - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &[E],
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &[E],
    ) -> Vec<Assertion<E>> {
        vec![Assertion::single(1, 0, E::ZERO)]
    }

    fn get_auxiliary_proof_verifier<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
    ) -> Self::AuxProofVerifier {
        DummyAuxProofVerifier
    }
}

// LagrangeComplexProver
// ================================================================================================

struct LagrangeComplexProver {
    aux_trace_width: usize,
    options: ProofOptions,
}

impl LagrangeComplexProver {
    fn new(aux_trace_width: usize) -> Self {
        Self {
            aux_trace_width,
            options: ProofOptions::new(1, 2, 0, FieldExtension::None, 2, 1),
        }
    }
}

impl Prover for LagrangeComplexProver {
    type BaseField = BaseElement;
    type Air = LagrangeKernelComplexAir;
    type Trace = LagrangeComplexTrace;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LagrangeKernelComplexAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>)
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn generate_aux_proof<E>(
        &self,
        main_trace: &Self::Trace,
        public_coin: &mut Self::RandomCoin,
    ) -> (ProverAuxProof<Self>, LagrangeKernelRandElements<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let main_trace = main_trace.main_segment();
        let log_trace_len = main_trace.num_rows().ilog2() as usize;
        let lagrange_kernel_rand_elements: Vec<E> = {
            let mut rand_elements = Vec::with_capacity(log_trace_len);
            for _ in 0..log_trace_len {
                rand_elements.push(public_coin.draw().unwrap());
            }

            rand_elements
        };

        (log_trace_len, LagrangeKernelRandElements::new(lagrange_kernel_rand_elements))
    }

    fn build_aux_trace<E>(
        &self,
        main_trace: &Self::Trace,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let main_trace = main_trace.main_segment();
        let lagrange_kernel_rand_elements = aux_rand_elements
            .lagrange()
            .expect("expected lagrange random elements to be present.");

        let mut columns = Vec::new();

        // first build the Lagrange kernel column
        {
            let r = &lagrange_kernel_rand_elements;

            let mut lagrange_col = Vec::with_capacity(main_trace.num_rows());

            for row_idx in 0..main_trace.num_rows() {
                let mut row_value = E::ONE;
                for (bit_idx, &r_i) in r.iter().enumerate() {
                    if row_idx & (1 << bit_idx) == 0 {
                        row_value *= E::ONE - r_i;
                    } else {
                        row_value *= r_i;
                    }
                }
                lagrange_col.push(row_value);
            }

            columns.push(lagrange_col);
        }

        // Then all other auxiliary columns
        let rand_summed = lagrange_kernel_rand_elements.iter().fold(E::ZERO, |acc, &r| acc + r);
        for _ in 1..self.aux_trace_width {
            // building a dummy auxiliary column
            let column = main_trace
                .get_column(0)
                .iter()
                .map(|row_val| rand_summed.mul_base(*row_val))
                .collect();

            columns.push(column);
        }

        ColMatrix::new(columns)
    }
}
