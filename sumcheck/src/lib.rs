// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![no_std]

use alloc::vec::Vec;

use ::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use math::FieldElement;

#[macro_use]
extern crate alloc;

#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

mod prover;
pub use prover::*;

mod verifier;
pub use verifier::*;

mod univariate;
pub use univariate::{CompressedUnivariatePoly, CompressedUnivariatePolyEvals};

mod multilinear;
pub use multilinear::{EqFunction, MultiLinearPoly};

/// Represents an opening claim at an evaluation point against a batch of oracles.
///
/// After verifying [`Proof`], the verifier is left with a question on the validity of a final
/// claim on a number of oracles open to a given set of values at some given point.
/// This question is answered either using further interaction with the Prover or using
/// a polynomial commitment opening proof in the compiled protocol.
#[derive(Clone, Debug)]
pub struct FinalOpeningClaim<E> {
    pub eval_point: Vec<E>,
    pub openings: Vec<E>,
}

impl<E: FieldElement> Serializable for FinalOpeningClaim<E> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { eval_point, openings } = self;
        eval_point.write_into(target);
        openings.write_into(target);
    }
}

impl<E> Deserializable for FinalOpeningClaim<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            eval_point: Deserializable::read_from(source)?,
            openings: Deserializable::read_from(source)?,
        })
    }
}

/// A sum-check proof.
///
/// Composed of the round proofs i.e., the polynomials sent by the Prover at each round as well as
/// the (claimed) openings of the multi-linear oracles at the evaluation point given by the round
/// challenges.
#[derive(Debug, Clone)]
pub struct SumCheckProof<E: FieldElement> {
    pub openings_claim: FinalOpeningClaim<E>,
    pub round_proofs: Vec<RoundProof<E>>,
}

impl<E> Serializable for SumCheckProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.openings_claim.write_into(target);
        self.round_proofs.write_into(target);
    }
}

impl<E> Deserializable for SumCheckProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            openings_claim: Deserializable::read_from(source)?,
            round_proofs: Deserializable::read_from(source)?,
        })
    }
}

/// A sum-check round proof.
///
/// This represents the partial polynomial sent by the Prover during one of the rounds of the
/// sum-check protocol. The polynomial is in coefficient form and excludes the coefficient for
/// the linear term as the Verifier can recover it from the other coefficients and the current
/// (reduced) claim.
#[derive(Debug, Clone)]
pub struct RoundProof<E: FieldElement> {
    pub round_poly_coefs: CompressedUnivariatePoly<E>,
}

impl<E: FieldElement> Serializable for RoundProof<E> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { round_poly_coefs } = self;
        round_poly_coefs.write_into(target);
    }
}

impl<E> Deserializable for RoundProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            round_poly_coefs: Deserializable::read_from(source)?,
        })
    }
}

/// A proof for the input circuit layer i.e., the final layer in the GKR protocol.
#[derive(Debug, Clone)]
pub struct FinalLayerProof<E: FieldElement> {
    pub proof: SumCheckProof<E>,
}

impl<E> Serializable for FinalLayerProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { proof } = self;
        proof.write_into(target);
    }
}

impl<E> Deserializable for FinalLayerProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            proof: Deserializable::read_from(source)?,
        })
    }
}

/// Contains the round challenges sent by the Verifier up to some round as well as the current
/// reduced claim.
#[derive(Debug)]
pub struct SumCheckRoundClaim<E: FieldElement> {
    pub eval_point: Vec<E>,
    pub claim: E,
}

// GKR CIRCUIT PROOF
// ===============================================================================================

/// A GKR proof for the correct evaluation of the sum of fractions circuit.
#[derive(Debug, Clone)]
pub struct GkrCircuitProof<E: FieldElement> {
    pub circuit_outputs: CircuitOutput<E>,
    pub before_final_layer_proofs: BeforeFinalLayerProof<E>,
    pub final_layer_proof: FinalLayerProof<E>,
}

impl<E: FieldElement> GkrCircuitProof<E> {
    pub fn get_final_opening_claim(&self) -> FinalOpeningClaim<E> {
        self.final_layer_proof.proof.openings_claim.clone()
    }
}

impl<E> Serializable for GkrCircuitProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.circuit_outputs.write_into(target);
        self.before_final_layer_proofs.write_into(target);
        self.final_layer_proof.proof.write_into(target);
    }
}

impl<E> Deserializable for GkrCircuitProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            circuit_outputs: CircuitOutput::read_from(source)?,
            before_final_layer_proofs: BeforeFinalLayerProof::read_from(source)?,
            final_layer_proof: FinalLayerProof::read_from(source)?,
        })
    }
}

/// A set of sum-check proofs for all GKR layers but for the input circuit layer.
#[derive(Debug, Clone)]
pub struct BeforeFinalLayerProof<E: FieldElement> {
    pub proof: Vec<SumCheckProof<E>>,
}

impl<E> Serializable for BeforeFinalLayerProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { proof } = self;
        proof.write_into(target);
    }
}

impl<E> Deserializable for BeforeFinalLayerProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            proof: Deserializable::read_from(source)?,
        })
    }
}

/// Holds the output layer of an [`EvaluatedCircuit`].
#[derive(Clone, Debug)]
pub struct CircuitOutput<E: FieldElement> {
    pub numerators: MultiLinearPoly<E>,
    pub denominators: MultiLinearPoly<E>,
}

impl<E> Serializable for CircuitOutput<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { numerators, denominators } = self;
        numerators.write_into(target);
        denominators.write_into(target);
    }
}

impl<E> Deserializable for CircuitOutput<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            numerators: MultiLinearPoly::read_from(source)?,
            denominators: MultiLinearPoly::read_from(source)?,
        })
    }
}

/// The non-linear composition polynomial of the LogUp-GKR protocol.
///
/// This is the result of batching the `p_k` and `q_k` of section 3.2 in
/// https://eprint.iacr.org/2023/1284.pdf.
fn comb_func<E: FieldElement>(p0: E, p1: E, q0: E, q1: E, eq: E, r_batch: E) -> E {
    (p0 * q1 + p1 * q0 + r_batch * q0 * q1) * eq
}

/// The non-linear composition polynomial of the LogUp-GKR protocol specific to the input layer.
pub fn evaluate_composition_poly<E: FieldElement>(
    eq_at_mu: &[E],
    numerators: &[E],
    denominators: &[E],
    eq_eval: E,
    r_sum_check: E,
) -> E {
    let numerators = MultiLinearPoly::from_evaluations(numerators.to_vec());
    let denominators = MultiLinearPoly::from_evaluations(denominators.to_vec());

    let (left_numerators, right_numerators) = numerators.project_least_significant_variable();
    let (left_denominators, right_denominators) = denominators.project_least_significant_variable();

    left_numerators
        .evaluations()
        .iter()
        .zip(
            right_numerators.evaluations().iter().zip(
                left_denominators
                    .evaluations()
                    .iter()
                    .zip(right_denominators.evaluations().iter().zip(eq_at_mu.iter())),
            ),
        )
        .map(|(p0, (p1, (q0, (q1, eq_w))))| {
            *eq_w * comb_func(*p0, *p1, *q0, *q1, eq_eval, r_sum_check)
        })
        .fold(E::ZERO, |acc, x| acc + x)
}
