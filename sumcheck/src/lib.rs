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

mod prover;
pub use prover::*;

mod verifier;
pub use verifier::*;

mod utils;
pub use utils::*;

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

/// Contains the round challenges sent by the Verifier up to some round as well as the current
/// reduced claim.
#[derive(Debug)]
pub struct SumCheckRoundClaim<E: FieldElement> {
    pub eval_point: Vec<E>,
    pub claim: E,
}

/// The non-linear composition polynomial of the LogUp-GKR protocol specific to the input layer.
pub fn evaluate_composition_poly<E: FieldElement>(
    numerators: &[E],
    denominators: &[E],
    eq_eval: E,
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> E {
    let numerators = MultiLinearPoly::from_evaluations(numerators.to_vec());
    let denominators = MultiLinearPoly::from_evaluations(denominators.to_vec());

    let (left_numerators, right_numerators) = numerators.project_least_significant_variable();
    let (left_denominators, right_denominators) = denominators.project_least_significant_variable();

    let eval_left_numerators =
        left_numerators.evaluate_with_lagrange_kernel(tensored_merge_randomness);
    let eval_right_numerators =
        right_numerators.evaluate_with_lagrange_kernel(tensored_merge_randomness);

    let eval_left_denominators =
        left_denominators.evaluate_with_lagrange_kernel(tensored_merge_randomness);
    let eval_right_denominators =
        right_denominators.evaluate_with_lagrange_kernel(tensored_merge_randomness);

    eq_eval
        * ((eval_left_numerators * eval_right_denominators
            + eval_right_numerators * eval_left_denominators)
            + eval_left_denominators * eval_right_denominators * r_sum_check)
}
