// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{RoundProof, SumCheckRoundClaim};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

/// Verifies a round of the sum-check protocol.
pub fn verify_rounds<E, C, H>(
    claim: E,
    round_proofs: &[RoundProof<E>],
    coin: &mut C,
) -> Result<SumCheckRoundClaim<E>, SumCheckVerifierError>
where
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut round_claim = claim;
    let mut evaluation_point = vec![];
    for round_proof in round_proofs {
        let round_poly_coefs = round_proof.round_poly_coefs.clone();
        coin.reseed(H::hash_elements(&round_poly_coefs.0));

        let r = coin.draw().map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

        round_claim = round_proof.round_poly_coefs.evaluate_using_claim(&round_claim, &r);
        evaluation_point.push(r);
    }

    Ok(SumCheckRoundClaim {
        eval_point: evaluation_point,
        claim: round_claim,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum SumCheckVerifierError {
    #[error("the final evaluation check of sum-check failed")]
    FinalEvaluationCheckFailed,
    #[error("failed to generate round challenge")]
    FailedToGenerateChallenge,
    #[error("wrong opening point for the oracles")]
    WrongOpeningPoint,
}
