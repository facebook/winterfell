// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    verifier, DefaultProverChannel, DefaultVerifierChannel, FriOptions, FriProof, VerifierContext,
    VerifierError,
};
use crypto::{hashers::Blake3_256, PublicCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use utils::{Deserializable, Serializable, SliceReader};

// TEST UTILS
// ================================================================================================

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> DefaultProverChannel<BaseElement, BaseElement, Blake3_256<BaseElement>> {
    DefaultProverChannel::new(trace_length * options.blowup_factor(), 32)
}

pub fn build_evaluations(
    trace_length: usize,
    lde_blowup: usize,
    ce_blowup: usize,
) -> Vec<BaseElement> {
    let len = (trace_length * ce_blowup) as u128;
    let mut p = (0..len).map(BaseElement::new).collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, BaseElement::ZERO);

    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}

pub fn verify_proof(
    proof: FriProof,
    commitments: Vec<[u8; 32]>,
    evaluations: &[BaseElement],
    max_degree: usize,
    domain_size: usize,
    positions: &[usize],
    options: &FriOptions,
) -> Result<(), VerifierError> {
    // test proof serialization / deserialization
    let mut proof_bytes = Vec::new();
    proof.write_into(&mut proof_bytes);

    let mut reader = SliceReader::new(&proof_bytes);
    let proof = FriProof::read_from(&mut reader).unwrap();

    // verify the proof
    let mut channel = DefaultVerifierChannel::<BaseElement, Blake3_256<BaseElement>>::new(
        proof,
        domain_size,
        options.folding_factor(),
    )
    .unwrap();
    let mut coin = PublicCoin::<BaseElement, Blake3_256<BaseElement>>::new(&[]);
    let alphas = commitments
        .iter()
        .map(|&com| {
            coin.reseed(com);
            coin.draw().unwrap()
        })
        .collect::<Vec<BaseElement>>();
    let context = VerifierContext::<BaseElement, BaseElement, Blake3_256<BaseElement>>::new(
        evaluations.len(),
        max_degree,
        commitments,
        alphas,
        channel.num_partitions(),
        options.clone(),
    );
    let queried_evaluations = positions
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();
    verifier::verify(&context, &mut channel, &queried_evaluations, &positions)
}
