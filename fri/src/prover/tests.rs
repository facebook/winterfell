// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{DefaultProverChannel, FriProver};
use crate::{
    verifier::{DefaultVerifierChannel, FriVerifier},
    FriOptions, FriProof, VerifierError,
};
use crypto::{hashers::Blake3_256, Hasher, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use utils::{collections::Vec, Deserializable, Serializable, SliceReader};

type Blake3 = Blake3_256<BaseElement>;

// PROVE/VERIFY TEST
// ================================================================================================

#[test]
fn fri_prove_verify() {
    let trace_length = 4096;
    let lde_blowup = 8;

    let options = FriOptions::new(lde_blowup, 4, 256);
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);

    // make sure the proof can be verified
    let commitments = channel.layer_commitments().to_vec();
    let max_degree = trace_length - 1;
    let result = verify_proof(
        proof.clone(),
        commitments.clone(),
        &evaluations,
        max_degree,
        trace_length * lde_blowup,
        &positions,
        &options,
    );
    assert!(result.is_ok(), "{:}", result.err().unwrap());

    // make sure proof fails for invalid degree
    let result = verify_proof(
        proof,
        commitments,
        &evaluations,
        max_degree - 256,
        trace_length * lde_blowup,
        &positions,
        &options,
    );
    assert!(result.is_err());
}

// TEST UTILS
// ================================================================================================

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> DefaultProverChannel<BaseElement, BaseElement, Blake3> {
    DefaultProverChannel::new(trace_length * options.blowup_factor(), 32)
}

pub fn build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<BaseElement> {
    let mut p = (0..trace_length as u128)
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, BaseElement::ZERO);

    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}

pub fn verify_proof(
    proof: FriProof,
    commitments: Vec<<Blake3 as Hasher>::Digest>,
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
    let mut channel = DefaultVerifierChannel::<BaseElement, Blake3>::new(
        proof,
        commitments,
        domain_size,
        options.folding_factor(),
    )
    .unwrap();
    let mut coin = RandomCoin::<BaseElement, Blake3>::new(&[]);
    let verifier = FriVerifier::new(&mut channel, &mut coin, options.clone(), max_degree).unwrap();
    let queried_evaluations = positions
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();
    verifier.verify(&mut channel, &queried_evaluations, &positions)
}
