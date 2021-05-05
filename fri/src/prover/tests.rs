// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    verifier, DefaultProverChannel, DefaultVerifierChannel, FriOptions, FriProof, VerifierChannel,
    VerifierContext, VerifierError,
};
use crypto::hash;
use math::{
    fft,
    field::{f128::BaseElement, FieldElement, StarkField},
    utils::{get_power_series_with_offset, log2},
};

// TEST UTILS
// ================================================================================================

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions<BaseElement>,
) -> DefaultProverChannel<hash::Blake3_256> {
    DefaultProverChannel::new(trace_length * options.blowup_factor(), 32)
}

pub fn build_lde_domain(
    trace_length: usize,
    lde_blowup: usize,
    offset: BaseElement,
) -> Vec<BaseElement> {
    let domain_size = trace_length * lde_blowup;
    let g = BaseElement::get_root_of_unity(log2(domain_size));
    get_power_series_with_offset(g, offset, domain_size)
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
    options: &FriOptions<BaseElement>,
) -> Result<(), VerifierError> {
    let channel = DefaultVerifierChannel::<BaseElement, hash::Blake3_256>::new(
        proof,
        commitments,
        domain_size,
    )
    .unwrap();
    let context = VerifierContext::new(
        evaluations.len(),
        max_degree,
        channel.num_fri_partitions(),
        options.clone(),
    );
    let queried_evaluations = positions
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();
    verifier::verify(&context, &channel, &queried_evaluations, &positions)
}
