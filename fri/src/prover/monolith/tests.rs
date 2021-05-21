// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    super::tests::{build_evaluations, build_lde_domain, build_prover_channel, verify_proof},
    FriProver,
};
use crate::FriOptions;
use math::field::{f128::BaseElement, StarkField};

#[test]
fn sequential_fri_prove_verify() {
    let trace_length = 4096;
    let ce_blowup = 2;
    let lde_blowup = 8;
    let offset = BaseElement::GENERATOR;

    let options = FriOptions::new(lde_blowup, offset);
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup, ce_blowup);
    let lde_domain = build_lde_domain(trace_length, lde_blowup, offset);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone(), &lde_domain);
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);

    // make sure the proof can be verified
    let commitments = channel.fri_layer_commitments().to_vec();
    let max_degree = trace_length * ce_blowup - 1;
    let result = verify_proof(
        proof,
        commitments,
        &evaluations,
        max_degree,
        lde_domain.len(),
        &positions,
        &options,
    );
    assert!(result.is_ok(), "{:}", result.err().unwrap());
}
