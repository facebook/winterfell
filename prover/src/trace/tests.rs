// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    tests::{build_fib_trace, MockAir},
    StarkDomain,
};
use crypto::{hashers::Blake3_256, ElementHasher, MerkleTree};
use math::{
    fields::f128::BaseElement, get_power_series, get_power_series_with_offset, log2, polynom,
    FieldElement, StarkField,
};
use utils::collections::Vec;

type Blake3 = Blake3_256<BaseElement>;

#[test]
fn new_trace_table() {
    let trace_length = 8;
    let trace = build_fib_trace(trace_length * 2);

    assert_eq!(2, trace.width());
    assert_eq!(8, trace.length());

    let expected: Vec<BaseElement> = vec![1u32, 2, 5, 13, 34, 89, 233, 610]
        .into_iter()
        .map(BaseElement::from)
        .collect();
    assert_eq!(expected, trace.get_register(0));

    let expected: Vec<BaseElement> = vec![1u32, 3, 8, 21, 55, 144, 377, 987]
        .into_iter()
        .map(BaseElement::from)
        .collect();
    assert_eq!(expected, trace.get_register(1));
}

#[test]
fn extend_trace_table() {
    // build and extend trace table
    let trace_length = 8;
    let air = MockAir::with_trace_length(trace_length);
    let trace = build_fib_trace(trace_length * 2);
    let domain = StarkDomain::new(&air);
    let (extended_trace, trace_polys) = trace.extend(&domain);

    assert_eq!(2, extended_trace.width());
    assert_eq!(64, extended_trace.len());

    // make sure trace polynomials evaluate to Fibonacci trace
    let trace_root = BaseElement::get_root_of_unity(log2(trace_length));
    let trace_domain = get_power_series(trace_root, trace_length);
    assert_eq!(2, trace_polys.num_polys());
    assert_eq!(
        vec![1u32, 2, 5, 13, 34, 89, 233, 610]
            .into_iter()
            .map(BaseElement::from)
            .collect::<Vec<BaseElement>>(),
        polynom::eval_many(trace_polys.get_poly(0), &trace_domain)
    );
    assert_eq!(
        vec![1u32, 3, 8, 21, 55, 144, 377, 987]
            .into_iter()
            .map(BaseElement::from)
            .collect::<Vec<BaseElement>>(),
        polynom::eval_many(trace_polys.get_poly(1), &trace_domain)
    );

    // make sure column values are consistent with trace polynomials
    let lde_domain = build_lde_domain(domain.lde_domain_size());
    assert_eq!(
        trace_polys.get_poly(0),
        polynom::interpolate(&lde_domain, extended_trace.get_column(0), true)
    );
    assert_eq!(
        trace_polys.get_poly(1),
        polynom::interpolate(&lde_domain, extended_trace.get_column(1), true)
    );
}

#[test]
fn commit_trace_table() {
    // build and extend trace table
    let trace_length = 8;
    let air = MockAir::with_trace_length(trace_length);
    let trace = build_fib_trace(trace_length * 2);
    let domain = StarkDomain::new(&air);
    let (extended_trace, _) = trace.extend(&domain);

    // commit to the trace
    let trace_tree = extended_trace.build_commitment::<Blake3>();

    // build Merkle tree from trace rows
    let mut hashed_states = Vec::new();
    let mut trace_state = vec![BaseElement::ZERO; extended_trace.width()];
    #[allow(clippy::needless_range_loop)]
    for i in 0..extended_trace.len() {
        for j in 0..extended_trace.width() {
            trace_state[j] = extended_trace.get(j, i);
        }
        let buf = Blake3::hash_elements(&trace_state);
        hashed_states.push(buf);
    }
    let expected_tree = MerkleTree::<Blake3>::new(hashed_states).unwrap();

    // compare the result
    assert_eq!(expected_tree.root(), trace_tree.root())
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_lde_domain<B: StarkField>(domain_size: usize) -> Vec<B> {
    let g = B::get_root_of_unity(log2(domain_size));
    get_power_series_with_offset(g, B::GENERATOR, domain_size)
}
