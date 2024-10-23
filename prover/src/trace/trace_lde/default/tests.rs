// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::PartitionOptions;
use crypto::{hashers::Blake3_256, ElementHasher, MerkleTree};
use math::{
    fields::f128::BaseElement, get_power_series, get_power_series_with_offset, polynom,
    FieldElement, StarkField,
};

use crate::{
    tests::{build_fib_trace, MockAir},
    DefaultTraceLde, StarkDomain, Trace, TraceLde,
};

type Blake3 = Blake3_256<BaseElement>;

#[test]
fn extend_trace_table() {
    // build the trace and the domain
    let trace_length = 8;
    let air = MockAir::with_trace_length(trace_length);
    let trace = build_fib_trace(trace_length * 2);
    let domain = StarkDomain::new(&air);
    let partition_option = PartitionOptions::default();

    // build the trace polynomials, extended trace, and commitment using the default TraceLde impl
    let (trace_lde, trace_polys) = DefaultTraceLde::<BaseElement, Blake3, MerkleTree<Blake3>>::new(
        trace.info(),
        trace.main_segment(),
        &domain,
        partition_option,
    );

    // check the width and length of the extended trace
    assert_eq!(2, trace_lde.main_segment_width());
    assert_eq!(64, trace_lde.trace_len());

    // make sure trace polynomials evaluate to Fibonacci trace
    let trace_root = BaseElement::get_root_of_unity(trace_length.ilog2());
    let trace_domain = get_power_series(trace_root, trace_length);
    assert_eq!(2, trace_polys.num_main_trace_polys());
    assert_eq!(
        vec![1u32, 2, 5, 13, 34, 89, 233, 610]
            .into_iter()
            .map(BaseElement::from)
            .collect::<Vec<BaseElement>>(),
        polynom::eval_many(trace_polys.get_main_trace_poly(0), &trace_domain)
    );
    assert_eq!(
        vec![1u32, 3, 8, 21, 55, 144, 377, 987]
            .into_iter()
            .map(BaseElement::from)
            .collect::<Vec<BaseElement>>(),
        polynom::eval_many(trace_polys.get_main_trace_poly(1), &trace_domain)
    );

    // make sure column values are consistent with trace polynomials
    let lde_domain = build_lde_domain(domain.lde_domain_size());
    assert_eq!(
        trace_polys.get_main_trace_poly(0),
        polynom::interpolate(&lde_domain, &trace_lde.get_main_segment_column(0), true)
    );
    assert_eq!(
        trace_polys.get_main_trace_poly(1),
        polynom::interpolate(&lde_domain, &trace_lde.get_main_segment_column(1), true)
    );
}

#[test]
fn commit_trace_table() {
    // build the trace and the domain
    let trace_length = 8;
    let air = MockAir::with_trace_length(trace_length);
    let trace = build_fib_trace(trace_length * 2);
    let domain = StarkDomain::new(&air);
    let partition_option = PartitionOptions::default();

    // build the trace polynomials, extended trace, and commitment using the default TraceLde impl
    let (trace_lde, _) = DefaultTraceLde::<BaseElement, Blake3, MerkleTree<Blake3>>::new(
        trace.info(),
        trace.main_segment(),
        &domain,
        partition_option,
    );

    // build commitment, using a Merkle tree, to the trace rows
    let mut hashed_states = Vec::new();
    let mut trace_state = vec![BaseElement::ZERO; trace_lde.main_segment_width()];
    #[allow(clippy::needless_range_loop)]
    for i in 0..trace_lde.trace_len() {
        for j in 0..trace_lde.main_segment_width() {
            trace_state[j] = trace_lde.get_main_segment().get(j, i);
        }
        let buf = Blake3::hash_elements(&trace_state);
        hashed_states.push(buf);
    }
    let expected_tree = MerkleTree::<Blake3>::new(hashed_states).unwrap();

    // compare the result
    assert_eq!(*expected_tree.root(), trace_lde.get_main_trace_commitment())
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_lde_domain<B: StarkField>(domain_size: usize) -> Vec<B> {
    let g = B::get_root_of_unity(domain_size.ilog2());
    get_power_series_with_offset(g, B::GENERATOR, domain_size)
}
