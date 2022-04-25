// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    super::tests::{build_prng, build_sequence_poly},
    Assertion, BoundaryConstraint,
};
use crypto::{hashers::Blake3_256, RandomCoin};
use math::{fields::f128::BaseElement, log2, polynom, FieldElement, StarkField};
use rand_utils::{rand_value, rand_vector, shuffle};
use utils::collections::{BTreeMap, Vec};

// BOUNDARY CONSTRAINT TESTS
// ================================================================================================

#[test]
fn boundary_constraint_from_single_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, step 0
    let value = rand_value::<BaseElement>();
    let assertion = Assertion::single(0, 0, value);
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(vec![value], constraint.poly());
    assert_eq!((0, BaseElement::ONE), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );

    // single value constraints should evaluate to trace_value - value
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - value,
        constraint.evaluate_at(rand_value::<BaseElement>(), trace_value)
    );

    // constraint is build correctly for column 1 step 8
    let value = rand_value::<BaseElement>();
    let assertion = Assertion::single(1, 8, value);
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(1, constraint.column());
    assert_eq!(vec![value], constraint.poly());
    assert_eq!((0, BaseElement::ONE), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );

    // single value constraints should evaluate to trace_value - value
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - value,
        constraint.evaluate_at(rand_value::<BaseElement>(), trace_value)
    );

    // twiddle map was not touched
    assert!(twiddle_map.is_empty());
}

#[test]
fn boundary_constraint_from_periodic_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, step 0, stride 4
    let value = rand_value::<BaseElement>();
    let assertion = Assertion::periodic(0, 0, 4, value);
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(vec![value], constraint.poly());
    assert_eq!((0, BaseElement::ONE), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );

    // periodic value constraints should evaluate to trace_value - value
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - value,
        constraint.evaluate_at(rand_value::<BaseElement>(), trace_value)
    );

    // constraint should be built correctly for column 2, first step 3, stride 8
    let value = rand_value::<BaseElement>();
    let assertion = Assertion::periodic(2, 3, 8, value);
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(2, constraint.column());
    assert_eq!(vec![value], constraint.poly());
    assert_eq!((0, BaseElement::ONE), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );

    // periodic value constraints should evaluate to trace_value - value
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - value,
        constraint.evaluate_at(rand_value::<BaseElement>(), trace_value)
    );

    // twiddle map was not touched
    assert!(twiddle_map.is_empty());
}

#[test]
fn boundary_constraint_from_sequence_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, first step 0, stride 4
    let values = rand_vector::<BaseElement>(4);
    let constraint_poly = build_sequence_poly(&values, 16);
    let assertion = Assertion::sequence(0, 0, 4, values);
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(constraint_poly, constraint.poly());
    assert_eq!((0, BaseElement::ONE), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );
    assert_eq!(1, twiddle_map.len());

    // sequence value constraints with no offset should evaluate to
    // trace_value - constraint_poly(x)
    let x = rand_value::<BaseElement>();
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - polynom::eval(&constraint_poly, x),
        constraint.evaluate_at(x, trace_value)
    );

    // constraint should be built correctly for column 0, first step 3, stride 8
    let values = rand_vector::<BaseElement>(2);
    let constraint_poly = build_sequence_poly(&values, 16);
    let assertion = Assertion::sequence(0, 3, 8, values.clone());
    let constraint = BoundaryConstraint::<BaseElement, BaseElement>::new(
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw_pair().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(constraint_poly, constraint.poly());
    assert_eq!((3, inv_g.exp(3)), constraint.poly_offset());
    assert_eq!(
        &test_prng.draw_pair::<BaseElement>().unwrap(),
        constraint.cc()
    );
    assert_eq!(2, twiddle_map.len());

    // sequence value constraints with offset should evaluate to
    // trace_value - constraint_poly(x * offset)
    let x = rand_value::<BaseElement>();
    let trace_value = rand_value::<BaseElement>();
    assert_eq!(
        trace_value - polynom::eval(&constraint_poly, x * constraint.poly_offset().1),
        constraint.evaluate_at(x, trace_value)
    );
}

// PREPARE ASSERTIONS
// ================================================================================================

#[test]
fn prepare_assertions() {
    let values = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let mut assertions = vec![
        Assertion::single(0, 9, BaseElement::new(5)), // column 0, step 9
        Assertion::single(0, 0, BaseElement::new(3)), // column 0, step 0
        Assertion::sequence(0, 3, 4, values.clone()), // column 1, steps 2, 6, 10, 14
        Assertion::sequence(0, 2, 4, values.clone()), // column 0, steps 2, 6, 10, 14
        Assertion::periodic(1, 3, 8, BaseElement::new(7)), // column 1, steps 3, 11
        Assertion::sequence(1, 0, 8, values[..2].to_vec()), // column 1, steps 0, 8
    ];

    // assertions should be sorted by stride, first step, and column
    let expected = vec![
        Assertion::single(0, 0, BaseElement::new(3)), // column 0, step 0
        Assertion::single(0, 9, BaseElement::new(5)), // column 0, step 9
        Assertion::sequence(0, 2, 4, values.clone()), // column 0, steps 2, 6, 10, 14
        Assertion::sequence(0, 3, 4, values.clone()), // column 1, steps 2, 6, 10, 14
        Assertion::sequence(1, 0, 8, values[..2].to_vec()), // column 1, steps 0, 8
        Assertion::periodic(1, 3, 8, BaseElement::new(7)), // column 1, steps 3, 11
    ];

    let trace_width = 2;
    let trace_length = 16;
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);

    shuffle(&mut assertions);
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);

    shuffle(&mut assertions);
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);
}

#[test]
#[should_panic(
    expected = "assertion (column=0, steps=[1, 9, ...], value=7) overlaps with assertion (column=0, step=9, value=5)"
)]
fn prepare_assertions_with_overlap() {
    let assertions = vec![
        Assertion::single(0, 9, BaseElement::new(5)),
        Assertion::periodic(0, 1, 8, BaseElement::new(7)),
    ];
    let _ = super::prepare_assertions(assertions.clone(), 2, 16);
}

#[test]
#[should_panic(
    expected = "assertion (column=0, step=16, value=5) is invalid: expected trace length to be at least 32, but was 16"
)]
fn prepare_assertions_with_invalid_trace_length() {
    let assertions = vec![Assertion::single(0, 16, BaseElement::new(5))];
    let _ = super::prepare_assertions(assertions.clone(), 2, 16);
}

#[test]
#[should_panic(
    expected = "assertion (column=3, step=17, value=5) is invalid: expected trace width to be at least 3, but was 2"
)]
fn prepare_assertions_with_invalid_trace_width() {
    let assertions = vec![Assertion::single(3, 17, BaseElement::new(5))];
    let _ = super::prepare_assertions(assertions.clone(), 2, 16);
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_constraint_params(
    trace_length: usize,
) -> (
    BaseElement,
    BTreeMap<usize, Vec<BaseElement>>,
    RandomCoin<BaseElement, Blake3_256<BaseElement>>,
) {
    let inv_g = BaseElement::get_root_of_unity(log2(trace_length)).inv();
    let prng = build_prng();
    let twiddle_map = BTreeMap::<usize, Vec<BaseElement>>::new();
    (inv_g, twiddle_map, prng)
}
