// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Assertion, AssertionError};
use math::{fields::f128::BaseElement, FieldElement};
use rand_utils::{rand_value, rand_vector};
use utils::collections::Vec;

// SINGLE ASSERTIONS
// ================================================================================================
#[test]
fn single_assertion() {
    let value = rand_value::<BaseElement>();
    let a = Assertion::single(2, 8, value);
    assert_eq!(2, a.column);
    assert_eq!(8, a.first_step);
    assert_eq!(vec![value], a.values);
    assert_eq!(0, a.stride);
    assert_eq!(1, a.get_num_steps(16));
    assert_eq!(1, a.get_num_steps(32));

    a.apply(16, |step, val| {
        assert_eq!(8, step);
        assert_eq!(value, val);
    });

    assert_eq!(Ok(()), a.validate_trace_width(3));
    assert_eq!(
        Err(AssertionError::TraceWidthTooShort(2, 1)),
        a.validate_trace_width(1)
    );

    assert_eq!(Ok(()), a.validate_trace_length(16));
    assert_eq!(
        Err(AssertionError::TraceLengthTooShort(16, 8)),
        a.validate_trace_length(8)
    );
}

// PERIODIC ASSERTIONS
// ================================================================================================

#[test]
fn periodic_assertion() {
    let value = rand_value::<BaseElement>();
    let a = Assertion::periodic(4, 1, 16, value);
    assert_eq!(4, a.column);
    assert_eq!(1, a.first_step);
    assert_eq!(vec![value], a.values);
    assert_eq!(16, a.stride);
    assert_eq!(1, a.get_num_steps(16));
    assert_eq!(2, a.get_num_steps(32));

    a.apply(16, |step, val| {
        assert_eq!(1, step);
        assert_eq!(value, val);
    });
    a.apply(32, |step, val| {
        if step == 1 || step == 17 {
            assert_eq!(value, val);
            return;
        }
        assert!(false);
    });

    assert_eq!(Ok(()), a.validate_trace_width(5));
    assert_eq!(
        Err(AssertionError::TraceWidthTooShort(4, 2)),
        a.validate_trace_width(2)
    );
    assert_eq!(Ok(()), a.validate_trace_length(16));
    assert_eq!(
        Err(AssertionError::TraceLengthTooShort(16, 8)),
        a.validate_trace_length(8)
    );
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 0: stride must be a power of two, but was 3"
)]
fn periodic_assertion_stride_not_power_of_two() {
    let _ = Assertion::periodic(0, 1, 3, BaseElement::ONE);
}

#[test]
#[should_panic(expected = "invalid assertion for column 0: stride must be at least 2, but was 1")]
fn periodic_assertion_stride_too_small() {
    let _ = Assertion::periodic(0, 1, 1, BaseElement::ONE);
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 0: first step must be smaller than stride (4 steps), but was 5"
)]
fn periodic_assertion_first_step_greater_than_stride() {
    let _ = Assertion::periodic(0, 5, 4, BaseElement::ONE);
}

#[test]
#[should_panic(
    expected = "invalid trace length: expected trace length to be at least 8, but was 4"
)]
fn periodic_assertion_get_num_steps_error() {
    let a = Assertion::periodic(0, 1, 8, BaseElement::ONE);
    let _ = a.get_num_steps(4);
}

// SEQUENCE ASSERTIONS
// ================================================================================================

#[test]
fn sequence_assertion() {
    let values = rand_vector::<BaseElement>(2);
    let a = Assertion::sequence(3, 2, 4, values.clone());
    assert_eq!(3, a.column);
    assert_eq!(2, a.first_step);
    assert_eq!(values, a.values);
    assert_eq!(4, a.stride);
    assert_eq!(2, a.get_num_steps(8));

    a.apply(8, |step, val| {
        if step == 2 {
            assert_eq!(values[0], val);
            return;
        } else if step == 6 {
            assert_eq!(values[1], val);
            return;
        }
        assert!(false);
    });

    assert_eq!(Ok(()), a.validate_trace_length(8));
    assert_eq!(
        Err(AssertionError::TraceLengthNotExact(8, 4)),
        a.validate_trace_length(4)
    );
    assert_eq!(
        Err(AssertionError::TraceLengthNotExact(8, 16)),
        a.validate_trace_length(16)
    );

    assert_eq!(Ok(()), a.validate_trace_width(4));
    assert_eq!(
        Err(AssertionError::TraceWidthTooShort(3, 2)),
        a.validate_trace_width(2)
    );
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: stride must be a power of two, but was 5"
)]
fn sequence_assertion_stride_not_power_of_two() {
    let _ = Assertion::sequence(3, 2, 5, vec![BaseElement::ONE, BaseElement::ZERO]);
}

#[test]
#[should_panic(expected = "invalid assertion for column 3: stride must be at least 2, but was 1")]
fn sequence_assertion_stride_too_small() {
    let _ = Assertion::sequence(3, 2, 1, vec![BaseElement::ONE, BaseElement::ZERO]);
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: first step must be smaller than stride (4 steps), but was 5"
)]
fn sequence_assertion_first_step_greater_than_stride() {
    let _ = Assertion::sequence(3, 5, 4, vec![BaseElement::ONE, BaseElement::ZERO]);
}

#[test]
#[should_panic(expected = "invalid trace length: expected trace length to be exactly 8, but was 4")]
fn sequence_assertion_inconsistent_trace() {
    let a = Assertion::sequence(3, 2, 4, vec![BaseElement::ONE, BaseElement::ZERO]);
    let _ = a.get_num_steps(4);
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: number of asserted values must be greater than zero"
)]
fn sequence_assertion_empty_values() {
    let _ = Assertion::sequence(3, 2, 4, Vec::<BaseElement>::new());
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: number of asserted values must be a power of two, but was 3"
)]
fn sequence_assertion_num_values_not_power_of_two() {
    let _ = Assertion::sequence(
        3,
        2,
        4,
        vec![BaseElement::ONE, BaseElement::ZERO, BaseElement::ONE],
    );
}

// OVERLAPPING ASSERTIONS
// ================================================================================================

#[test]
fn assertion_overlap() {
    // ----- single-single overlap ----------------------------------------------------------------

    let a = Assertion::single(3, 2, BaseElement::ONE);
    let b = Assertion::single(3, 2, BaseElement::ONE);
    assert!(a.overlaps_with(&b));

    // different columns: no overlap
    let b = Assertion::single(1, 2, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));

    // different steps: no overlap
    let b = Assertion::single(3, 1, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));

    // ----- single-periodic overlap --------------------------------------------------------------

    let a = Assertion::periodic(3, 2, 4, BaseElement::ONE);
    let b = Assertion::single(3, 2, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::single(3, 6, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::single(3, 10, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    let b = Assertion::single(1, 2, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different steps: no overlap
    let b = Assertion::single(3, 3, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- single-sequence overlap --------------------------------------------------------------

    let values = vec![BaseElement::ONE, BaseElement::ZERO];
    let a = Assertion::sequence(3, 2, 8, values);
    let b = Assertion::single(3, 2, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::single(3, 10, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::single(3, 18, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    let b = Assertion::single(1, 2, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different steps: no overlap
    let b = Assertion::single(3, 3, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- periodic-periodic overlap ------------------------------------------------------------

    let a = Assertion::periodic(3, 4, 8, BaseElement::ONE);
    let b = Assertion::periodic(3, 4, 8, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::periodic(3, 4, 16, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::periodic(3, 0, 4, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    let b = Assertion::periodic(1, 4, 8, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    let b = Assertion::periodic(0, 0, 8, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    let b = Assertion::periodic(0, 0, 16, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- sequence-sequence overlap ------------------------------------------------------------

    let values = vec![BaseElement::ONE, BaseElement::ZERO];

    let a = Assertion::sequence(3, 4, 8, values.clone());
    let b = Assertion::sequence(3, 4, 8, values.clone());
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::sequence(3, 4, 16, values.clone());
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::sequence(3, 0, 4, values.clone());
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    let b = Assertion::sequence(1, 4, 8, values.clone());
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    let b = Assertion::sequence(0, 0, 8, values.clone());
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    let b = Assertion::sequence(0, 0, 16, values.clone());
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- sequence-periodic overlap ------------------------------------------------------------

    let values = vec![BaseElement::ONE, BaseElement::ZERO];

    let a = Assertion::sequence(3, 4, 8, values.clone());
    let b = Assertion::periodic(3, 4, 8, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::periodic(3, 4, 16, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    let b = Assertion::periodic(3, 0, 4, BaseElement::ONE);
    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    let b = Assertion::periodic(1, 4, 8, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    let b = Assertion::periodic(0, 0, 8, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    let b = Assertion::periodic(0, 0, 16, BaseElement::ONE);
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));
}
