// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use crate::{AuxTraceRandElements, FieldExtension, HashFunction};
use crypto::{hashers::Blake3_256, RandomCoin};
use math::{fields::f128::BaseElement, get_power_series, log2, polynom, FieldElement, StarkField};
use utils::collections::{BTreeMap, Vec};

// PERIODIC COLUMNS
// ================================================================================================

#[test]
fn get_periodic_column_polys() {
    // no periodic columns
    let air = MockAir::with_periodic_columns(vec![], 16);
    let column_polys = air.get_periodic_column_polys();
    assert_eq!(0, column_polys.len());

    let col1 = vec![BaseElement::ONE, BaseElement::ZERO];
    let col2 = vec![
        BaseElement::ONE,
        BaseElement::ZERO,
        BaseElement::ONE,
        BaseElement::ONE,
    ];
    let air = MockAir::with_periodic_columns(vec![col1.clone(), col2.clone()], 16);
    let column_polys = air.get_periodic_column_polys();
    assert_eq!(2, column_polys.len());
    assert_eq!(build_periodic_column_poly(&col1), column_polys[0]);
    assert_eq!(build_periodic_column_poly(&col2), column_polys[1]);
}

#[test]
#[should_panic(expected = "number of values in a periodic column must be at least 2, but was 1")]
fn get_periodic_column_polys_num_values_too_small() {
    let col1 = vec![BaseElement::ONE];
    let air = MockAir::with_periodic_columns(vec![col1], 16);
    let column_polys = air.get_periodic_column_polys();
    assert_eq!(0, column_polys.len());
}

#[test]
#[should_panic(
    expected = "number of values in a periodic column must be a power of two, but was 3"
)]
fn get_periodic_column_polys_num_values_not_power_of_two() {
    let col1 = vec![BaseElement::ONE, BaseElement::ZERO, BaseElement::ONE];
    let air = MockAir::with_periodic_columns(vec![col1], 16);
    let column_polys = air.get_periodic_column_polys();
    assert_eq!(0, column_polys.len());
}

// TRANSITION CONSTRAINTS
// ================================================================================================

// TODO

// BOUNDARY CONSTRAINTS
// ================================================================================================

#[test]
fn get_boundary_constraints() {
    // define assertions
    let values = vec![
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];
    let assertions = vec![
        Assertion::single(0, 0, BaseElement::new(3)), // column 0, step 0 -> group 0
        Assertion::single(0, 9, BaseElement::new(5)), // column 0, step 9 -> group 1
        Assertion::single(1, 9, BaseElement::new(9)), // column 0, step 9 -> group 1
        Assertion::sequence(0, 2, 4, values.clone()), // column 0, steps 2, 6, 10, 14 -> group 4
        Assertion::sequence(1, 2, 4, values.clone()), // column 1, steps 2, 6, 10, 14 -> group 4
        Assertion::sequence(1, 0, 8, values[..2].to_vec()), // column 1, steps 0, 8 -> group 2
        Assertion::sequence(0, 3, 8, values[..2].to_vec()), // column 0, steps 3, 11 -> group 3
        Assertion::periodic(1, 3, 8, BaseElement::new(7)), // column 1, steps 3, 11 -> group 3
    ];

    // instantiate mock AIR
    let trace_length = 16;
    let air = MockAir::with_assertions(assertions, trace_length);
    let no_poly_offset = (0, BaseElement::ONE);
    let g = BaseElement::get_root_of_unity(log2(trace_length)); // trace domain generator

    // build coefficients for random liner combination; these will be derived for assertions
    // sorted first by stride, then by first step, and finally by column (similar to the order)
    // of assertions above
    let mut prng = build_prng();
    let mut expected_cc = BTreeMap::<usize, (BaseElement, BaseElement)>::new();
    expected_cc.insert(0, prng.draw_pair().unwrap());
    expected_cc.insert(1, prng.draw_pair().unwrap());
    expected_cc.insert(2, prng.draw_pair().unwrap());
    expected_cc.insert(6, prng.draw_pair().unwrap());
    expected_cc.insert(7, prng.draw_pair().unwrap());
    expected_cc.insert(3, prng.draw_pair().unwrap());
    expected_cc.insert(4, prng.draw_pair().unwrap());
    expected_cc.insert(5, prng.draw_pair().unwrap());

    // get boundary constraints from AIR, and sort constraint groups so that the order
    // is stable; the original order is just by degree_adjustment
    let mut prng = build_prng();
    let coefficients = (0..8)
        .map(|_| prng.draw_pair().unwrap())
        .collect::<Vec<(BaseElement, BaseElement)>>();
    let constraints = air.get_boundary_constraints(&AuxTraceRandElements::new(), &coefficients);
    let mut groups = constraints.main_constraints().to_vec();

    groups.sort_by(|g1, g2| {
        if g1.degree_adjustment() == g2.degree_adjustment() {
            let n1 = &g1.divisor().numerator()[0].1;
            let n2 = &g2.divisor().numerator()[0].1;
            n1.as_int().partial_cmp(&n2.as_int()).unwrap()
        } else {
            g1.degree_adjustment()
                .partial_cmp(&g2.degree_adjustment())
                .unwrap()
        }
    });
    assert_eq!(5, groups.len());

    // group 0
    let group = &groups[0];
    assert_eq!(1, group.divisor().degree());
    assert_eq!(vec![(1, g.exp(0))], group.divisor().numerator());
    assert_eq!(1, group.constraints().len());

    let constraint = &group.constraints()[0];
    assert_eq!(0, constraint.column());
    assert_eq!(vec![BaseElement::new(3)], constraint.poly());
    assert_eq!(no_poly_offset, constraint.poly_offset());
    assert_eq!(expected_cc[&0], constraint.cc().clone());

    // group 1
    let group = &groups[1];
    assert_eq!(1, group.divisor().degree());
    assert_eq!(vec![(1, g.exp(9))], group.divisor().numerator());
    assert_eq!(2, group.constraints().len());

    let constraint = &group.constraints()[0];
    assert_eq!(0, constraint.column());
    assert_eq!(vec![BaseElement::new(5)], constraint.poly());
    assert_eq!(no_poly_offset, constraint.poly_offset());
    assert_eq!(expected_cc[&1], constraint.cc().clone());

    let constraint = &group.constraints()[1];
    assert_eq!(1, constraint.column());
    assert_eq!(vec![BaseElement::new(9)], constraint.poly());
    assert_eq!(no_poly_offset, constraint.poly_offset());
    assert_eq!(expected_cc[&2], constraint.cc().clone());

    // group 2
    let group = &groups[2];
    assert_eq!(2, group.divisor().degree());
    assert_eq!(vec![(2, g.exp(0))], group.divisor().numerator());
    assert_eq!(1, group.constraints().len());

    let constraint = &group.constraints()[0];
    assert_eq!(1, constraint.column());
    assert_eq!(
        build_sequence_poly(&values[..2], trace_length),
        constraint.poly()
    );
    assert_eq!(no_poly_offset, constraint.poly_offset());
    assert_eq!(expected_cc[&3], constraint.cc().clone());

    // group 3
    let group = &groups[3];
    assert_eq!(2, group.divisor().degree());
    assert_eq!(vec![(2, g.exp(2 * 3))], group.divisor().numerator());
    assert_eq!(2, group.constraints().len());

    let constraint = &group.constraints()[0];
    assert_eq!(0, constraint.column());
    assert_eq!(
        build_sequence_poly(&values[..2], trace_length),
        constraint.poly()
    );
    assert_eq!((3, g.inv().exp(3)), constraint.poly_offset());
    assert_eq!(expected_cc[&4], constraint.cc().clone());

    let constraint = &group.constraints()[1];
    assert_eq!(1, constraint.column());
    assert_eq!(vec![BaseElement::new(7)], constraint.poly());
    assert_eq!(no_poly_offset, constraint.poly_offset());
    assert_eq!(expected_cc[&5], constraint.cc().clone());

    // group 4
    let group = &groups[4];
    assert_eq!(4, group.divisor().degree());
    assert_eq!(vec![(4, g.exp(4 * 2))], group.divisor().numerator());
    assert_eq!(2, group.constraints().len());

    let constraint = &group.constraints()[0];
    assert_eq!(0, constraint.column());
    assert_eq!(
        build_sequence_poly(&values, trace_length),
        constraint.poly()
    );
    assert_eq!((2, g.inv().exp(2)), constraint.poly_offset());
    assert_eq!(expected_cc[&6], constraint.cc().clone());

    let constraint = &group.constraints()[1];
    assert_eq!(1, constraint.column());
    assert_eq!(
        build_sequence_poly(&values, trace_length),
        constraint.poly()
    );
    assert_eq!((2, g.inv().exp(2)), constraint.poly_offset());
    assert_eq!(expected_cc[&7], constraint.cc().clone());
}

// MOCK AIR
// ================================================================================================

struct MockAir {
    context: AirContext<BaseElement>,
    assertions: Vec<Assertion<BaseElement>>,
    periodic_columns: Vec<Vec<BaseElement>>,
}

impl MockAir {
    pub fn with_periodic_columns(
        column_values: Vec<Vec<BaseElement>>,
        trace_length: usize,
    ) -> Self {
        let mut result = Self::new(
            TraceInfo::with_meta(4, trace_length, vec![1]),
            (),
            ProofOptions::new(
                32,
                8,
                0,
                HashFunction::Blake3_256,
                FieldExtension::None,
                4,
                256,
            ),
        );
        result.periodic_columns = column_values;
        result
    }

    pub fn with_assertions(assertions: Vec<Assertion<BaseElement>>, trace_length: usize) -> Self {
        let mut result = Self::new(
            TraceInfo::with_meta(4, trace_length, vec![assertions.len() as u8]),
            (),
            ProofOptions::new(
                32,
                8,
                0,
                HashFunction::Blake3_256,
                FieldExtension::None,
                4,
                256,
            ),
        );
        result.assertions = assertions;
        result
    }
}

impl Air for MockAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: (), _options: ProofOptions) -> Self {
        let num_assertions = trace_info.meta()[0] as usize;
        let context = build_context(trace_info.length(), trace_info.width(), num_assertions);
        MockAir {
            context,
            assertions: Vec::new(),
            periodic_columns: Vec::new(),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        self.periodic_columns.clone()
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        self.assertions.clone()
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
    }
}

// UTILITY FUNCTIONS
// ================================================================================================

pub fn build_context<B: StarkField>(
    trace_length: usize,
    trace_width: usize,
    num_assertions: usize,
) -> AirContext<B> {
    let options = ProofOptions::new(
        32,
        8,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
        4,
        256,
    );
    let t_degrees = vec![TransitionConstraintDegree::new(2)];
    let trace_info = TraceInfo::new(trace_width, trace_length);
    AirContext::new(trace_info, t_degrees, num_assertions, options)
}

pub fn build_prng() -> RandomCoin<BaseElement, Blake3_256<BaseElement>> {
    RandomCoin::new(&[0; 32])
}

pub fn build_sequence_poly(values: &[BaseElement], trace_length: usize) -> Vec<BaseElement> {
    let cycle_length = trace_length / values.len();
    let domain_size = trace_length / cycle_length;
    let g = BaseElement::get_root_of_unity(log2(domain_size));
    let xs = get_power_series(g, domain_size);
    polynom::interpolate(&xs, values, false)
}

pub fn build_periodic_column_poly(values: &[BaseElement]) -> Vec<BaseElement> {
    let domain_size = values.len();
    let g = BaseElement::get_root_of_unity(log2(domain_size));
    let xs = get_power_series(g, domain_size);
    polynom::interpolate(&xs, values, false)
}
