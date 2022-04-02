// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::TraceTable;
use air::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, HashFunction, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
use math::{fields::f128::BaseElement, FieldElement, StarkField};
use utils::collections::Vec;

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub fn build_fib_trace(length: usize) -> TraceTable<BaseElement> {
    assert!(length.is_power_of_two(), "length must be a power of 2");

    let mut reg1 = vec![BaseElement::ONE];
    let mut reg2 = vec![BaseElement::ONE];

    for i in 0..(length / 2 - 1) {
        reg1.push(reg1[i] + reg2[i]);
        reg2.push(reg1[i] + BaseElement::from(2u8) * reg2[i]);
    }

    TraceTable::init(vec![reg1, reg2])
}

// MOCK AIR
// ================================================================================================

pub struct MockAir {
    context: AirContext<BaseElement>,
    assertions: Vec<Assertion<BaseElement>>,
    periodic_columns: Vec<Vec<BaseElement>>,
}

impl MockAir {
    pub fn with_trace_length(trace_length: usize) -> Self {
        Self::new(
            TraceInfo::new(4, trace_length),
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
        )
    }

    pub fn with_periodic_columns(
        column_values: Vec<Vec<BaseElement>>,
        trace_length: usize,
    ) -> Self {
        let mut result = Self::new(
            TraceInfo::new(4, trace_length),
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
            TraceInfo::new(4, trace_length),
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
        let context = build_context(trace_info, 8, 1);
        MockAir {
            context,
            assertions: Vec::new(),
            periodic_columns: Vec::new(),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        self.assertions.clone()
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        self.periodic_columns.clone()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_context<B: StarkField>(
    trace_info: TraceInfo,
    blowup_factor: usize,
    num_assertions: usize,
) -> AirContext<B> {
    let options = ProofOptions::new(
        32,
        blowup_factor,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
        4,
        256,
    );
    let t_degrees = vec![TransitionConstraintDegree::new(2)];
    AirContext::new(trace_info, t_degrees, num_assertions, options)
}
