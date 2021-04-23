// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ExecutionTrace;
use common::{
    Air, Assertion, ComputationContext, EvaluationFrame, FieldExtension, HashFunction,
    ProofOptions, TraceInfo, TransitionConstraintDegree,
};
use math::field::{f128::BaseElement, FieldElement};

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub fn build_fib_trace(length: usize) -> ExecutionTrace<BaseElement> {
    assert!(length.is_power_of_two(), "length must be a power of 2");

    let mut reg1 = vec![BaseElement::ONE];
    let mut reg2 = vec![BaseElement::ONE];

    for i in 0..(length / 2 - 1) {
        reg1.push(reg1[i] + reg2[i]);
        reg2.push(reg1[i] + BaseElement::from(2u8) * reg2[i]);
    }

    ExecutionTrace::init(vec![reg1, reg2])
}

// MOCK AIR
// ================================================================================================

pub struct MockAir {
    context: ComputationContext,
    assertions: Vec<Assertion<BaseElement>>,
    periodic_columns: Vec<Vec<BaseElement>>,
}

impl MockAir {
    pub fn with_periodic_columns(
        column_values: Vec<Vec<BaseElement>>,
        trace_length: usize,
    ) -> Self {
        let mut result = Self::new(
            TraceInfo {
                length: trace_length,
                meta: Vec::new(),
            },
            (),
            ProofOptions::new(32, 8, 0, HashFunction::Blake3_256, FieldExtension::None),
        );
        result.periodic_columns = column_values;
        result
    }

    pub fn with_assertions(assertions: Vec<Assertion<BaseElement>>, trace_length: usize) -> Self {
        let mut result = Self::new(
            TraceInfo {
                length: trace_length,
                meta: Vec::new(),
            },
            (),
            ProofOptions::new(32, 8, 0, HashFunction::Blake3_256, FieldExtension::None),
        );
        result.assertions = assertions;
        result
    }
}

impl Air for MockAir {
    type BaseElement = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: (), _options: ProofOptions) -> Self {
        let context = build_context(trace_info.length, 4, 8);
        MockAir {
            context,
            assertions: Vec::new(),
            periodic_columns: Vec::new(),
        }
    }

    fn context(&self) -> &ComputationContext {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseElement>> {
        self.periodic_columns.clone()
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        self.assertions.clone()
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_context(
    trace_length: usize,
    trace_width: usize,
    blowup_factor: usize,
) -> ComputationContext {
    let options = ProofOptions::new(
        32,
        blowup_factor,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
    );
    let t_degrees = vec![TransitionConstraintDegree::new(2)];
    ComputationContext::new(trace_width, trace_length, t_degrees, options)
}
