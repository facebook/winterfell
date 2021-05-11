// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{compose_constraints, evaluate_constraints, VerifierChannel};
use common::CompositionCoefficients;
use common::{errors::VerifierError, Air, EvaluationFrame, PublicCoin};
use crypto::Hasher;
use fri::VerifierChannel as FriVerifierChannel;
use math::field::{FieldElement, StarkField};

// VERIFICATION PROCEDURE
// ================================================================================================

pub fn perform_verification<A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher>(
    air: A,
    channel: VerifierChannel<A::BaseElement, E, H>,
) -> Result<(), VerifierError> {
    // 1 ----- Compute constraint evaluations at OOD point z ----------------------------------

    // draw a pseudo-random out-of-domain point for DEEP composition
    let z = channel.draw_deep_point::<E>();

    // evaluate constraints at z
    let ood_frame = channel.read_ood_frame();
    let constraint_evaluation_at_z = evaluate_constraints(&air, &channel, ood_frame, z);

    // 2 ----- Read queried trace states and constraint evaluations ---------------------------

    // draw pseudo-random query positions
    let query_positions = channel.draw_query_positions();

    // compute LDE domain coordinates for all query positions
    let g_lde = air.context().get_lde_domain_generator::<A::BaseElement>();
    let domain_offset = air.context().domain_offset::<A::BaseElement>();
    let x_coordinates: Vec<A::BaseElement> = query_positions
        .iter()
        .map(|&p| g_lde.exp((p as u64).into()) * domain_offset)
        .collect();

    // read trace states and constraint evaluations at the queried positions; this also
    // checks that Merkle authentication paths for the states and evaluations are valid
    let trace_states = channel.read_trace_states(&query_positions)?;
    let constraint_evaluations = channel.read_constraint_evaluations(&query_positions)?;

    // 3 ----- Compute composition polynomial evaluations -------------------------------------

    // draw coefficients for computing random linear combination of trace and constraint
    // polynomials; the result of this linear combination are evaluations of deep composition
    // polynomial
    let coefficients = channel.draw_composition_coefficients();

    // compute composition of trace registers
    let t_composition = compose_registers(
        &air,
        &trace_states,
        &x_coordinates,
        &ood_frame,
        z,
        &coefficients,
    );

    // compute composition of constraints
    let c_composition = compose_constraints(
        constraint_evaluations,
        &x_coordinates,
        z,
        constraint_evaluation_at_z,
        &coefficients,
    );

    // add the two together
    let evaluations = t_composition
        .iter()
        .zip(c_composition)
        .map(|(&t, c)| t + c)
        .collect::<Vec<_>>();

    // 4 ----- Verify low-degree proof -------------------------------------------------------------
    // make sure that evaluations we computed in the previous step are in fact evaluations
    // of a polynomial of degree equal to context.deep_composition_degree()
    let fri_context = fri::VerifierContext::new(
        air.context().lde_domain_size(),
        air.context().composition_degree(),
        channel.num_fri_partitions(),
        air.context().options().to_fri_options::<A::BaseElement>(),
    );
    fri::verify(&fri_context, &channel, &evaluations, &query_positions)
        .map_err(VerifierError::FriVerificationFailed)
}

// TRACE COMPOSITION
// ================================================================================================

/// TODO: add comments
fn compose_registers<B: StarkField, E: FieldElement + From<B>, A: Air<BaseElement = B>>(
    air: &A,
    trace_states: &[Vec<B>],
    x_coordinates: &[B],
    ood_frame: &EvaluationFrame<E>,
    z: E,
    cc: &CompositionCoefficients<E>,
) -> Vec<E> {
    let next_z = z * E::from(air.trace_domain_generator());

    let trace_at_z1 = &ood_frame.current;
    let trace_at_z2 = &ood_frame.next;

    // TODO: this is computed in several paces; consolidate
    let composition_degree = air.context().deep_composition_degree();
    let incremental_degree = (composition_degree - (air.trace_length() - 2)) as u32;

    // when field extension is enabled, these will be set to conjugates of trace values at
    // z as well as conjugate of z itself
    let conjugate_values = get_conjugate_values(air, trace_at_z1, z);

    let mut result = Vec::with_capacity(trace_states.len());
    for (registers, &x) in trace_states.iter().zip(x_coordinates) {
        let x = E::from(x);
        let mut composition = E::ZERO;
        for (i, &value) in registers.iter().enumerate() {
            let value = E::from(value);
            // compute T1(x) = (T(x) - T(z)) / (x - z)
            let t1 = (value - trace_at_z1[i]) / (x - z);
            // multiply it by a pseudo-random coefficient, and combine with result
            composition += t1 * cc.trace[i].0;

            // compute T2(x) = (T(x) - T(z * g)) / (x - z * g)
            let t2 = (value - trace_at_z2[i]) / (x - next_z);
            // multiply it by a pseudo-random coefficient, and combine with result
            composition += t2 * cc.trace[i].1;

            // compute T3(x) = (T(x) - T(z_conjugate)) / (x - z_conjugate)
            // when extension field is enabled, this constraint is needed in order to verify
            // that the trace is defined over the base field, rather than the extension field
            if let Some((z_conjugate, ref trace_at_z1_conjugates)) = conjugate_values {
                let t3 = (value - trace_at_z1_conjugates[i]) / (x - z_conjugate);
                composition += t3 * cc.trace[i].2;
            }
        }

        // raise the degree to match composition degree
        let xp = x.exp(incremental_degree.into());
        composition *= cc.trace_degree.0 + xp * cc.trace_degree.1;

        result.push(composition);
    }

    result
}

/// When field extension is used, returns conjugate values of the `trace_state` and `z`;
/// otherwise, returns None.
fn get_conjugate_values<A: Air, E: FieldElement + From<A::BaseElement>>(
    air: &A,
    trace_state: &[E],
    z: E,
) -> Option<(E, Vec<E>)> {
    if air.context().options().field_extension().is_none() {
        None
    } else {
        Some((
            z.conjugate(),
            trace_state.iter().map(|v| v.conjugate()).collect(),
        ))
    }
}
