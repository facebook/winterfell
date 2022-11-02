// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{Air, ConstraintDivisor};
use math::{fft, get_power_series, log2, StarkField};
use utils::collections::{BTreeMap, Vec};

// TYPES AND INTERFACES
// ================================================================================================

pub struct StarkDomain<B: StarkField> {
    /// Twiddles which can be used to evaluate polynomials in the trace domain. Length of this
    /// vector is half the length of the trace domain size.
    trace_twiddles: Vec<B>,

    /// LDE domain size / constraint evaluation domain size
    ce_to_lde_blowup: usize,

    /// Offset of the low-degree extension domain.
    domain_offset: B,

    /// [g^i for i in (0..ce_domain_size)] where g is the constraint evaluation domain generator.
    ce_domain: Vec<B>,

    /// A mapping from adjustment degrees to domain_offset^adjustment_degree.
    degree_adj_map: BTreeMap<u32, B>,
}

// STARK DOMAIN IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> StarkDomain<B> {
    /// Returns a new STARK domain initialized with the provided `context`.
    pub fn new<A: Air<BaseField = B>>(air: &A) -> Self {
        let trace_twiddles = fft::get_twiddles(air.trace_length());

        let domain_gen = B::get_root_of_unity(log2(air.ce_domain_size()));
        let ce_domain = get_power_series(domain_gen, air.ce_domain_size());
        let degree_adj_map = generate_degree_adj_map(air);

        StarkDomain {
            trace_twiddles,
            ce_to_lde_blowup: air.lde_domain_size() / air.ce_domain_size(),
            domain_offset: air.domain_offset(),
            ce_domain,
            degree_adj_map,
        }
    }

    // EXECUTION TRACE
    // --------------------------------------------------------------------------------------------

    /// Returns length of the execution trace for this computation.
    pub fn trace_length(&self) -> usize {
        &self.trace_twiddles.len() * 2
    }

    /// Returns twiddles which can be used to evaluate trace polynomials.
    pub fn trace_twiddles(&self) -> &[B] {
        &self.trace_twiddles
    }

    /// Returns blowup factor from trace to constraint evaluation domain.
    pub fn trace_to_ce_blowup(&self) -> usize {
        self.ce_domain_size() / self.trace_length()
    }

    /// Returns blowup factor from trace to LDE domain.
    pub fn trace_to_lde_blowup(&self) -> usize {
        self.lde_domain_size() / self.trace_length()
    }

    // CONSTRAINT EVALUATION DOMAIN
    // --------------------------------------------------------------------------------------------

    /// Returns the size of the constraint evaluation domain for this computation.
    pub fn ce_domain_size(&self) -> usize {
        self.ce_domain.len()
    }

    /// Returns the constraint evaluation domain for this computation.
    pub fn ce_domain(&self) -> Vec<B> {
        self.ce_domain.clone()
    }

    /// Returns the degree adjustment map for this computation.
    pub fn degree_adj_map(&self) -> BTreeMap<u32, B> {
        self.degree_adj_map.clone()
    }

    /// Returns the generator of constraint evaluation domain.
    pub fn ce_domain_generator(&self) -> B {
        B::get_root_of_unity(log2(self.ce_domain_size()))
    }

    /// Returns blowup factor from constraint evaluation to LDE domain.
    pub fn ce_to_lde_blowup(&self) -> usize {
        self.ce_to_lde_blowup
    }

    /// Returns (offset * g^(step))^degree_adjustment.
    pub fn get_ce_x_power_at<A: Air<BaseField = B>>(
        &self,
        step: usize,
        degree_adjustment: u32,
    ) -> A::BaseField {
        let index: usize = step * (degree_adjustment as usize);
        let index = index % (self.ce_domain_size());
        let xp = self.ce_domain()[index] * *self.degree_adj_map().get(&degree_adjustment).unwrap();

        xp
    }

    // LOW-DEGREE EXTENSION DOMAIN
    // --------------------------------------------------------------------------------------------

    /// Returns the size of the low-degree extension domain.
    pub fn lde_domain_size(&self) -> usize {
        self.ce_domain_size() * self.ce_to_lde_blowup()
    }

    /// Returns LDE domain offset.
    pub fn offset(&self) -> B {
        self.domain_offset
    }
}

// HELPERS
// --------------------------------------------------------------------------------------------

fn generate_degree_adj_map<A: Air<BaseField = B>, B: StarkField>(air: &A) -> BTreeMap<u32, B> {
    let mut degree_adj_map = BTreeMap::new();
    let domain_offset = air.domain_offset();
    let context = air.context();
    let divisor: ConstraintDivisor<B> = ConstraintDivisor::from_transition(
        context.trace_len(),
        context.num_transition_exemptions(),
    );
    let div_deg = divisor.degree();
    let (main_constraint_degrees, aux_constraint_degrees) = context.transition_constraint_degrees();
    let trace_len = context.trace_len();
    let comp_deg = context.composition_degree();
    let target_deg = comp_deg + div_deg;

    for degree in main_constraint_degrees
        .iter()
        .chain(aux_constraint_degrees.iter())
    {
        let evaluation_degree = degree.get_evaluation_degree(trace_len);
        let degree_adjustment = (target_deg - evaluation_degree) as u32;
        let _ = degree_adj_map
            .entry(degree_adjustment)
            .or_insert_with(|| domain_offset.exp(degree_adjustment.into()));
    }
    degree_adj_map
}
