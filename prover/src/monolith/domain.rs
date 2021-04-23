// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::ComputationContext;
use math::{
    fft,
    field::StarkField,
    utils::{get_power_series_with_offset, log2},
};

// TYPES AND INTERFACES
// ================================================================================================

pub struct StarkDomain<B: StarkField> {
    /// Contains all values in the low-degree extension domain. Length of this vector is the same
    /// as the size of LDE domain.
    lde_domain: Vec<B>,

    /// Twiddles which can be used to evaluate polynomials in the trace domain. Length of this
    /// vector is half the length of the trace domain size.
    trace_twiddles: Vec<B>,

    /// Twiddles which can be used to evaluate polynomials in the constraint evaluation domain.
    /// Length of this vector is half the length of constraint evaluation domain size.
    ce_twiddles: Vec<B>,

    // this is used a lot during constraint evaluation; cache it here to avoid recomputation
    ce_to_lde_blowup: usize,
}

// STARK DOMAIN IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> StarkDomain<B> {
    /// Returns a new STARK domain initialized with the provided `context`.
    pub fn new(context: &ComputationContext) -> Self {
        let lde_domain = build_lde_domain(context.lde_domain_size(), context.domain_offset());
        let trace_twiddles = fft::get_twiddles(context.trace_length());
        let ce_twiddles = fft::get_twiddles(context.ce_domain_size());
        StarkDomain {
            lde_domain,
            trace_twiddles,
            ce_twiddles,
            ce_to_lde_blowup: context.lde_domain_size() / context.ce_domain_size(),
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
    #[allow(dead_code)]
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
        &self.ce_twiddles.len() * 2
    }

    /// Returns twiddles which can be used to evaluate constraint polynomials.
    pub fn ce_twiddles(&self) -> &[B] {
        &self.ce_twiddles
    }

    /// Returns blowup factor from constraint evaluation to LDE domain.
    pub fn ce_to_lde_blowup(&self) -> usize {
        self.ce_to_lde_blowup
    }

    pub fn ce_step_to_lde_info(&self, ce_step: usize) -> (usize, B) {
        let lde_step = ce_step * self.ce_to_lde_blowup;
        (lde_step, self.lde_domain[lde_step])
    }

    // LOW-DEGREE EXTENSION DOMAIN
    // --------------------------------------------------------------------------------------------

    /// Returns the size of the low-degree extension domain.
    pub fn lde_domain_size(&self) -> usize {
        self.lde_domain.len()
    }

    /// Returns all values in the LDE domain.
    pub fn lde_values(&self) -> &[B] {
        &self.lde_domain
    }

    /// Returns LDE domain offset.
    pub fn offset(&self) -> B {
        self.lde_domain[0]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_lde_domain<B: StarkField>(domain_size: usize, offset: B) -> Vec<B> {
    let g = B::get_root_of_unity(log2(domain_size));
    get_power_series_with_offset(g, offset, domain_size)
}
