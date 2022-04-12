// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::Air;
use math::{fft, log2, StarkField};
use utils::collections::Vec;

// TYPES AND INTERFACES
// ================================================================================================

pub struct StarkDomain<B: StarkField> {
    /// Twiddles which can be used to evaluate polynomials in the trace domain. Length of this
    /// vector is half the length of the trace domain size.
    trace_twiddles: Vec<B>,

    /// Size of the constraint evaluation domain.
    ce_domain_size: usize,

    /// LDE domain size / constraint evaluation domain size
    ce_to_lde_blowup: usize,

    /// Offset of the low-degree extension domain.
    domain_offset: B,
}

// STARK DOMAIN IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> StarkDomain<B> {
    /// Returns a new STARK domain initialized with the provided `context`.
    pub fn new<A: Air<BaseField = B>>(air: &A) -> Self {
        let trace_twiddles = fft::get_twiddles(air.trace_length());
        StarkDomain {
            trace_twiddles,
            ce_domain_size: air.ce_domain_size(),
            ce_to_lde_blowup: air.lde_domain_size() / air.ce_domain_size(),
            domain_offset: air.domain_offset(),
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
        self.ce_domain_size
    }

    /// Returns the generator of constraint evaluation domain.
    pub fn ce_domain_generator(&self) -> B {
        B::get_root_of_unity(log2(self.ce_domain_size()))
    }

    /// Returns blowup factor from constraint evaluation to LDE domain.
    pub fn ce_to_lde_blowup(&self) -> usize {
        self.ce_to_lde_blowup
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
