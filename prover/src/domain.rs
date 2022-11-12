// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::Air;
use math::{fft, get_power_series, log2, StarkField};
use utils::collections::Vec;

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
}

// STARK DOMAIN IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> StarkDomain<B> {
    /// Returns a new STARK domain initialized with the provided `context`.
    pub fn new<A: Air<BaseField = B>>(air: &A) -> Self {
        // this is needed to ensure that step * power does not overflow in get_ce_x_power_at().
        // in the future, we should revisit this to enable domain sizes greater than 2^32
        assert!(
            air.ce_domain_size() <= 2_usize.pow(32),
            "constraint evaluation domain size cannot exceed {}, but was {}",
            u32::MAX,
            2_usize.pow(32)
        );

        let trace_twiddles = fft::get_twiddles(air.trace_length());

        // build constraint evaluation domain
        let domain_gen = B::get_root_of_unity(log2(air.ce_domain_size()));
        let ce_domain = get_power_series(domain_gen, air.ce_domain_size());

        StarkDomain {
            trace_twiddles,
            ce_to_lde_blowup: air.lde_domain_size() / air.ce_domain_size(),
            domain_offset: air.domain_offset(),
            ce_domain,
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
    #[inline(always)]
    pub fn ce_domain_size(&self) -> usize {
        self.ce_domain.len()
    }

    /// Returns the generator of constraint evaluation domain.
    pub fn ce_domain_generator(&self) -> B {
        B::get_root_of_unity(log2(self.ce_domain_size()))
    }

    /// Returns blowup factor from constraint evaluation to LDE domain.
    pub fn ce_to_lde_blowup(&self) -> usize {
        self.ce_to_lde_blowup
    }

    /// Returns s * g^step where g is the constraint evaluation domain generator and s is the
    /// domain offset.
    #[inline(always)]
    pub fn get_ce_x_at(&self, step: usize) -> B {
        self.ce_domain[step] * self.domain_offset
    }

    /// Returns (s * g^step)^power where g is the constraint evaluation domain generator and s is
    /// the domain offset.
    ///
    /// The computation is performed without doing exponentiations. offset_exp is assumed to be
    /// s^power which is pre-computed elsewhere.
    #[inline(always)]
    pub fn get_ce_x_power_at(&self, step: usize, power: u32, offset_exp: B) -> B {
        let index: usize = step * power as usize;
        let index = index % self.ce_domain_size();
        self.ce_domain[index] * offset_exp
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
