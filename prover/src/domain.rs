// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::Air;
use math::{fft, get_power_series, StarkField};

// TYPES AND INTERFACES
// ================================================================================================

/// Info about domains related to specific instance of proof generation.
pub struct StarkDomain<B: StarkField> {
    /// Twiddles which can be used to evaluate polynomials in the trace domain. Length of this
    /// vector is half the length of the trace domain size.
    trace_twiddles: Vec<B>,

    /// [g^i for i in (0..ce_domain_size)] where g is the constraint evaluation domain generator.
    ce_domain: Vec<B>,

    /// LDE domain size / constraint evaluation domain size
    ce_to_lde_blowup: usize,

    /// A mask which can be used to compute (x % ce_domain_size) via binary AND. This takes
    /// advantage of the fact that ce_domain_size is a power of two. The mask is then simply
    /// ce_domain_size - 1.
    ce_domain_mod_mask: usize,

    /// Offset of the low-degree extension domain.
    domain_offset: B,
}

// STARK DOMAIN IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> StarkDomain<B> {
    /// Returns a new STARK domain initialized with the provided `context`.
    pub fn new<A: Air<BaseField = B>>(air: &A) -> Self {
        let trace_twiddles = fft::get_twiddles(air.trace_length());

        // build constraint evaluation domain
        let domain_gen = B::get_root_of_unity(air.ce_domain_size().ilog2());
        let ce_domain = get_power_series(domain_gen, air.ce_domain_size());

        StarkDomain {
            trace_twiddles,
            ce_domain,
            ce_to_lde_blowup: air.lde_domain_size() / air.ce_domain_size(),
            ce_domain_mod_mask: air.ce_domain_size() - 1,
            domain_offset: air.domain_offset(),
        }
    }

    /// Returns a new STARK domain initialized with the provided custom inputs.
    pub fn from_twiddles(trace_twiddles: Vec<B>, blowup_factor: usize, domain_offset: B) -> Self {
        // both `trace_twiddles` length and `blowup_factor` must be a power of two.
        assert!(
            trace_twiddles.len().is_power_of_two(),
            "the length of trace twiddles must be a power of 2"
        );
        assert!(blowup_factor.is_power_of_two(), "blowup factor must be a power of 2");

        let ce_domain_size = trace_twiddles.len() * blowup_factor * 2;
        let domain_gen = B::get_root_of_unity(ce_domain_size.ilog2());
        let ce_domain = get_power_series(domain_gen, ce_domain_size);

        StarkDomain {
            trace_twiddles,
            ce_domain,
            ce_to_lde_blowup: 1,
            ce_domain_mod_mask: ce_domain_size - 1,
            domain_offset,
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
        B::get_root_of_unity(self.ce_domain_size().ilog2())
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
    pub fn get_ce_x_power_at(&self, step: usize, power: u64, offset_exp: B) -> B {
        debug_assert_eq!(offset_exp, self.offset().exp(power.into()));
        // this computes (step * power) % ce_domain_size. even though both step and power could be
        // 64-bit values, we are not concerned about overflow here because we are modding by a
        // power of two. this is also the reason why we can do & ce_domain_mod_mask instead of
        // performing the actual modulus operation.
        let index = step.wrapping_mul(power as usize) & self.ce_domain_mod_mask;
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
