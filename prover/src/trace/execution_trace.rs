// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{StarkDomain, TraceLde, TracePolyTable};
use air::{Air, EvaluationFrame, TraceInfo};
use math::{fft, log2, polynom, StarkField};
use utils::{collections::Vec, iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// TRACE TABLE
// ================================================================================================
/// An execution trace of a computation.
///
/// Execution trace is a two-dimensional matrix in which each row represents the state of a
/// computation at a single point in time and each column corresponds to an algebraic register
/// tracked over all steps of the computation.
///
/// There are two ways to create an execution trace.
///
/// First, you can use the [ExecutionTrace::init()] function which takes a set of vectors as a
/// parameter, where each vector contains values for a given column of the trace. This approach
/// allows you to build an execution trace as you see fit, as long as it meets a basic set of
/// requirements. These requirements are:
///
/// 1. Lengths of all columns in the execution trace must be the same.
/// 2. The length of the columns must be some power of two.
///
/// The other approach is to use [ExecutionTrace::new()] function, which takes trace width and
/// length as parameters. This function will allocate memory for the trace, but will not fill it
/// with data. To fill the execution trace, you can use the [fill()](ExecutionTrace::fill) method,
/// which takes two closures as parameters:
///
/// 1. The first closure is responsible for initializing the first state of the computation
///    (the first row of the execution trace).
/// 2. The second closure receives the previous state of the execution trace as input, and must
///    update it to the next state of the computation.
///
/// You can also use [ExecutionTrace::with_meta()] function to create a blank execution trace.
/// This function work just like [ExecutionTrace::new()] function, but also takes a metadata
/// parameter which can be an arbitrary sequence of bytes up to 64KB in size.
///
/// # Concurrent trace generation
/// For computations which consist of many small independent computations, we can generate the
/// execution trace of the entire computation by building fragments of the trace in parallel,
/// and then joining these fragments together.
///
/// For this purpose, `ExecutionTrace` struct exposes [fragments()](ExecutionTrace::fragments)
/// method, which takes fragment length as a parameter, breaks the execution trace into equally
/// sized fragments, and returns an iterator over these fragments. You can then use fragment's
/// [fill()](ExecutionTraceFragment::fill) method to fill all fragments with data in parallel.
/// The semantics of the fragment's [ExecutionTraceFragment::fill()] method are identical to the
/// semantics of the [ExecutionTrace::fill()] method.
pub struct ExecutionTrace<B: StarkField> {
    trace: Vec<Vec<B>>,
    meta: Vec<u8>,
}

impl<B: StarkField> ExecutionTrace<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new execution trace of the specified width and length.
    ///
    /// This allocates all the required memory for the trace, but does not initialize it. It is
    /// expected that the trace will be filled using one of the data mutator methods.
    ///
    /// # Panics
    /// Panics if:
    /// * `width` is zero or greater than 255.
    /// * `length` is smaller than 8, greater than biggest multiplicative subgroup in the field
    ///   `B`, or is not a power of two.
    pub fn new(width: usize, length: usize) -> Self {
        Self::with_meta(width, length, vec![])
    }

    /// Creates a new execution trace of the specified width and length, and with the specified
    /// metadata.
    ///
    /// This allocates all the required memory for the trace, but does not initialize it. It is
    /// expected that the trace will be filled using one of the data mutator methods.
    ///
    /// # Panics
    /// Panics if:
    /// * `width` is zero or greater than 255.
    /// * `length` is smaller than 8, greater than the biggest multiplicative subgroup in the
    ///   field `B`, or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        assert!(
            width > 0,
            "execution trace must consist of at least one register"
        );
        assert!(
            width <= TraceInfo::MAX_TRACE_WIDTH,
            "execution trace width cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            width
        );
        assert!(
            length >= TraceInfo::MIN_TRACE_LENGTH,
            "execution trace must be at lest {} steps long, but was {}",
            TraceInfo::MIN_TRACE_LENGTH,
            length
        );
        assert!(
            length.is_power_of_two(),
            "execution trace length must be a power of 2"
        );
        assert!(
            log2(length) as u32 <= B::TWO_ADICITY,
            "execution trace length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            log2(length)
        );
        assert!(
            meta.len() <= TraceInfo::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            TraceInfo::MAX_META_LENGTH,
            meta.len()
        );

        let registers = unsafe { (0..width).map(|_| uninit_vector(length)).collect() };
        ExecutionTrace {
            trace: registers,
            meta,
        }
    }

    /// Creates a new execution trace from a list of provided register traces.
    ///
    /// The provides `registers` vector is expected to contain register traces.
    ///
    /// # Panics
    /// Panics if:
    /// * The `registers` vector is empty or has over 255 registers.
    /// * Number of elements in any of the registers is smaller than 8, greater than the biggest
    ///   multiplicative subgroup in the field `B`, or is not a power of two.
    /// * Number of elements is not identical for all registers.
    pub fn init(registers: Vec<Vec<B>>) -> Self {
        assert!(
            !registers.is_empty(),
            "execution trace must consist of at least one register"
        );
        assert!(
            registers.len() <= TraceInfo::MAX_TRACE_WIDTH,
            "execution trace width cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            registers.len()
        );
        let trace_length = registers[0].len();
        assert!(
            trace_length >= TraceInfo::MIN_TRACE_LENGTH,
            "execution trace must be at lest {} steps long, but was {}",
            TraceInfo::MIN_TRACE_LENGTH,
            trace_length
        );
        assert!(
            trace_length.is_power_of_two(),
            "execution trace length must be a power of 2"
        );
        assert!(
            log2(trace_length) as u32 <= B::TWO_ADICITY,
            "execution trace length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            log2(trace_length)
        );
        for register in registers.iter() {
            assert_eq!(
                register.len(),
                trace_length,
                "all register traces must have the same length"
            );
        }

        ExecutionTrace {
            trace: registers,
            meta: vec![],
        }
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a value in a single cell of the execution trace.
    ///
    /// Specifically, the value in the specified `register` and the specified `step` is set to the
    /// provide `value`.
    ///
    /// # Panics
    /// Panics if either `register` or `step` are out of bounds for this execution trace.
    pub fn set(&mut self, register: usize, step: usize, value: B) {
        self.trace[register][step] = value;
    }

    /// Updates metadata for this execution trace to the specified vector of bytes.
    ///
    /// # Panics
    /// Panics if the length of `meta` is greater than 65535;
    pub fn set_meta(&mut self, meta: Vec<u8>) {
        assert!(
            meta.len() <= TraceInfo::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            TraceInfo::MAX_META_LENGTH,
            meta.len()
        );
        self.meta = meta
    }

    /// Fill all rows in the execution trace.
    ///
    /// The rows are filled by executing the provided closures as follows:
    /// - `init` closure is used to initialize the first row of the trace; it receives a mutable
    ///   reference to the first state initialized to all zeros. The contents of the state are
    ///   copied into the first row of the trace after the closure returns.
    /// - `update` closure is used to populate all subsequent rows of the trace; it receives two
    ///   parameters:
    ///   - index of the last updated row (starting with 0).
    ///   - a mutable reference to the last updated state; the contents of the state are copied
    ///     into the next row of the trace after the closure returns.
    pub fn fill<I, U>(&mut self, init: I, update: U)
    where
        I: Fn(&mut [B]),
        U: Fn(usize, &mut [B]),
    {
        let mut state = vec![B::ZERO; self.width()];
        init(&mut state);
        self.update_row(0, &state);

        for i in 0..self.length() - 1 {
            update(i, &mut state);
            self.update_row(i + 1, &state);
        }
    }

    /// Updates a single row in the execution trace with provided data.
    pub fn update_row(&mut self, step: usize, state: &[B]) {
        for (register, &value) in self.trace.iter_mut().zip(state) {
            register[step] = value;
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns trace info for this execution trace.
    pub fn get_info(&self) -> TraceInfo {
        TraceInfo::with_meta(self.width(), self.length(), self.meta.clone())
    }

    /// Returns number of registers in the trace table.
    pub fn width(&self) -> usize {
        self.trace.len()
    }

    /// Returns the number of states in this trace table.
    pub fn length(&self) -> usize {
        self.trace[0].len()
    }

    /// Returns value of the cell the specified `register` at the specified `step`.
    pub fn get(&self, register: usize, step: usize) -> B {
        self.trace[register][step]
    }

    /// Returns the entire register trace for the register at the specified index.
    pub fn get_register(&self, idx: usize) -> &[B] {
        &self.trace[idx]
    }

    /// Reads a single row of this trace at the specified `step` into the specified `target`.
    pub fn read_row_into(&self, step: usize, target: &mut [B]) {
        for (i, register) in self.trace.iter().enumerate() {
            target[i] = register[step];
        }
    }

    /// Returns metadata associated with this execution trace.
    pub fn get_meta(&self) -> &[u8] {
        &self.meta
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Checks if this execution trace is valid against the specified AIR, and panics if not.
    ///
    /// NOTE: this is a very expensive operation and is intended for use only in debug mode.
    pub fn validate<A: Air<BaseField = B>>(&self, air: &A) {
        // TODO: eventually, this should return errors instead of panicking

        // make sure the width align; if they don't something went terribly wrong
        assert_eq!(
            self.width(),
            air.trace_width(),
            "inconsistent trace width: expected {}, but was {}",
            self.width(),
            air.trace_width()
        );

        // --- 1. make sure the assertions are valid ----------------------------------------------
        for assertion in air.get_assertions() {
            assertion.apply(self.length(), |step, value| {
                assert!(
                    value == self.get(assertion.register(), step),
                    "trace does not satisfy assertion trace({}, {}) == {}",
                    assertion.register(),
                    step,
                    value
                );
            });
        }

        // --- 2. make sure this trace satisfies all transition constraints -----------------------

        // collect the info needed to build periodic values for a specific step
        let g = air.trace_domain_generator();
        let periodic_values_polys = air.get_periodic_column_polys();
        let mut periodic_values = vec![B::ZERO; periodic_values_polys.len()];

        // initialize buffers to hold evaluation frames and results of constraint evaluations
        let mut x = B::ONE;
        let mut ev_frame = EvaluationFrame::new(self.width());
        let mut evaluations = vec![B::ZERO; air.num_transition_constraints()];

        for step in 0..self.length() - 1 {
            // build periodic values
            for (p, v) in periodic_values_polys.iter().zip(periodic_values.iter_mut()) {
                let num_cycles = air.trace_length() / p.len();
                let x = x.exp((num_cycles as u32).into());
                *v = polynom::eval(p, x);
            }

            // build evaluation frame
            self.read_row_into(step, ev_frame.current_mut());
            self.read_row_into(step + 1, ev_frame.next_mut());

            // evaluate transition constraints
            air.evaluate_transition(&ev_frame, &periodic_values, &mut evaluations);

            // make sure all constraints evaluated to ZERO
            for (i, &evaluation) in evaluations.iter().enumerate() {
                assert!(
                    evaluation == B::ZERO,
                    "transition constraint {} did not evaluate to ZERO at step {}",
                    i,
                    step
                );
            }

            // update x coordinate of the domain
            x *= g;
        }
    }

    // LOW-DEGREE EXTENSION
    // --------------------------------------------------------------------------------------------
    /// Extends all registers of the trace table to the length of the LDE domain.
    ///
    /// The extension is done by first interpolating each register into a polynomial over the
    /// trace domain, and then evaluating the polynomial over the LDE domain.
    pub fn extend(mut self, domain: &StarkDomain<B>) -> (TraceLde<B>, TracePolyTable<B>) {
        assert_eq!(
            self.length(),
            domain.trace_length(),
            "inconsistent trace length"
        );
        // build and cache trace twiddles for FFT interpolation; we do it here so that we
        // don't have to rebuild these twiddles for every register.
        let inv_twiddles = fft::get_inv_twiddles::<B>(domain.trace_length());

        // extend all registers; the extension procedure first interpolates register traces into
        // polynomials (in-place), then evaluates these polynomials over a larger domain, and
        // then returns extended evaluations.
        let extended_trace = iter_mut!(self.trace)
            .map(|register_trace| extend_register(register_trace, domain, &inv_twiddles))
            .collect();

        (
            TraceLde::new(extended_trace, domain.trace_to_lde_blowup()),
            TracePolyTable::new(self.trace),
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn extend_register<B: StarkField>(
    trace: &mut [B],
    domain: &StarkDomain<B>,
    inv_twiddles: &[B],
) -> Vec<B> {
    let domain_offset = domain.offset();
    let twiddles = domain.trace_twiddles();
    let blowup_factor = domain.trace_to_lde_blowup();

    // interpolate register trace into a polynomial; we do this over the un-shifted trace_domain
    fft::interpolate_poly(trace, inv_twiddles);

    // evaluate the polynomial over extended domain; the domain may be shifted by the
    // domain_offset
    fft::evaluate_poly_with_offset(trace, twiddles, domain_offset, blowup_factor)
}
