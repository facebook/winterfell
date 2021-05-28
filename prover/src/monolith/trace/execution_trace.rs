// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{StarkDomain, TracePolyTable, TraceTable};
use common::{Air, EvaluationFrame};
use math::{fft, field::StarkField, polynom};
use utils::{iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// CONSTANTS
// ================================================================================================

const MIN_TRACE_LENGTH: usize = 8;
const MIN_FRAGMENT_LENGTH: usize = 2;

// TRACE TABLE
// ================================================================================================
pub struct ExecutionTrace<B: StarkField>(Vec<Vec<B>>);

impl<B: StarkField> ExecutionTrace<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new execution trace of the specified width and length; data in the trace is not
    /// initialized and it is expected that the trace will be filled using one of the data mutator
    /// methods.
    pub fn new(width: usize, length: usize) -> Self {
        assert!(
            width > 0,
            "execution trace must consist of at least one register"
        );
        assert!(
            length >= MIN_TRACE_LENGTH,
            "execution trace must be at lest {} steps long, but was {}",
            MIN_TRACE_LENGTH,
            length
        );
        assert!(
            length.is_power_of_two(),
            "execution trace length must be a power of 2"
        );

        let registers = (0..width).map(|_| uninit_vector(length)).collect();
        ExecutionTrace(registers)
    }

    /// Creates a new execution trace from a list of provided register traces.
    pub fn init(registers: Vec<Vec<B>>) -> Self {
        assert!(
            !registers.is_empty(),
            "execution trace must consist of at least one register"
        );
        let trace_length = registers[0].len();
        assert!(
            trace_length >= MIN_TRACE_LENGTH,
            "execution trace must be at lest {} steps long, but was {}",
            MIN_TRACE_LENGTH,
            trace_length
        );
        assert!(
            trace_length.is_power_of_two(),
            "execution trace length must be a power of 2"
        );
        for register in registers.iter() {
            assert_eq!(
                register.len(),
                trace_length,
                "all register traces must have the same length"
            );
        }

        ExecutionTrace(registers)
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates the value in the execution trace at the specified `register` and the specified
    /// `step` to the specified `value`.
    pub fn set(&mut self, register: usize, step: usize, value: B) {
        self.0[register][step] = value;
    }

    /// Fills all rows in the execution trace using the specified closures as follows:
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

        for i in 0..self.len() - 1 {
            update(i, &mut state);
            self.update_row(i + 1, &state);
        }
    }

    /// Updates a single row in the execution trace with provided data.
    pub fn update_row(&mut self, step: usize, state: &[B]) {
        for (register, &value) in self.0.iter_mut().zip(state) {
            register[step] = value;
        }
    }

    /// Breaks the execution trace into mutable fragments each having the number of rows
    /// specified by `fragment_length` parameter. The returned fragments can be used to
    /// update data in the trace from multiple threads.
    pub fn fragments(&mut self, fragment_length: usize) -> Vec<ExecutionTraceFragment<B>> {
        assert!(
            fragment_length >= MIN_FRAGMENT_LENGTH,
            "fragment length must be at least {}, but was {}",
            MIN_FRAGMENT_LENGTH,
            fragment_length
        );
        assert!(
            fragment_length.is_power_of_two(),
            "fragment length must be a power of 2"
        );
        let num_fragments = self.len() / fragment_length;

        let mut fragment_data = (0..num_fragments).map(|_| Vec::new()).collect::<Vec<_>>();
        self.0.iter_mut().for_each(|column| {
            for (i, fragment) in column.chunks_mut(fragment_length).enumerate() {
                fragment_data[i].push(fragment);
            }
        });

        fragment_data
            .into_iter()
            .enumerate()
            .map(|(i, data)| ExecutionTraceFragment {
                offset: i * fragment_length,
                data,
            })
            .collect()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of registers in the trace table.
    pub fn width(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of states in this trace table.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0[0].len()
    }

    /// Returns value in the specified `register` at the specified `step`.
    pub fn get(&self, register: usize, step: usize) -> B {
        self.0[register][step]
    }

    /// Returns the entire register trace for the register at the specified index.
    pub fn get_register(&self, idx: usize) -> &[B] {
        &self.0[idx]
    }

    /// Reads a single row of this trace at the specified step into the `target`.
    pub fn read_row_into(&self, step: usize, target: &mut [B]) {
        for (i, register) in self.0.iter().enumerate() {
            target[i] = register[step];
        }
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Checks if this execution trace is valid against the specified AIR, and panics if not.
    ///
    /// NOTE: this is a very expensive operation and is intended for use only in debug mode.
    pub fn validate<A: Air<BaseElement = B>>(&self, air: &A) {
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
            assertion.apply(self.len(), |step, value| {
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

        for step in 0..self.len() - 1 {
            // build periodic values
            for (p, v) in periodic_values_polys.iter().zip(periodic_values.iter_mut()) {
                let num_cycles = air.trace_length() / p.len();
                let x = x.exp((num_cycles as u32).into());
                *v = polynom::eval(p, x);
            }

            // build evaluation frame
            self.read_row_into(step, &mut ev_frame.current);
            self.read_row_into(step + 1, &mut ev_frame.next);

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
    /// Extends all registers of the trace table to the length of the LDE domain; The extension
    /// is done by first interpolating a register into a polynomial and then evaluating the
    /// polynomial over the LDE domain.
    pub fn extend(mut self, domain: &StarkDomain<B>) -> (TraceTable<B>, TracePolyTable<B>) {
        assert_eq!(
            self.len(),
            domain.trace_length(),
            "inconsistent trace length"
        );
        // build and cache trace twiddles for FFT interpolation; we do it here so that we
        // don't have to rebuild these twiddles for every register.
        let inv_twiddles = fft::get_inv_twiddles::<B>(domain.trace_length());

        // extend all registers; the extension procedure first interpolates register traces into
        // polynomials (in-place), then evaluates these polynomials over a larger domain, and
        // then returns extended evaluations.
        let extended_trace = iter_mut!(self.0)
            .map(|register_trace| extend_register(register_trace, &domain, &inv_twiddles))
            .collect();

        (
            TraceTable::new(extended_trace, domain.trace_to_lde_blowup()),
            TracePolyTable::new(self.0),
        )
    }
}

// TRACE FRAGMENTS
// ================================================================================================

pub struct ExecutionTraceFragment<'a, B: StarkField> {
    offset: usize,
    data: Vec<&'a mut [B]>,
}

impl<'a, B: StarkField> ExecutionTraceFragment<'a, B> {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------
    /// Returns the step at which the fragment starts.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the length of this execution trace fragment.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data[0].len()
    }

    /// Returns the width of the fragment (same as the width of the underlying table)
    pub fn width(&self) -> usize {
        self.data.len()
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Fills all rows in the fragment using the specified closures as follows:
    /// - `init` closure is used to initialize the first row of the fragment; it receives a
    ///   mutable reference to the first state initialized to all zeros. Contents of the state are
    ///   copied into the first row of the fragment after the closure returns.
    /// - `update` closure is used to populate all subsequent rows of the fragment; it receives two
    ///   parameters:
    ///   - index of the last updated row (starting with 0).
    ///   - a mutable reference to the last updated state; the contents of the state are copied
    ///     into the next row of the fragment after the closure returns.
    pub fn fill<I, T>(&mut self, init_state: I, update_state: T)
    where
        I: Fn(&mut [B]),
        T: Fn(usize, &mut [B]),
    {
        let mut state = vec![B::ZERO; self.width()];
        init_state(&mut state);
        self.update_row(0, &state);

        for i in 0..self.len() - 1 {
            update_state(i, &mut state);
            self.update_row(i + 1, &state);
        }
    }

    /// Updates a single row in the fragment with provided data.
    pub fn update_row(&mut self, row_idx: usize, row_data: &[B]) {
        for (column, &value) in self.data.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
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
