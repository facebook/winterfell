// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{EvaluationFrame, TraceInfo};
use math::StarkField;
use utils::uninit_vector;
#[cfg(feature = "concurrent")]
use utils::{iterators::*, rayon};

use super::{ColMatrix, Trace};

// CONSTANTS
// ================================================================================================

const MIN_FRAGMENT_LENGTH: usize = 2;

// TRACE TABLE
// ================================================================================================
/// A concrete implementation of the [Trace] trait.
///
/// This implementation supports concurrent trace generation and should be sufficient for most use
/// cases. There are two ways to create a trace table trace.
///
/// First, you can use the [TraceTable::init()] function which takes a set of vectors as a
/// parameter, where each vector contains values for a given column of the trace. This approach
/// allows you to build an execution trace as you see fit, as long as it meets a basic set of
/// requirements. These requirements are:
///
/// 1. Lengths of all columns in the execution trace must be the same.
/// 2. The length of the columns must be some power of two.
///
/// The other approach is to use [TraceTable::new()] function, which takes trace width and
/// length as parameters. This function will allocate memory for the trace, but will not fill it
/// with data. To fill the execution trace, you can use the [fill()](TraceTable::fill) method,
/// which takes two closures as parameters:
///
/// 1. The first closure is responsible for initializing the first state of the computation (the
///    first row of the execution trace).
/// 2. The second closure receives the previous state of the execution trace as input, and must
///    update it to the next state of the computation.
///
/// You can also use [TraceTable::with_meta()] function to create a blank execution trace.
/// This function work just like [TraceTable::new()] function, but also takes a metadata
/// parameter which can be an arbitrary sequence of bytes up to 64KB in size.
///
/// # Concurrent trace generation
/// For computations which consist of many small independent computations, we can generate the
/// execution trace of the entire computation by building fragments of the trace in parallel,
/// and then joining these fragments together.
///
/// For this purpose, `TraceTable` struct exposes [fragments()](TraceTable::fragments)
/// method, which takes fragment length as a parameter, breaks the execution trace into equally
/// sized fragments, and returns an iterator over these fragments. You can then use fragment's
/// [fill()](TraceTableFragment::fill) method to fill all fragments with data in parallel.
/// The semantics of the fragment's [TraceTableFragment::fill()] method are identical to the
/// semantics of the [TraceTable::fill()] method.
#[derive(Debug, Clone)]
pub struct TraceTable<B: StarkField> {
    info: TraceInfo,
    trace: ColMatrix<B>,
}

impl<B: StarkField> TraceTable<B> {
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
    /// * `length` is smaller than 8, greater than biggest multiplicative subgroup in the field `B`,
    ///   or is not a power of two.
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
    /// * `length` is smaller than 8, greater than the biggest multiplicative subgroup in the field
    ///   `B`, or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        let info = TraceInfo::with_meta(width, length, meta);
        assert!(
            length.ilog2() <= B::TWO_ADICITY,
            "execution trace length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            length.ilog2()
        );

        let columns = unsafe { (0..width).map(|_| uninit_vector(length)).collect() };

        Self { info, trace: ColMatrix::new(columns) }
    }

    /// Creates a new execution trace from a list of provided trace columns.
    ///
    /// # Panics
    /// Panics if:
    /// * The `columns` vector is empty or has over 255 columns.
    /// * Number of elements in any of the columns is smaller than 8, greater than the biggest
    ///   multiplicative subgroup in the field `B`, or is not a power of two.
    /// * Number of elements is not identical for all columns.
    pub fn init(columns: Vec<Vec<B>>) -> Self {
        assert!(!columns.is_empty(), "execution trace must consist of at least one column");

        let trace_length = columns[0].len();
        let info = TraceInfo::with_meta(columns.len(), trace_length, Vec::new());

        assert!(
            trace_length.ilog2() <= B::TWO_ADICITY,
            "execution trace length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            trace_length.ilog2()
        );

        for column in columns.iter().skip(1) {
            assert_eq!(column.len(), trace_length, "all columns traces must have the same length");
        }

        Self { info, trace: ColMatrix::new(columns) }
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a value in a single cell of the execution trace.
    ///
    /// Specifically, the value in the specified `column` and the specified `step` is set to the
    /// provide `value`.
    ///
    /// # Panics
    /// Panics if either `column` or `step` are out of bounds for this execution trace.
    pub fn set(&mut self, column: usize, step: usize, value: B) {
        self.trace.set(column, step, value)
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
    ///   - a mutable reference to the last updated state; the contents of the state are copied into
    ///     the next row of the trace after the closure returns.
    pub fn fill<I, U>(&mut self, init: I, mut update: U)
    where
        I: FnOnce(&mut [B]),
        U: FnMut(usize, &mut [B]),
    {
        let mut state = vec![B::ZERO; self.info.main_trace_width()];
        init(&mut state);
        self.update_row(0, &state);

        for i in 0..self.info.length() - 1 {
            update(i, &mut state);
            self.update_row(i + 1, &state);
        }
    }

    /// Updates a single row in the execution trace with provided data.
    pub fn update_row(&mut self, step: usize, state: &[B]) {
        self.trace.update_row(step, state);
    }

    // FRAGMENTS
    // --------------------------------------------------------------------------------------------

    /// Breaks the execution trace into mutable fragments.
    ///
    /// The number of rows in each fragment will be equal to `fragment_length` parameter. The
    /// returned fragments can be used to update data in the trace from multiple threads.
    ///
    /// # Panics
    /// Panics if `fragment_length` is smaller than 2, greater than the length of the trace,
    /// or is not a power of two.
    #[cfg(not(feature = "concurrent"))]
    pub fn fragments(
        &mut self,
        fragment_length: usize,
    ) -> alloc::vec::IntoIter<TraceTableFragment<B>> {
        self.build_fragments(fragment_length).into_iter()
    }

    /// Breaks the execution trace into mutable fragments.
    ///
    /// The number of rows in each fragment will be equal to `fragment_length` parameter. The
    /// returned fragments can be used to update data in the trace from multiple threads.
    ///
    /// # Panics
    /// Panics if `fragment_length` is smaller than 2, greater than the length of the trace,
    /// or is not a power of two.
    #[cfg(feature = "concurrent")]
    pub fn fragments(
        &mut self,
        fragment_length: usize,
    ) -> rayon::vec::IntoIter<TraceTableFragment<B>> {
        self.build_fragments(fragment_length).into_par_iter()
    }

    /// Returns a vector of trace fragments each covering the number of steps specified by the
    /// `fragment_length` parameter.
    fn build_fragments(&mut self, fragment_length: usize) -> Vec<TraceTableFragment<B>> {
        assert!(
            fragment_length >= MIN_FRAGMENT_LENGTH,
            "fragment length must be at least {MIN_FRAGMENT_LENGTH}, but was {fragment_length}"
        );
        assert!(
            fragment_length <= self.info.length(),
            "length of a fragment cannot exceed {}, but was {}",
            self.info.length(),
            fragment_length
        );
        assert!(fragment_length.is_power_of_two(), "fragment length must be a power of 2");
        let num_fragments = self.info.length() / fragment_length;

        let mut fragment_data = (0..num_fragments).map(|_| Vec::new()).collect::<Vec<_>>();
        self.trace.columns_mut().for_each(|column| {
            for (i, fragment) in column.chunks_mut(fragment_length).enumerate() {
                fragment_data[i].push(fragment);
            }
        });

        fragment_data
            .into_iter()
            .enumerate()
            .map(|(i, data)| TraceTableFragment {
                index: i,
                offset: i * fragment_length,
                data,
            })
            .collect()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this execution trace.
    pub fn width(&self) -> usize {
        self.info.main_trace_width()
    }

    /// Returns the entire trace column at the specified index.
    pub fn get_column(&self, col_idx: usize) -> &[B] {
        self.trace.get_column(col_idx)
    }

    /// Returns value of the cell in the specified column at the specified row of this trace.
    pub fn get(&self, column: usize, step: usize) -> B {
        self.trace.get(column, step)
    }

    /// Reads a single row from this execution trace into the provided target.
    pub fn read_row_into(&self, step: usize, target: &mut [B]) {
        self.trace.read_row_into(step, target);
    }
}

// TRACE TRAIT IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> Trace for TraceTable<B> {
    type BaseField = B;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = (row_idx + 1) % self.info.length();
        self.trace.read_row_into(row_idx, frame.current_mut());
        self.trace.read_row_into(next_row_idx, frame.next_mut());
    }

    fn main_segment(&self) -> &ColMatrix<B> {
        &self.trace
    }
}

// TRACE FRAGMENTS
// ================================================================================================
/// A set of consecutive rows of an execution trace.
///
/// An execution trace fragment is a "view" into the specific execution trace. Updating data in
/// the fragment, directly updates the data in the underlying execution trace.
///
/// A fragment cannot be instantiated directly but is created by executing
/// [TraceTable::fragments()] method.
///
/// A fragment always contains contiguous rows, and the number of rows is guaranteed to be a power
/// of two.
pub struct TraceTableFragment<'a, B: StarkField> {
    index: usize,
    offset: usize,
    data: Vec<&'a mut [B]>,
}

impl<B: StarkField> TraceTableFragment<'_, B> {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of this fragment.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the step at which the fragment starts in the context of the original execution
    /// trace.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of rows in this execution trace fragment.
    pub fn length(&self) -> usize {
        self.data[0].len()
    }

    /// Returns the width of the fragment (same as the width of the underlying execution trace).
    pub fn width(&self) -> usize {
        self.data.len()
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Fills all rows in the fragment.
    ///
    /// The rows are filled by executing the provided closures as follows:
    /// - `init` closure is used to initialize the first row of the fragment; it receives a mutable
    ///   reference to the first state initialized to all zeros. Contents of the state are copied
    ///   into the first row of the fragment after the closure returns.
    /// - `update` closure is used to populate all subsequent rows of the fragment; it receives two
    ///   parameters:
    ///   - index of the last updated row (starting with 0).
    ///   - a mutable reference to the last updated state; the contents of the state are copied into
    ///     the next row of the fragment after the closure returns.
    pub fn fill<I, T>(&mut self, init_state: I, mut update_state: T)
    where
        I: FnOnce(&mut [B]),
        T: FnMut(usize, &mut [B]),
    {
        let mut state = vec![B::ZERO; self.width()];
        init_state(&mut state);
        self.update_row(0, &state);

        for i in 0..self.length() - 1 {
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
