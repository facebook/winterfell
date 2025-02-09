// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{collections::BTreeMap, vec::Vec};

use crypto::{RandomCoin, RandomCoinError};
use math::{fft, ExtensibleField, ExtensionOf, FieldElement, StarkField, ToElements};

use crate::{BatchingMethod, ProofOptions};

mod aux;
pub use aux::AuxRandElements;

mod trace_info;
pub use trace_info::TraceInfo;

mod context;
pub use context::AirContext;

mod assertions;
pub use assertions::Assertion;

mod boundary;
pub use boundary::{BoundaryConstraint, BoundaryConstraintGroup, BoundaryConstraints};

mod transition;
pub use transition::{EvaluationFrame, TransitionConstraintDegree, TransitionConstraints};

mod coefficients;
pub use coefficients::{ConstraintCompositionCoefficients, DeepCompositionCoefficients};

mod divisor;
pub use divisor::ConstraintDivisor;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const MIN_CYCLE_LENGTH: usize = 2;

// AIR TRAIT
// ================================================================================================
/// Describes algebraic intermediate representation of a computation.
///
/// To describe AIR for a given computation, you'll need to implement the `Air` trait which
/// involves the following:
///
/// 1. Define base field for your computation via the [Air::BaseField] associated type (see
///    [math::fields] for available field options).
/// 2. Define a set of public inputs which are required for your computation via the
///    [Air::PublicInputs] associated type.
/// 3. Implement [Air::new()] function. As a part of this function you should create a [AirContext]
///    struct which takes degrees for all transition constraints as one of the constructor
///    parameters.
/// 4. Implement [Air::context()] method which should return a reference to the [AirContext] struct
///    created in [Air::new()] function.
/// 5. Implement [Air::evaluate_transition()] method which should evaluate [transition
///    constraints](#transition-constraints) over a given evaluation frame.
/// 6. Implement [Air::get_assertions()] method which should return a vector of
///    [assertions](#trace-assertions) for a given instance of your computation.
/// 7. If your computation requires [periodic values](#periodic-values), you can also override the
///    default [Air::get_periodic_column_values()] method.
///
/// If your computation uses [Randomized AIR](#randomized-air), you will also need to override
/// [Air::evaluate_aux_transition()] and [Air::get_aux_assertions()] methods.
///
/// ### Transition constraints
/// Transition constraints define algebraic relations between two consecutive steps of a
/// computation. In Winterfell, transition constraints are evaluated inside
/// [Air::evaluate_transition()] function which takes the following parameters:
///
/// - [EvaluationFrame] which contains vectors with current and next states of the computation.
/// - A list of periodic values. When periodic columns are defined for a computation, this will
///   contain values of periodic columns at the current step of the computation. Otherwise, this
///   will be an empty list.
/// - A mutable `result` slice. This is the slice where constraint evaluations should be written to.
///   The length of this slice will be equal to the number of transition constraints defined for the
///   computation.
///
/// The constraints are considered to be satisfied if and only if, after the function returns,
/// the `result` slice contains all zeros. In general, it is important for the transition
/// constraint evaluation function to work as follows:
///
/// * For all valid transitions between consecutive computation steps, transition constraints should
///   evaluation to all zeros.
/// * For any invalid transition, at least one constraint must evaluate to a non-zero value.
///
/// **Note:** since transition constraints define algebraic relations, they should be
/// described using only algebraic operations: additions, subtractions, and multiplications
/// (divisions can be emulated using inverse of multiplication).
///
/// ### Constraint degrees
/// One of the main factors impacting proof generation time and proof size is the maximum degree
/// of transition constraints. The higher is this degree, the larger our blowup factor needs to be.
/// Usually, we want to keep this degree as low as possible - e.g. under 4 or 8. To accurately
/// describe degrees of your transition constraints, keep the following in mind:
///
/// * All trace columns have degree `1`.
/// * When multiplying trace columns together, the degree increases by `1`. For example, if our
///   constraint involves multiplication of two columns, the degree of this constraint will be `2`.
///   We can describe this constraint using [TransitionConstraintDegree] struct as follows:
///   `TransitionConstraintDegree::new(2)`.
/// * Degrees of periodic columns depend on the length of their cycles, but in most cases, these
///   degrees are very close to `1`.
/// * To describe a degree of a constraint involving multiplication of trace columns and periodic
///   columns, use the [TransitionConstraintDegree::with_cycles()] constructor. For example, if our
///   constraint involves multiplication of one trace column and one periodic column with a cycle of
///   32 steps, the degree can be described as: `TransitionConstraintDegree::with_cycles(1,
///   vec![32])`.
///
/// In general, multiplications should be used judiciously - though, there are ways to ease this
/// restriction a bit at the expense of wider execution trace.
///
/// ### Trace assertions
/// Assertions are used to specify that a valid execution trace of a computation must contain
/// certain values in certain cells. They are frequently used to tie public inputs to a specific
/// execution trace, but can be used to constrain a computation in other ways as well.
/// Internally within Winterfell, assertions are converted into *boundary constraints*.
///
/// To define assertions for your computation, you'll need to implement [Air::get_assertions()]
/// function which should return a vector of [Assertion] structs. Every computation must have at
/// least one assertion. Assertions can be of the following types:
///
/// * A single assertion - such assertion specifies that a single cell of an execution trace must be
///   equal to a specific value. For example: *value in column 0, at step 0, must be equal to 1*.
/// * A periodic assertion - such assertion specifies that values in a given column at specified
///   intervals should be equal to some value. For example: *values in column 0, at steps 0, 8, 16,
///   24 etc. must be equal to 2*.
/// * A sequence assertion - such assertion specifies that values in a given column at specific
///   intervals must be equal to a sequence of provided values. For example: *values in column 0, at
///   step 0 must be equal to 1, at step 8 must be equal to 2, at step 16 must be equal to 3 etc.*
///
/// ### Periodic values
/// Sometimes, it may be useful to define a column in an execution trace which contains a set of
/// repeating values. For example, let's say we have a column which contains value 1 on every
/// 4th step, and 0 otherwise. Such a column can be described with a simple periodic sequence of
/// `[1, 0, 0, 0]`.
///
/// To define such columns for your computation, you can override
/// [Air::get_periodic_column_values()] method. The values of the periodic columns at a given
/// step of the computation will be supplied to the [Air::evaluate_transition()] method via the
/// `periodic_values` parameter.
///
/// ### Randomized AIR
/// Randomized AIR is a powerful extension of AIR which enables, among other things, multiset and
/// permutation checks similar to the ones available in PLONKish systems. These, in turn, allow
/// efficient descriptions of "non-local" constraints which can be used to build such components
/// as efficient range checks, random access memory, and many others.
///
/// With Randomized AIR, construction of the execution trace is split into multiple stages. During
/// the first stage, the *main trace segment* is built in a manner similar to how the trace is
/// built for regular AIR. In the subsequent stages, the *auxiliary trace segment* is built. When
/// building the auxiliary trace segment, the prover has access to extra randomness sent by the
/// verifier (in the non-interactive version of the protocol, this randomness is derived from the
/// previous trace segment commitments).
///
/// To describe Randomized AIR, you will need to do the following when implementing the [Air]
/// trait:
/// * The [AirContext] struct returned from [Air::context()] method must be instantiated using
///   [AirContext::new_multi_segment()] constructor. When building AIR context in this way, you will
///   need to provide a [`crate::TraceInfo`] which describes the shape of a multi-segment execution
///   trace.
/// * Override [Air::evaluate_aux_transition()] method. This method is similar to the
///   [Air::evaluate_transition()] method but it also accepts two extra parameters:
///   `aux_evaluation_frame` and `aux_rand_elements`. These parameters are needed for evaluating
///   transition constraints over the auxiliary trace segment.
/// * Override [Air::get_aux_assertions()] method. This method is similar to the
///   [Air::get_assertions()] method, but it should return assertions against columns of the
///   auxiliary trace segment.
pub trait Air: Send + Sync {
    /// Base field for the computation described by this AIR. STARK protocol for this computation
    /// may be executed in the base field, or in an extension of the base fields as specified
    /// by [ProofOptions] struct.
    type BaseField: StarkField + ExtensibleField<2> + ExtensibleField<3>;

    /// A type defining shape of public inputs for the computation described by this protocol.
    /// This could be any type as long as it can be serialized into a sequence of field elements.
    type PublicInputs: ToElements<Self::BaseField> + Send;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns new instance of AIR for this computation instantiated from the provided parameters,
    /// which have the following meaning:
    /// - `trace_info` contains information about a concrete execution trace of the computation
    ///   described by this AIR, including trace width, trace length length, and optionally,
    ///   additional custom parameters in `meta` field.
    /// - `public_inputs` specifies public inputs for this instance of the computation.
    /// - `options` defines proof generation options such as blowup factor, hash function etc. these
    ///   options define security level of the proof and influence proof generation time.
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self;

    /// Returns context for this instance of the computation.
    fn context(&self) -> &AirContext<Self::BaseField>;

    /// Evaluates transition constraints over the specified evaluation frame.
    ///
    /// The evaluations should be written into the `results` slice in the same order as the
    /// the order of transition constraint degree descriptors used to instantiate [AirContext]
    /// for this AIR. Thus, the length of the `result` slice will equal to the number of
    /// transition constraints defined for this computation.
    ///
    /// We define type `E` separately from `Self::BaseField` to allow evaluation of constraints
    /// over the out-of-domain evaluation frame, which may be defined over an extension field
    /// (when extension fields are used).
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    );

    /// Returns a set of assertions against a concrete execution trace of this computation.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>>;

    // AUXILIARY TRACE CONSTRAINTS
    // --------------------------------------------------------------------------------------------

    /// Evaluates transition constraints over the specified evaluation frames for the main and
    /// auxiliary trace segment.
    ///
    /// The evaluations should be written into the `results` slice in the same order as the order
    /// of auxiliary transition constraint degree descriptors used to instantiate [AirContext] for
    /// this AIR. Thus, the length of the `result` slice will equal to the number of auxiliary
    /// transition constraints defined for this computation.
    ///
    /// The default implementation of this function panics. It must be overridden for AIRs
    /// describing computations which require multiple trace segments.
    ///
    /// The types for main and auxiliary trace evaluation frames are defined as follows:
    /// * When the entire protocol is executed in a prime field, types `F` and `E` are the same, and
    ///   thus, both the main and the auxiliary trace frames are defined over the base field.
    /// * When the protocol is executed in an extension field, the main trace frame is defined over
    ///   the base field, while the auxiliary trace frame is defined over the extension field.
    ///
    /// We define type `F` separately from `Self::BaseField` to allow evaluation of constraints
    /// over the out-of-domain evaluation frame, which may be defined over an extension field
    /// (when extension fields are used). The type bounds specified for this function allow the
    /// following:
    /// * `F` and `E` could be the same [StarkField] or extensions of the same [StarkField].
    /// * `F` and `E` could be the same field, because a field is always an extension of itself.
    /// * If `F` and `E` are different, then `E` must be an extension of `F`.
    #[allow(unused_variables)]
    fn evaluate_aux_transition<F, E>(
        &self,
        main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        periodic_values: &[F],
        aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        unimplemented!("evaluation of auxiliary transition constraints has not been implemented");
    }

    /// Returns a set of assertions placed against the auxiliary trace segment.
    ///
    /// The default implementation of this function returns an empty vector. It should be overridden
    /// only if the computation relies on the auxiliary trace segment. In such a case, the vector
    /// returned from this function must contain at least one assertion.
    ///
    /// The column index for assertions is expected to be zero-based across all auxiliary trace
    /// segments. That is, assertion against column 0, is an assertion against the first column of
    /// auxiliary trace segment.
    ///
    /// `aux_rand_elements` holds the random elements used to build all auxiliary columns.
    ///
    /// When the protocol is executed using an extension field, auxiliary assertions are defined
    /// over the extension field. This is in contrast with the assertions returned from
    /// [get_assertions()](Air::get_assertions) function, which always returns assertions defined
    /// over the base field of the protocol.
    #[allow(unused_variables)]
    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        Vec::new()
    }

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a vector of field elements required for construction of the auxiliary trace segment.
    ///
    /// The elements are drawn uniformly at random from the provided public coin.
    fn get_aux_rand_elements<E, R>(
        &self,
        public_coin: &mut R,
    ) -> Result<AuxRandElements<E>, RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        R: RandomCoin<BaseField = Self::BaseField>,
    {
        let num_elements = self.trace_info().get_num_aux_segment_rand_elements();
        let mut rand_elements = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            rand_elements.push(public_coin.draw()?);
        }
        Ok(AuxRandElements::new(rand_elements))
    }

    /// Returns values for all periodic columns used in the computation.
    ///
    /// These values will be used to compute column values at specific states of the computation
    /// and passed in to the [evaluate_transition()](Air::evaluate_transition) method as
    /// `periodic_values` parameter.
    ///
    /// The default implementation of this method returns an empty vector. For computations which
    /// rely on periodic columns, this method should be overridden in the specialized
    /// implementation. Number of values for each periodic column must be a power of two.
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        Vec::new()
    }

    /// Returns polynomial for all periodic columns.
    ///
    /// These polynomials are interpolated from the values returned from the
    /// [get_periodic_column_values()](Air::get_periodic_column_values) method.
    fn get_periodic_column_polys(&self) -> Vec<Vec<Self::BaseField>> {
        // cache inverse twiddles for each cycle length so that we don't have to re-build them
        // for columns with identical cycle lengths
        let mut twiddle_map = BTreeMap::new();
        // iterate over all periodic columns and convert column values into polynomials
        self.get_periodic_column_values()
            .into_iter()
            .map(|mut column| {
                let cycle_length = column.len();
                assert!(
                    cycle_length >= MIN_CYCLE_LENGTH,
                    "number of values in a periodic column must be at least {MIN_CYCLE_LENGTH}, but was {cycle_length}"
                );
                assert!(
                    cycle_length.is_power_of_two(),
                    "number of values in a periodic column must be a power of two, but was {cycle_length}"
                );
                assert!(cycle_length <= self.trace_length(),
                    "number of values in a periodic column cannot exceed trace length {}, but was {}",
                    self.trace_length(),
                    cycle_length
                );

                // get twiddles for interpolation and interpolate values into a polynomial
                let inv_twiddles = twiddle_map
                    .entry(cycle_length)
                    .or_insert_with(|| fft::get_inv_twiddles::<Self::BaseField>(cycle_length));
                fft::interpolate_poly(&mut column, inv_twiddles);
                column
            })
            .collect()
    }

    /// Groups transition constraints together by their degree.
    ///
    /// This function also assigns composition coefficients to each constraint. These coefficients
    /// will be used to compute a random linear combination of transition constraints evaluations
    /// during constraint merging performed by [TransitionConstraintGroup::merge_evaluations()]
    /// function.
    fn get_transition_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_coefficients: &[E],
    ) -> TransitionConstraints<E> {
        TransitionConstraints::new(self.context(), composition_coefficients)
    }

    /// Convert assertions returned from [get_assertions()](Air::get_assertions) and
    /// [get_aux_assertions()](Air::get_aux_assertions) methods into boundary constraints.
    ///
    /// This function also assigns composition coefficients to each constraint, and groups the
    /// constraints by their divisors. The coefficients will be used to compute random linear
    /// combination of boundary constraints during constraint merging.
    fn get_boundary_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        aux_rand_elements: Option<&AuxRandElements<E>>,
        composition_coefficients: &[E],
    ) -> BoundaryConstraints<E> {
        BoundaryConstraints::new(
            self.context(),
            self.get_assertions(),
            aux_rand_elements
                .map(|aux_rand_elements| self.get_aux_assertions(aux_rand_elements))
                .unwrap_or_default(),
            composition_coefficients,
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns options which specify STARK protocol parameters for an instance of the computation
    /// described by this AIR.
    fn options(&self) -> &ProofOptions {
        &self.context().options
    }

    /// Returns info of the execution trace for an instance of the computation described by
    /// this AIR.
    fn trace_info(&self) -> &TraceInfo {
        &self.context().trace_info
    }

    /// Returns length of the execution trace for an instance of the computation described by
    /// this AIR.
    ///
    /// This is guaranteed to be a power of two greater than or equal to 8.
    fn trace_length(&self) -> usize {
        self.context().trace_info.length()
    }

    /// Returns degree of trace polynomials for an instance of the computation described by
    /// this AIR.
    ///
    /// The degree is always `trace_length` - 1.
    fn trace_poly_degree(&self) -> usize {
        self.context().trace_poly_degree()
    }

    /// Returns the generator of the trace domain for an instance of the computation described
    /// by this AIR.
    ///
    /// The generator is the $n$th root of unity where $n$ is the length of the execution trace.
    fn trace_domain_generator(&self) -> Self::BaseField {
        self.context().trace_domain_generator
    }

    /// Returns constraint evaluation domain blowup factor for the computation described by this
    /// AIR.
    ///
    /// The blowup factor is defined as the smallest power of two greater than or equal to the
    /// hightest transition constraint degree. For example, if the hightest transition
    /// constraint degree = 3, `ce_blowup_factor` will be set to 4.
    ///
    /// `ce_blowup_factor` is guaranteed to be smaller than or equal to the `lde_blowup_factor`.
    fn ce_blowup_factor(&self) -> usize {
        self.context().ce_blowup_factor
    }

    /// Returns size of the constraint evaluation domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length * ce_blowup_factor`.
    fn ce_domain_size(&self) -> usize {
        self.context().ce_domain_size()
    }

    /// Returns low-degree extension domain blowup factor for the computation described by this
    /// AIR. This is guaranteed to be a power of two, and is always either equal to or greater
    /// than ce_blowup_factor.
    fn lde_blowup_factor(&self) -> usize {
        self.context().options.blowup_factor()
    }

    /// Returns the size of the low-degree extension domain.
    ///
    /// This is guaranteed to be a power of two, and is equal to `trace_length * lde_blowup_factor`.
    fn lde_domain_size(&self) -> usize {
        self.context().lde_domain_size()
    }

    /// Returns the generator of the low-degree extension domain for an instance of the
    /// computation described by this AIR.
    ///
    /// The generator is the $n$th root of unity where $n$ is the size of the low-degree extension
    /// domain.
    fn lde_domain_generator(&self) -> Self::BaseField {
        self.context().lde_domain_generator
    }

    /// Returns the offset by which the domain for low-degree extension is shifted in relation
    /// to the execution trace domain.
    fn domain_offset(&self) -> Self::BaseField {
        self.context().options.domain_offset()
    }

    // LINEAR COMBINATION COEFFICIENTS
    // --------------------------------------------------------------------------------------------

    /// Returns coefficients needed for random linear combination during construction of constraint
    /// composition polynomial.
    fn get_constraint_composition_coefficients<E, R>(
        &self,
        public_coin: &mut R,
    ) -> Result<ConstraintCompositionCoefficients<E>, RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        R: RandomCoin<BaseField = Self::BaseField>,
    {
        match self.context().options.constraint_batching_method() {
            BatchingMethod::Linear => ConstraintCompositionCoefficients::draw_linear(
                public_coin,
                self.context().num_transition_constraints(),
                self.context().num_assertions(),
            ),
            BatchingMethod::Algebraic => ConstraintCompositionCoefficients::draw_algebraic(
                public_coin,
                self.context().num_transition_constraints(),
                self.context().num_assertions(),
            ),
        }
    }

    /// Returns coefficients needed for random linear combinations during construction of DEEP
    /// composition polynomial.
    fn get_deep_composition_coefficients<E, R>(
        &self,
        public_coin: &mut R,
    ) -> Result<DeepCompositionCoefficients<E>, RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        R: RandomCoin<BaseField = Self::BaseField>,
    {
        match self.context().options.deep_poly_batching_method() {
            BatchingMethod::Linear => DeepCompositionCoefficients::draw_linear(
                public_coin,
                self.trace_info().width(),
                self.context().num_constraint_composition_columns(),
            ),
            BatchingMethod::Algebraic => DeepCompositionCoefficients::draw_algebraic(
                public_coin,
                self.trace_info().width(),
                self.context().num_constraint_composition_columns(),
            ),
        }
    }
}
