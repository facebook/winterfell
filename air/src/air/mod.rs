// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ProofOptions;
use crypto::{Hasher, RandomCoin, RandomCoinError};
use math::{fft, ExtensibleField, FieldElement, StarkField};
use utils::{
    collections::{BTreeMap, BTreeSet, Vec},
    Serializable,
};

mod trace_info;
pub use trace_info::TraceInfo;

mod context;
pub use context::AirContext;

mod assertions;
pub use assertions::Assertion;

mod boundary;
pub use boundary::{BoundaryConstraint, BoundaryConstraintGroup};

mod transition;
pub use transition::{EvaluationFrame, TransitionConstraintDegree, TransitionConstraintGroup};

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
/// 3. Implement [Air::new()] function. As a part of this function you should create a
///    [AirContext] struct which takes degrees for all transition constraints as one of
///    the constructor parameters.
/// 4. Implement [Air::context()] method which should return a reference to the
///    [AirContext] struct created in [Air::new()] function.
/// 5. Implement [Air::evaluate_transition()] method which should evaluate
///    [transition constraints](#transition-constraints) over a given evaluation frame.
/// 6. Implement [Air::get_assertions()] method which should return a vector of
///    [assertions](#trace-assertions) for a given instance of your computation.
/// 7. If your computation requires [periodic values](#periodic-values), you can also override
///    the default [Air::get_periodic_column_values()] method.
///
/// ### Transition constraints
/// Transition constraints define algebraic relations between two consecutive steps of a
/// computation. In Winterfell, transition constraints are evaluated inside
/// [Air::evaluate_transition()] function which takes the following parameters:
///
/// - [EvaluationFrame] which contains vectors with current and next states of the
///   computation.
/// - A list of periodic values. When periodic columns are defined for a computation,
///   this will contain values of periodic columns at the current step of the computation.
///   Otherwise, this will be an empty list.
/// - A mutable `result` slice. This is the slice where constraint evaluations should be
///   written to. The length of this slice will be equal to the number of transition
///   constraints defined for the computation.
///
/// The constraints are considered to be satisfied if and only if, after the function returns,
/// the `result` slice contains all zeros. In general, it is important for the transition
/// constraint evaluation function to work as follows:
///
/// * For all valid transitions between consecutive computation steps, transition constraints
///   should evaluation to all zeros.
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
/// * All trace registers have degree `1`.
/// * When multiplying trace registers together, the degree increases by `1`. For example, if our
///   constraint involves multiplication of two registers, the degree of this constraint will be
///   `2`. We can describe this constraint using [TransitionConstraintDegree] struct as follows:
///   `TransitionConstraintDegree::new(2)`.
/// * Degrees of periodic columns depend on the length of their cycles, but in most cases, these
///   degrees are very close to `1`.
/// * To describe a degree of a constraint involving multiplication of trace registers and
///   periodic columns, use the [TransitionConstraintDegree::with_cycles()] constructor. For
///   example, if our constraint involves multiplication of one trace register and one periodic
///   column with a cycle of 32 steps, the degree can be described as:
///   `TransitionConstraintDegree::with_cycles(1, vec![32])`.
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
/// * A single assertion - such assertion specifies that a single cell of an execution trace must
///   be equal to a specific value. For example: *value in register 0, at step 0, must be equal
///   to 1*.
/// * A periodic assertion - such assertion specifies that values in a given register at specified
///   intervals should be equal to some value. For example: *values in register 0, at steps 0, 8,
///   16, 24 etc. must be equal to 2*.
/// * A sequence assertion - such assertion specifies that values in a given register at specific
///   intervals must be equal to a sequence of provided values. For example: *values in register 0,
///   at step 0 must be equal to 1, at step 8 must be equal to 2, at step 16 must be equal to 3
///   etc.*
///
/// ### Periodic values
/// Sometimes, it may be useful to define a column in an execution trace which contains a set of
/// repeating values. For example, let's say we have a register which contains value 1 on every
/// 4th step, and 0 otherwise. Such a column can be described with a simple periodic sequence of
/// `[1, 0, 0, 0]`.
///
/// To define such columns for your computation, you can override
/// [Air::get_periodic_column_values()] method. The values of the periodic columns at a given
/// step of the computation will be supplied to the [Air::evaluate_transition()] method via the
/// `periodic_values` parameter.
pub trait Air: Send + Sync {
    /// Base field for the computation described by this AIR. STARK protocol for this computation
    /// may be executed in the base field, or in an extension of the base fields as specified
    /// by [ProofOptions] struct.
    type BaseField: StarkField + ExtensibleField<2> + ExtensibleField<3>;

    /// A type defining shape of public inputs for the computation described by this protocol.
    /// This could be any type as long as it can be serialized into a sequence of bytes.
    type PublicInputs: Serializable;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns new instance of AIR for this computation instantiated from the provided parameters,
    /// which have the following meaning:
    /// - `trace_info` contains information about a concrete execution trace of the computation
    ///   described by this AIR, including trace width, trace length length, and optionally,
    ///   additional custom parameters in `meta` field.
    /// - `public_inputs` specifies public inputs for this instance of the computation.
    /// - `options` defines proof generation options such as blowup factor, hash function etc.
    ///   these options define security level of the proof and influence proof generation time.
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self;

    /// Returns context for this instance of the computation.
    fn context(&self) -> &AirContext<Self::BaseField>;

    /// Evaluates transition constraints over the specified evaluation frame.
    ///
    /// The evaluations should be written into the `results` slice in the same order as the
    /// the order of transition constraint degree descriptors used to instantiate [AirContext]
    /// for this AIR. Thus, the length of the `result` slice will equal to the number of
    /// transition constraints defined for this computation.
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    );

    /// Returns a set of assertions against a concrete execution trace of this computation.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

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
                    "number of values in a periodic column must be at least {}, but was {}",
                    MIN_CYCLE_LENGTH,
                    cycle_length
                );
                assert!(
                    cycle_length.is_power_of_two(),
                    "number of values in a periodic column must be a power of two, but was {}",
                    cycle_length
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
    /// This function also assigns coefficients to each constraint. These coefficients will be
    /// used to compute a random linear combination of transition constraints evaluations during
    /// constraint merging performed by [TransitionConstraintGroup::merge_evaluations()] function.
    fn get_transition_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        coefficients: &[(E, E)],
    ) -> Vec<TransitionConstraintGroup<E>> {
        assert_eq!(
            self.num_transition_constraints(),
            coefficients.len(),
            "number of transition constraints must match the number of coefficient tuples"
        );

        // iterate over all transition constraint degrees, and assign each constraint to the
        // appropriate group based on degree
        let context = self.context();
        let mut groups = BTreeMap::new();
        for (i, degree) in context.transition_constraint_degrees.iter().enumerate() {
            let evaluation_degree = degree.get_evaluation_degree(self.trace_length());
            let group = groups.entry(evaluation_degree).or_insert_with(|| {
                TransitionConstraintGroup::new(
                    degree.clone(),
                    self.trace_poly_degree(),
                    self.composition_degree(),
                )
            });
            group.add(i, coefficients[i]);
        }

        // convert from hash map into a vector and return
        groups.into_iter().map(|e| e.1).collect()
    }

    /// Convert assertions returned from [get_assertions()](Air::get_assertions) method into
    /// boundary constraints.
    ///
    /// This function also assign coefficients to each constraint, and group the constraints by
    /// denominator. The coefficients will be used to compute random linear combination of boundary
    /// constraints during constraint merging.
    fn get_boundary_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        coefficients: &[(E, E)],
    ) -> Vec<BoundaryConstraintGroup<Self::BaseField, E>> {
        // compute inverse of the trace domain generator; this will be used for offset
        // computations when creating sequence constraints
        let inv_g = self.trace_domain_generator().inv();

        // cache inverse twiddles for multi-value assertions in this map so that we don't have
        // to re-build them for assertions with identical strides
        let mut twiddle_map = BTreeMap::new();

        // get the assertions for this computation and make sure that they are all valid in
        // the context of this computation; also, sort the assertions in the deterministic order
        // so that changing the order of assertions does not change random coefficients that
        // get assigned to them
        let assertions = prepare_assertions(self.get_assertions(), self.context());
        assert_eq!(
            assertions.len(),
            coefficients.len(),
            "number of assertions must match the number of coefficient tuples"
        );

        // iterate over all assertions, which are sorted first by stride and then by first_step
        // in ascending order
        let mut groups = BTreeMap::new();
        for (i, assertion) in assertions.into_iter().enumerate() {
            let key = (assertion.stride(), assertion.first_step());
            let group = groups.entry(key).or_insert_with(|| {
                BoundaryConstraintGroup::new(
                    ConstraintDivisor::from_assertion(&assertion, self.trace_length()),
                    self.trace_poly_degree(),
                    self.composition_degree(),
                )
            });

            // add a new assertion constraint to the current group (last group in the list)
            group.add(assertion, inv_g, &mut twiddle_map, coefficients[i]);
        }

        // make sure groups are sorted by adjustment degree
        let mut groups = groups.into_iter().map(|e| e.1).collect::<Vec<_>>();
        groups.sort_by_key(|c| c.degree_adjustment());

        groups
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
    // This is guaranteed to be greater than or equal to 8 and a power of two.
    fn trace_length(&self) -> usize {
        self.context().trace_info.length()
    }

    /// Returns width of the execution trace for an instance of the computation described by
    /// this AIR.
    ///
    /// This is guaranteed to be between 1 and 255.
    fn trace_width(&self) -> usize {
        self.context().trace_info.width()
    }

    /// Returns degree of trace polynomials for an instance of the computation described by
    /// this AIR.
    ///
    /// The degree is always `trace_length` - 1.
    fn trace_poly_degree(&self) -> usize {
        self.trace_length() - 1
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
        self.trace_length() * self.ce_blowup_factor()
    }

    /// Returns the degree to which all constraint polynomials are normalized before they are
    /// composed together.
    ///
    /// This degree is one less than the size of constraint evaluation domain.
    fn composition_degree(&self) -> usize {
        self.ce_domain_size() - 1
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
        self.trace_length() * self.lde_blowup_factor()
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

    /// Returns a list of transition constraint degree description for an instance of the
    /// computation described by this AIR.
    ///
    /// This list will be identical to the list passed into the [AirContext::new()] method as
    /// the `transition_constraint_degrees` parameter.
    fn transition_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.context().transition_constraint_degrees
    }

    /// Returns the number of transition constraints for an instance of the computation described
    /// by this AIR.
    ///
    /// The number of transition constraints is defined by the number of transition constraint
    /// degree descriptors.
    fn num_transition_constraints(&self) -> usize {
        self.context().transition_constraint_degrees.len()
    }

    /// Returns a divisor for transition constraints.
    ///
    /// All transition constraints have the same divisor which has the form:
    /// $$
    /// z(x) = \frac{x^n - 1}{x - g^{n - 1}}
    /// $$
    /// where: $n$ is the length of the execution trace and $g$ is the generator of the trace
    /// domain.
    ///
    /// This divisor specifies that transition constraints must hold on all steps of the
    /// execution trace except for the last one.
    fn transition_constraint_divisor(&self) -> ConstraintDivisor<Self::BaseField> {
        ConstraintDivisor::from_transition(self.trace_length())
    }

    // LINEAR COMBINATION COEFFICIENTS
    // --------------------------------------------------------------------------------------------

    /// Returns coefficients needed for random linear combination during construction of constraint
    /// composition polynomial.
    fn get_constraint_composition_coefficients<E, H>(
        &self,
        public_coin: &mut RandomCoin<Self::BaseField, H>,
    ) -> Result<ConstraintCompositionCoefficients<E>, RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        H: Hasher,
    {
        let mut t_coefficients = Vec::new();
        for _ in 0..self.num_transition_constraints() {
            t_coefficients.push(public_coin.draw_pair()?);
        }

        // TODO: calling self.get_assertions() is heavy; find a better way to specify the number
        // assertions
        let mut b_coefficients = Vec::new();
        for _ in 0..self.get_assertions().len() {
            b_coefficients.push(public_coin.draw_pair()?);
        }

        Ok(ConstraintCompositionCoefficients {
            transition: t_coefficients,
            boundary: b_coefficients,
        })
    }

    /// Returns coefficients needed for random linear combinations during construction of DEEP
    /// composition polynomial.
    fn get_deep_composition_coefficients<E, H>(
        &self,
        public_coin: &mut RandomCoin<Self::BaseField, H>,
    ) -> Result<DeepCompositionCoefficients<E>, RandomCoinError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        H: Hasher,
    {
        let mut t_coefficients = Vec::new();
        for _ in 0..self.trace_width() {
            t_coefficients.push(public_coin.draw_triple()?);
        }

        // self.ce_blowup_factor() is the same as number of composition columns
        let mut c_coefficients = Vec::new();
        for _ in 0..self.ce_blowup_factor() {
            c_coefficients.push(public_coin.draw()?);
        }

        Ok(DeepCompositionCoefficients {
            trace: t_coefficients,
            constraints: c_coefficients,
            degree: public_coin.draw_pair()?,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Makes sure the assertions are valid in the context of this computation and don't overlap with
/// each other - i.e. no two assertions are placed against the same register and step combination.
fn prepare_assertions<B: StarkField>(
    assertions: Vec<Assertion<B>>,
    context: &AirContext<B>,
) -> Vec<Assertion<B>> {
    // we use a sorted set to help us sort the assertions by their 'natural' order. The natural
    // order is defined as sorting first by stride, then by first step, and finally by register,
    // all in ascending order.
    let mut result = BTreeSet::<Assertion<B>>::new();

    for assertion in assertions.into_iter() {
        assertion
            .validate_trace_width(context.trace_info.width())
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        assertion
            .validate_trace_length(context.trace_info.length())
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        for a in result.iter().filter(|a| a.register == assertion.register) {
            assert!(
                !a.overlaps_with(&assertion),
                "assertion {} overlaps with assertion {}",
                assertion,
                a
            );
        }

        result.insert(assertion);
    }

    result.into_iter().collect()
}
