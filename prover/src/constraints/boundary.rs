// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{Air, AuxTraceRandElements, ConstraintDivisor};
use math::{fft, ExtensionOf, FieldElement};
use utils::collections::{BTreeMap, Vec};

// CONSTANTS
// ================================================================================================

/// Boundary polynomials with this degree or smaller will be evaluated on the fly, while for
/// larger polynomials all evaluations over the constraint evaluation domain will be pre-computed.
const SMALL_POLY_DEGREE: usize = 63;

// BOUNDARY CONSTRAINTS
// ================================================================================================

/// Contains all boundary constraints defined for an instance of a computation. This includes
/// constraints against the main segment of the execution trace as well as constraints against
/// auxiliary trace segments (if any).
///
/// We transform the constraints defined in the [air] crate into specialized constraints here
/// to make evaluation of these constraints more efficient in the prover context.
pub struct BoundaryConstraints<E: FieldElement>(Vec<BoundaryConstraintGroup<E>>);

impl<E: FieldElement> BoundaryConstraints<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [BoundaryConstraints] constructed from the constraints defined
    /// by an instance of AIR for a specific computation.
    pub fn new<A: Air<BaseField = E::BaseField>>(
        air: &A,
        aux_rand_elements: &AuxTraceRandElements<E>,
        composition_coefficients: &[(E, E)],
    ) -> Self {
        // get constraints from the AIR instance
        let source = air.get_boundary_constraints(aux_rand_elements, composition_coefficients);

        // initialize a map of twiddles here so that we can keep track of already computed
        // twiddles; this helps us avoid building twiddles over and over again for constraints
        // defined over the same domain. twiddles are relevant only for large polynomial
        // constraints.
        let mut twiddle_map = BTreeMap::new();

        // transform constraints against the main segment of the execution trace into specialized
        // constraints
        let mut result = source
            .main_constraints()
            .iter()
            .map(|group| {
                BoundaryConstraintGroup::from_main_constraints(group, air, &mut twiddle_map)
            })
            .collect::<Vec<BoundaryConstraintGroup<E>>>();

        // transform constraints against auxiliary trace segments (if any) into specialized
        // constraints. this also checks if a group with the same divisor has already been
        // transformed (when processing constraints against the main trace above), and if so,
        // appends constraints to that group rather than creating a new group. this ensures
        // that we always end up with a single constraint group for the same divisor.
        for group in source.aux_constraints() {
            match result.iter_mut().find(|g| &g.divisor == group.divisor()) {
                Some(x) => x.add_aux_constraints(group, air, &mut twiddle_map),
                None => {
                    let group =
                        BoundaryConstraintGroup::from_aux_constraints(group, air, &mut twiddle_map);
                    result.push(group);
                }
            };
        }

        Self(result)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a vector of all boundary constraint divisors.
    pub fn get_divisors(&self) -> Vec<ConstraintDivisor<E::BaseField>> {
        self.0.iter().map(|g| g.divisor.clone()).collect()
    }

    // EVALUATORS
    // --------------------------------------------------------------------------------------------

    /// Evaluates boundary constraints against the main segment of an execution trace at the
    /// specified step of constraint evaluation domain.
    ///
    /// Specifically, `step` is the step in the constraint evaluation domain, and `x` is the
    /// corresponding domain value. That is, x = s * g^step, where g is the generator of the
    /// constraint evaluation domain, and s is the domain offset.
    pub fn evaluate_main(
        &self,
        main_state: &[E::BaseField],
        x: E::BaseField,
        step: usize,
        result: &mut [E],
    ) {
        // compute the adjustment degree outside of the group so that we can re-use
        // it for groups which have the same adjustment degree
        let mut degree_adjustment = self.0[0].degree_adjustment;
        let mut xp: E::BaseField = x.exp(degree_adjustment.into());

        for (group, result) in self.0.iter().zip(result.iter_mut()) {
            // recompute adjustment degree only when it has changed
            if group.degree_adjustment != degree_adjustment {
                degree_adjustment = group.degree_adjustment;
                xp = x.exp(degree_adjustment.into());
            }
            // evaluate the group and save the result
            *result = group.evaluate_main(main_state, step, x, xp);
        }
    }

    /// Evaluates boundary constraints against all segments of an execution trace at the
    /// specified step of constraint evaluation domain.
    ///
    /// Specifically, `step` is the step in the constraint evaluation domain, and `x` is the
    /// corresponding domain value. That is, x = s * g^step, where g is the generator of the
    /// constraint evaluation domain, and s is the domain offset.
    pub fn evaluate_all(
        &self,
        main_state: &[E::BaseField],
        aux_state: &[E],
        x: E::BaseField,
        step: usize,
        result: &mut [E],
    ) {
        // compute the adjustment degree outside of the group so that we can re-use
        // it for groups which have the same adjustment degree
        let mut degree_adjustment = self.0[0].degree_adjustment;
        let mut xp: E::BaseField = x.exp(degree_adjustment.into());

        for (group, result) in self.0.iter().zip(result.iter_mut()) {
            // recompute adjustment degree only when it has changed
            if group.degree_adjustment != degree_adjustment {
                degree_adjustment = group.degree_adjustment;
                xp = x.exp(degree_adjustment.into());
            }
            // evaluate the group and save the result
            *result = group.evaluate_all(main_state, aux_state, step, x, xp);
        }
    }
}

// BOUNDARY CONSTRAINT GROUP
// ================================================================================================

/// Contains constraints all having the same divisor. The constraints are separated into single
/// value constraints, small polynomial constraints, and large polynomial constraints.
///
/// The constraints are also separated into constraints against the main segment of the execution
/// and the constraints against auxiliary segments of the execution trace (if any).
pub struct BoundaryConstraintGroup<E: FieldElement> {
    divisor: ConstraintDivisor<E::BaseField>,
    degree_adjustment: u32,
    // main trace constraints
    main_single_value: Vec<SingleValueConstraint<E::BaseField, E>>,
    main_small_poly: Vec<SmallPolyConstraint<E::BaseField, E>>,
    main_large_poly: Vec<LargePolyConstraint<E::BaseField, E>>,
    // auxiliary trace constraints
    aux_single_value: Vec<SingleValueConstraint<E, E>>,
    aux_small_poly: Vec<SmallPolyConstraint<E, E>>,
    aux_large_poly: Vec<LargePolyConstraint<E, E>>,
}

impl<E: FieldElement> BoundaryConstraintGroup<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an empty [BoundaryConstraintGroup] instantiated with the specified divisor and
    /// degree adjustment factor.
    fn new(divisor: ConstraintDivisor<E::BaseField>, degree_adjustment: u32) -> Self {
        Self {
            divisor,
            degree_adjustment,
            main_single_value: Vec::new(),
            main_small_poly: Vec::new(),
            main_large_poly: Vec::new(),
            aux_single_value: Vec::new(),
            aux_small_poly: Vec::new(),
            aux_large_poly: Vec::new(),
        }
    }

    /// Returns a [BoundaryConstraintGroup] created from the specified group of constraints against
    /// the main segment of an execution trace. Constraints against auxiliary trace segment in this
    /// group will be empty.
    ///
    /// Twiddles and [Air] instance are passed in for evaluating large polynomial constraints
    /// (if any).
    pub fn from_main_constraints<A: Air<BaseField = E::BaseField>>(
        source: &air::BoundaryConstraintGroup<E::BaseField, E>,
        air: &A,
        twiddle_map: &mut BTreeMap<usize, Vec<E::BaseField>>,
    ) -> Self {
        let mut result = Self::new(source.divisor().clone(), source.degree_adjustment());

        for constraint in source.constraints() {
            if constraint.poly().len() == 1 {
                let constraint = SingleValueConstraint::new(constraint);
                result.main_single_value.push(constraint);
            } else if constraint.poly().len() < SMALL_POLY_DEGREE {
                let constraint = SmallPolyConstraint::new(constraint);
                result.main_small_poly.push(constraint);
            } else {
                let constraint = LargePolyConstraint::new(constraint, air, twiddle_map);
                result.main_large_poly.push(constraint);
            }
        }

        result
    }

    /// Returns a [BoundaryConstraintGroup] created from the specified group of constraints against
    /// auxiliary segments of an execution trace. Constraints against the main trace segment in this
    /// group will be empty.
    ///
    /// Twiddles and [Air] instance are passed in for evaluating large polynomial constraints
    /// (if any).
    pub fn from_aux_constraints<A: Air<BaseField = E::BaseField>>(
        group: &air::BoundaryConstraintGroup<E, E>,
        air: &A,
        twiddle_map: &mut BTreeMap<usize, Vec<E::BaseField>>,
    ) -> Self {
        let mut result = Self::new(group.divisor().clone(), group.degree_adjustment());
        result.add_aux_constraints(group, air, twiddle_map);
        result
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided constraints against auxiliary segments of an execution trace to this
    /// group.
    ///
    /// Twiddles and [Air] instance are passed in for evaluating large polynomial constraints
    /// (if any).
    ///
    /// # Panics
    /// Panics if the divisor of the provided constraints doesn't match the divisor of this group.
    pub fn add_aux_constraints<A: Air<BaseField = E::BaseField>>(
        &mut self,
        group: &air::BoundaryConstraintGroup<E, E>,
        air: &A,
        twiddle_map: &mut BTreeMap<usize, Vec<E::BaseField>>,
    ) {
        assert_eq!(
            group.divisor(),
            &self.divisor,
            "inconsistent constraint divisor"
        );

        for constraint in group.constraints() {
            if constraint.poly().len() == 1 {
                let constraint = SingleValueConstraint::new(constraint);
                self.aux_single_value.push(constraint);
            } else if constraint.poly().len() < SMALL_POLY_DEGREE {
                let constraint = SmallPolyConstraint::new(constraint);
                self.aux_small_poly.push(constraint);
            } else {
                let constraint = LargePolyConstraint::new(constraint, air, twiddle_map);
                self.aux_large_poly.push(constraint);
            }
        }
    }

    // EVALUATORS
    // --------------------------------------------------------------------------------------------

    /// Evaluates the constraints against the main segment of the execution trace contained in
    /// this group at the specified step of the trace.
    pub fn evaluate_main(
        &self,
        state: &[E::BaseField],
        ce_step: usize,
        x: E::BaseField,
        xp: E::BaseField,
    ) -> E {
        let mut result = E::ZERO;

        // evaluate all single-value constraints
        for constraint in self.main_single_value.iter() {
            result += constraint.evaluate(state, xp);
        }

        // evaluate all small polynomial constraints
        for constraint in self.main_small_poly.iter() {
            result += constraint.evaluate(state, x, xp);
        }

        // evaluate all large polynomial constraints
        for constraint in self.main_large_poly.iter() {
            result += constraint.evaluate(state, ce_step, xp);
        }

        result
    }

    /// Evaluates all constraints contained in this group at the specified step of the
    /// execution trace.
    pub fn evaluate_all(
        &self,
        main_state: &[E::BaseField],
        aux_state: &[E],
        ce_step: usize,
        x: E::BaseField,
        xp: E::BaseField,
    ) -> E {
        let mut result = self.evaluate_main(main_state, ce_step, x, xp);

        // evaluate all single-value constraints
        for constraint in self.aux_single_value.iter() {
            result += constraint.evaluate(aux_state, xp);
        }

        // evaluate all small polynomial constraints
        for constraint in self.aux_small_poly.iter() {
            result += constraint.evaluate(aux_state, x, xp);
        }

        // evaluate all large polynomial constraints
        for constraint in self.aux_large_poly.iter() {
            result += constraint.evaluate(aux_state, ce_step, xp);
        }

        result
    }
}

// CONSTRAINT SPECIALIZATIONS
// ================================================================================================

/// A constraint where the numerator can be represented by p(x) - v, where v is the asserted value,
/// and p(x) is the trace polynomial for the column against which the constraint is applied.
struct SingleValueConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    column: usize,
    value: F,
    coefficients: (E, E),
}

impl<F, E> SingleValueConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    /// Returns an new instance of [SingleValueConstraint] created from the specified source
    /// boundary constraint.
    pub fn new(source: &air::BoundaryConstraint<F, E>) -> Self {
        debug_assert!(source.poly().len() == 1, "not a single constraint");
        Self {
            column: source.column(),
            value: source.poly()[0],
            coefficients: *source.cc(),
        }
    }

    /// Evaluates this constraint over the specified state and returns the result.
    ///
    /// This also applies composition coefficients as well as the degree adjustment factor
    /// (defined by `xp` parameter) to the evaluation before it is returned.
    pub fn evaluate(&self, state: &[F], xp: F::BaseField) -> E {
        let evaluation = state[self.column] - self.value;
        (self.coefficients.0 + self.coefficients.1.mul_base(xp)).mul_base(evaluation)
    }
}

/// A constraint where the numerator can be represented by p(x) - c(x), where b(x) is the
/// polynomial describing a set of asserted values. This specialization is useful when the
/// degree of b(x) is relatively small, and thus, is cheap to evaluate on the fly.
///
/// TODO: investigate whether we get any significant improvement vs. [LargePolyConstraint], and if
/// so, what is the appropriate value for SMALL_POLY_DEGREE.
struct SmallPolyConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    column: usize,
    poly: Vec<F>,
    x_offset: F::BaseField,
    coefficients: (E, E),
}

impl<F, E> SmallPolyConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    /// Returns an new instance of [SmallPolyConstraint] created from the specified source
    /// boundary constraint.
    pub fn new(source: &air::BoundaryConstraint<F, E>) -> Self {
        debug_assert!(
            source.poly().len() > 1 && source.poly().len() < SMALL_POLY_DEGREE,
            "not a small poly constraint"
        );
        Self {
            column: source.column(),
            poly: source.poly().to_vec(),
            x_offset: source.poly_offset().1,
            coefficients: *source.cc(),
        }
    }

    /// Evaluates this constraint over the specified state and returns the result.
    ///
    /// This also applies composition coefficients as well as the degree adjustment factor
    /// (defined by `xp` parameter) to the evaluation before it is returned.
    ///
    /// We need the point in the domain ('x') corresponding to the passed-in state because to
    /// evaluate the constraint we need to evaluate its value polynomial at `x`.
    pub fn evaluate(&self, state: &[F], x: F::BaseField, xp: F::BaseField) -> E {
        let x = x * self.x_offset;
        // evaluate constraint polynomial as x * offset using Horner evaluation
        let assertion_value = self
            .poly
            .iter()
            .rev()
            .fold(F::ZERO, |acc, &coeff| acc.mul_base(x) + coeff);
        // evaluate the constraint
        let evaluation = state[self.column] - assertion_value;
        (self.coefficients.0 + self.coefficients.1.mul_base(xp)).mul_base(evaluation)
    }
}

/// A constraint where the numerator can be represented by p(x) - b(x), where b(x) is a large
/// polynomial. In such cases, we pre-compute evaluations of b(x) by evaluating it over the
/// entire constraint evaluation domain (using FFT).
struct LargePolyConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    column: usize,
    values: Vec<F>,
    step_offset: usize,
    coefficients: (E, E),
}

impl<F, E> LargePolyConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    /// Returns a new instance of [LargePolyConstraint] created from the specified source
    /// boundary constraint.
    pub fn new<A: Air<BaseField = F::BaseField>>(
        source: &air::BoundaryConstraint<F, E>,
        air: &A,
        twiddle_map: &mut BTreeMap<usize, Vec<F::BaseField>>,
    ) -> Self {
        debug_assert!(
            source.poly().len() >= SMALL_POLY_DEGREE,
            "not a large poly constraint"
        );
        // evaluate the polynomial over the entire constraint evaluation domain; first
        // get twiddles for the evaluation; if twiddles haven't been built yet, build them
        let poly_length = source.poly().len();
        let twiddles = twiddle_map
            .entry(poly_length)
            .or_insert_with(|| fft::get_twiddles(poly_length));

        let values = fft::evaluate_poly_with_offset(
            source.poly(),
            twiddles,
            air.domain_offset(),
            air.ce_domain_size() / poly_length,
        );

        LargePolyConstraint {
            column: source.column(),
            values,
            step_offset: source.poly_offset().0 * air.ce_blowup_factor(),
            coefficients: *source.cc(),
        }
    }

    /// Evaluates this constraint at the specified step of the constraint evaluation domain.
    ///
    /// This also applies composition coefficients as well as the degree adjustment factor
    /// (defined by `xp` parameter) to the evaluation before it is returned.
    pub fn evaluate(&self, state: &[F], ce_step: usize, xp: F::BaseField) -> E {
        let value_index = if self.step_offset > 0 {
            // if the assertion happens on steps which are not a power of 2, we need to offset the
            // evaluation; the below basically computes (ce_step - step_offset) % values.len();
            // this is equivalent to evaluating the polynomial at x * x_offset coordinate.
            if self.step_offset > ce_step {
                self.values.len() + ce_step - self.step_offset
            } else {
                ce_step - self.step_offset
            }
        } else {
            ce_step
        };
        let evaluation = state[self.column] - self.values[value_index];
        (self.coefficients.0 + self.coefficients.1.mul_base(xp)).mul_base(evaluation)
    }
}
