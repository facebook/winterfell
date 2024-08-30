use alloc::vec::Vec;
use core::ops::Add;

use air::{EvaluationFrame, GkrData, LogUpGkrEvaluator};
use math::FieldElement;
use sumcheck::{EqFunction, MultiLinearPoly, SumCheckProverError};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::Trace;

mod prover;
pub use prover::prove_gkr;

// EVALUATED CIRCUIT
// ================================================================================================

/// Evaluation of a layered circuit for computing a sum of fractions.
///
/// The circuit computes a sum of fractions based on the formula a / c + b / d = (a * d + b * c) /
/// (c * d) which defines a "gate" ((a, b), (c, d)) --> (a * d + b * c, c * d) upon which the
/// [`EvaluatedCircuit`] is built. Due to the uniformity of the circuit, each of the circuit
/// layers collect all the:
///
/// 1. `a`'s into a [`MultiLinearPoly`] called `left_numerators`.
/// 2. `b`'s into a [`MultiLinearPoly`] called `right_numerators`.
/// 3. `c`'s into a [`MultiLinearPoly`] called `left_denominators`.
/// 4. `d`'s into a [`MultiLinearPoly`] called `right_denominators`.
///
/// The relation between two subsequent layers is given by the formula
///
/// p_0[layer + 1](x_0, x_1, ..., x_{ν - 2}) = p_0[layer](x_0, x_1, ..., x_{ν - 2}, 0) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 2}, 0)
///                                  + p_1[layer](x_0, x_1, ..., x_{ν - 2}, 0) * q_0[layer](x_0,
///                                    x_1, ..., x_{ν - 2}, 0)
///
/// p_1[layer + 1](x_0, x_1, ..., x_{ν - 2}) = p_0[layer](x_0, x_1, ..., x_{ν - 2}, 1) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 2}, 1)
///                                  + p_1[layer](x_0, x_1, ..., x_{ν - 2}, 1) * q_0[layer](x_0,
///                                    x_1, ..., x_{ν - 2}, 1)
///
/// and
///
/// q_0[layer + 1](x_0, x_1, ..., x_{ν - 2}) = q_0[layer](x_0, x_1, ..., x_{ν - 2}, 0) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 1}, 0)                                  
/// q_1[layer + 1](x_0, x_1, ..., x_{ν - 2}) = q_0[layer](x_0, x_1, ..., x_{ν - 2}, 1) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 1}, 1)
///
/// This logic is encoded in [`CircuitWire`].
///
/// This means that layer ν will be the output layer and will consist of four values
/// (p_0[ν - 1], p_1[ν - 1], p_0[ν - 1], p_1[ν - 1]) ∈ 𝔽^ν.
pub struct EvaluatedCircuit<E: FieldElement> {
    layer_polys: Vec<CircuitLayerPolys<E>>,
}

impl<E: FieldElement> EvaluatedCircuit<E> {
    /// Creates a new [`EvaluatedCircuit`] by evaluating the circuit where the input layer is
    /// defined from the main trace columns.
    pub fn new(
        main_trace_columns: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> Result<Self, GkrProverError> {
        let mut layer_polys = Vec::new();

        let mut current_layer =
            Self::generate_input_layer(main_trace_columns, evaluator, log_up_randomness);
        while current_layer.num_wires() > 1 {
            let next_layer = Self::compute_next_layer(&current_layer);

            layer_polys.push(CircuitLayerPolys::from_circuit_layer(current_layer));

            current_layer = next_layer;
        }

        Ok(Self { layer_polys })
    }

    /// Returns all layers of the evaluated circuit, starting from the input layer.
    ///
    /// Note that the return type is a slice of [`CircuitLayerPolys`] as opposed to
    /// [`CircuitLayer`], since the evaluated layers are stored in a representation which can be
    /// proved using GKR.
    pub fn layers(self) -> Vec<CircuitLayerPolys<E>> {
        self.layer_polys
    }

    /// Returns the numerator/denominator polynomials representing the output layer of the circuit.
    pub fn output_layer(&self) -> &CircuitLayerPolys<E> {
        self.layer_polys.last().expect("circuit has at least one layer")
    }

    /// Evaluates the output layer at `query`, where the numerators of the output layer are treated
    /// as evaluations of a multilinear polynomial, and similarly for the denominators.
    pub fn evaluate_output_layer(&self, query: E) -> (E, E) {
        let CircuitLayerPolys { numerators, denominators } = self.output_layer();

        (numerators.evaluate(&[query]), denominators.evaluate(&[query]))
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    /// Generates the input layer of the circuit from the main trace columns and some randomness
    /// provided by the verifier.
    fn generate_input_layer(
        main_trace: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> CircuitLayer<E> {
        let num_fractions = evaluator.get_num_fractions();
        let periodic_values =
            evaluator.build_periodic_values::<E::BaseField, E>();
        let mut input_layer_wires =
            Vec::with_capacity(main_trace.main_segment().num_rows() * num_fractions);
        let mut main_frame = EvaluationFrame::new(main_trace.main_segment().num_cols());

        let mut query = vec![E::BaseField::ZERO; evaluator.get_oracles().len()];
        let mut numerators = vec![E::ZERO; num_fractions];
        let mut denominators = vec![E::ZERO; num_fractions];
        for i in 0..main_trace.main_segment().num_rows() {
            let wires_from_trace_row = {
                main_trace.read_main_frame(i, &mut main_frame);
                let periodic_values_row = periodic_values.get_periodic_values_at(i);
                evaluator.build_query(&main_frame, &periodic_values_row, &mut query);

                evaluator.evaluate_query(
                    &query,
                    log_up_randomness,
                    &mut numerators,
                    &mut denominators,
                );
                let input_gates_values: Vec<CircuitWire<E>> = numerators
                    .iter()
                    .zip(denominators.iter())
                    .map(|(numerator, denominator)| CircuitWire::new(*numerator, *denominator))
                    .collect();
                input_gates_values
            };

            input_layer_wires.extend(wires_from_trace_row);
        }

        CircuitLayer::new(input_layer_wires)
    }

    /// Computes the subsequent layer of the circuit from a given layer.
    fn compute_next_layer(prev_layer: &CircuitLayer<E>) -> CircuitLayer<E> {
        let next_layer_wires = prev_layer
            .wires()
            .chunks_exact(2)
            .map(|input_wires| {
                let left_input_wire = input_wires[0];
                let right_input_wire = input_wires[1];

                // output wire
                left_input_wire + right_input_wire
            })
            .collect();

        CircuitLayer::new(next_layer_wires)
    }
}

// CIRCUIT LAYER POLYS
// ===============================================================================================

/// Holds a layer of an [`EvaluatedCircuit`] in a representation amenable to proving circuit
/// evaluation using GKR.
#[derive(Clone, Debug)]
pub struct CircuitLayerPolys<E: FieldElement> {
    pub numerators: MultiLinearPoly<E>,
    pub denominators: MultiLinearPoly<E>,
}

impl<E> CircuitLayerPolys<E>
where
    E: FieldElement,
{
    pub fn from_circuit_layer(layer: CircuitLayer<E>) -> Self {
        Self::from_wires(layer.wires)
    }

    pub fn from_wires(wires: Vec<CircuitWire<E>>) -> Self {
        let mut numerators = Vec::new();
        let mut denominators = Vec::new();

        for wire in wires {
            numerators.push(wire.numerator);
            denominators.push(wire.denominator);
        }

        Self {
            numerators: MultiLinearPoly::from_evaluations(numerators),
            denominators: MultiLinearPoly::from_evaluations(denominators),
        }
    }

    fn into_numerators_denominators(self) -> (MultiLinearPoly<E>, MultiLinearPoly<E>) {
        (self.numerators, self.denominators)
    }
}

impl<E> Serializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { numerators, denominators } = self;
        numerators.write_into(target);
        denominators.write_into(target);
    }
}

impl<E> Deserializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            numerators: MultiLinearPoly::read_from(source)?,
            denominators: MultiLinearPoly::read_from(source)?,
        })
    }
}

// CIRCUIT LAYER
// ===============================================================================================

/// Represents a layer in a [`EvaluatedCircuit`].
///
/// A layer is made up of a set of `n` wires, where `n` is a power of two. This is the natural
/// circuit representation of a layer, where each consecutive pair of wires are summed to yield a
/// wire in the subsequent layer of an [`EvaluatedCircuit`].
///
/// Note that a [`Layer`] needs to be first converted to a [`LayerPolys`] before the evaluation of
/// the layer can be proved using GKR.
pub struct CircuitLayer<E: FieldElement> {
    wires: Vec<CircuitWire<E>>,
}

impl<E: FieldElement> CircuitLayer<E> {
    /// Creates a new [`Layer`] from a set of projective coordinates.
    ///
    /// Panics if the number of projective coordinates is not a power of two.
    pub fn new(wires: Vec<CircuitWire<E>>) -> Self {
        assert!(wires.len().is_power_of_two());

        Self { wires }
    }

    /// Returns the wires that make up this circuit layer.
    pub fn wires(&self) -> &[CircuitWire<E>] {
        &self.wires
    }

    /// Returns the number of wires in the layer.
    pub fn num_wires(&self) -> usize {
        self.wires.len()
    }
}

// CIRCUIT WIRE
// ===============================================================================================

/// Represents a fraction `numerator / denominator` as a pair `(numerator, denominator)`. This is
/// the type for the gates' inputs in [`prover::EvaluatedCircuit`].
///
/// Hence, addition is defined in the natural way fractions are added together: `a/b + c/d = (ad +
/// bc) / bd`.
#[derive(Debug, Clone, Copy)]
pub struct CircuitWire<E: FieldElement> {
    numerator: E,
    denominator: E,
}

impl<E> CircuitWire<E>
where
    E: FieldElement,
{
    /// Creates new projective coordinates from a numerator and a denominator.
    pub fn new(numerator: E, denominator: E) -> Self {
        assert_ne!(denominator, E::ZERO);

        Self { numerator, denominator }
    }
}

impl<E> Add for CircuitWire<E>
where
    E: FieldElement,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let numerator = self.numerator * other.denominator + other.numerator * self.denominator;
        let denominator = self.denominator * other.denominator;

        Self::new(numerator, denominator)
    }
}

/// Represents a claim to be proven by a subsequent call to the sum-check protocol.
#[derive(Debug)]
pub struct GkrClaim<E: FieldElement> {
    pub evaluation_point: Vec<E>,
    pub claimed_evaluation: (E, E),
}

/// We receive our 4 multilinear polynomials which were evaluated at a random point:
/// `left_numerators` (or `p0`), `right_numerators` (or `p1`), `left_denominators` (or `q0`), and
/// `right_denominators` (or `q1`). We'll call the 4 evaluations at a random point `p0(r)`, `p1(r)`,
/// `q0(r)`, and `q1(r)`, respectively, where `r` is the random point. Note that `r` is a shorthand
/// for a tuple of random values `(r_0, ... r_{l-1})`, where `2^{l + 1}` is the number of wires in
/// the layer.
///
/// It is important to recall how `p0` and `p1` were constructed (and analogously for `q0` and
/// `q1`). They are the `numerators` layer polynomial (or `p`) evaluations `p(0, r)` and `p(1, r)`,
/// obtained from [`MultiLinearPoly::project_least_significant_variable`]. Hence, `[p0, p1]` form
/// the evaluations of polynomial `p'(x_0) = p(x_0, r)`. Then, the round claim for `numerators`,
/// defined as `p(r_layer, r)`, is simply `p'(r_layer)`.
fn reduce_layer_claim<E>(
    left_numerators_opening: E,
    right_numerators_opening: E,
    left_denominators_opening: E,
    right_denominators_opening: E,
    r_layer: E,
) -> (E, E)
where
    E: FieldElement,
{
    // This is the `numerators` layer polynomial `f(x_0) = numerators(x_0, rx_0, ..., rx_{l-1})`,
    // where `rx_0, ..., rx_{l-1}` are the random variables that were sampled during the sumcheck
    // round for this layer.
    let numerators_univariate =
        MultiLinearPoly::from_evaluations(vec![left_numerators_opening, right_numerators_opening]);

    // This is analogous to `numerators_univariate`, but for the `denominators` layer polynomial
    let denominators_univariate = MultiLinearPoly::from_evaluations(vec![
        left_denominators_opening,
        right_denominators_opening,
    ]);

    (
        numerators_univariate.evaluate(&[r_layer]),
        denominators_univariate.evaluate(&[r_layer]),
    )
}

/// Builds the auxiliary trace column for the univariate sum-check argument.
///
/// Following Section 5.2 in [1] and using the inner product representation of multi-linear queries,
/// we need two univariate oracles, or equivalently two columns in the auxiliary trace, namely:
///
/// 1. The Lagrange oracle, denoted by $c(X)$ in [1], and refered to throughout the codebase by
///    the Lagrange kernel column.
/// 2. The oracle witnessing the univariate sum-check relation defined by the aforementioned inner
///    product i.e., equation (12) in [1]. This oracle is refered to throughout the codebase as
///    the s-column.
///
/// The following function's purpose is two build the column in point 2 given the one in point 1.
///
/// [1]: https://eprint.iacr.org/2023/1284
pub fn build_s_column<E: FieldElement>(
    main_trace: &impl Trace<BaseField = E::BaseField>,
    gkr_data: &GkrData<E>,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    lagrange_kernel_col: &[E],
) -> Vec<E> {
    let c = gkr_data.compute_batched_claim();
    let main_segment = main_trace.main_segment();
    let mean = c / E::from(E::BaseField::from(main_segment.num_rows() as u32));

    let mut result = Vec::with_capacity(main_segment.num_rows());
    let mut last_value = E::ZERO;
    result.push(last_value);

    let mut query = vec![E::BaseField::ZERO; evaluator.get_oracles().len()];
    let mut main_frame = EvaluationFrame::new(main_trace.main_segment().num_cols());

    for (i, item) in lagrange_kernel_col.iter().enumerate().take(main_segment.num_rows() - 1) {
        main_trace.read_main_frame(i, &mut main_frame);

        evaluator.build_query(&main_frame, &[], &mut query);
        let cur_value = last_value - mean + gkr_data.compute_batched_query(&query) * *item;

        result.push(cur_value);
        last_value = cur_value;
    }

    result
}

/// Builds the Lagrange kernel column at a given point.
pub fn build_lagrange_column<E: FieldElement>(lagrange_randomness: &[E]) -> Vec<E> {
    EqFunction::new(lagrange_randomness.into()).evaluations()
}

#[derive(Debug, thiserror::Error)]
pub enum GkrProverError {
    #[error("failed to generate the sum-check proof")]
    FailedToProveSumCheck(#[from] SumCheckProverError),
    #[error("failed to generate the random challenge")]
    FailedToGenerateChallenge,
}
