use alloc::vec::Vec;
use core::ops::Add;

use air::{EvaluationFrame, GkrData, LogUpGkrEvaluator};
use math::FieldElement;
use sumcheck::{EqFunction, MultiLinearPoly, SumCheckProverError};
use tracing::instrument;
use utils::{
    batch_iter_mut, chunks, uninit_vector, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable,
};

use crate::Trace;

mod prover;
pub use prover::prove_gkr;
#[cfg(feature = "concurrent")]
pub use utils::{
    rayon::{current_num_threads as rayon_num_threads, prelude::*},
    {chunks_mut, iter, iter_mut},
};

#[cfg(feature = "concurrent")]
use sumcheck::LOG_MIN_MLE_SIZE;
#[cfg(feature = "concurrent")]
const MINIMAL_MLE_SIZE: usize = 1 << (LOG_MIN_MLE_SIZE + 2);

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
    #[instrument(skip_all, name = "evaluate_logup_gkr_circuit")]
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
        trace: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> CircuitLayer<E> {
        let num_fractions = evaluator.get_num_fractions();
        let periodic_values = evaluator.build_periodic_values();

        let mut input_layer_wires =
            unsafe { uninit_vector(trace.main_segment().num_rows() * num_fractions) };
        let num_cols = trace.main_segment().num_cols();
        let num_oracles = evaluator.get_oracles().len();
        let num_periodic_cols = periodic_values.num_columns();

        batch_iter_mut!(
            &mut input_layer_wires,
            1024,
            |batch: &mut [CircuitWire<E>], batch_offset: usize| {
                let mut main_frame = EvaluationFrame::new(num_cols);
                let mut query = vec![E::BaseField::ZERO; num_oracles];
                let mut periodic_values_row = vec![E::BaseField::ZERO; num_periodic_cols];
                let mut numerators = vec![E::ZERO; num_fractions];
                let mut denominators = vec![E::ZERO; num_fractions];

                let row_offset = batch_offset / num_fractions;
                let batch_size = batch.len();
                let num_rows_per_batch = batch_size / num_fractions;

                for i in
                    (0..trace.main_segment().num_rows()).skip(row_offset).take(num_rows_per_batch)
                {
                    trace.read_main_frame(i, &mut main_frame);
                    periodic_values.fill_periodic_values_at(i, &mut periodic_values_row);
                    evaluator.build_query(&main_frame, &mut query);

                    evaluator.evaluate_query(
                        &query,
                        &periodic_values_row,
                        log_up_randomness,
                        &mut numerators,
                        &mut denominators,
                    );

                    let n = (i - row_offset) * num_fractions;
                    for ((wire, numerator), denominator) in batch[n..n + num_fractions]
                        .iter_mut()
                        .zip(numerators.iter())
                        .zip(denominators.iter())
                    {
                        *wire = CircuitWire::new(*numerator, *denominator);
                    }
                }
            }
        );

        CircuitLayer::new(input_layer_wires)
    }

    /// Computes the subsequent layer of the circuit from a given layer.
    fn compute_next_layer(prev_layer: &CircuitLayer<E>) -> CircuitLayer<E> {
        let next_layer_wires = chunks!(prev_layer.wires(), 2)
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
    trace: &impl Trace<BaseField = E::BaseField>,
    gkr_data: &GkrData<E>,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    lagrange_kernel_col: &[E],
) -> Vec<E> {
    let c = gkr_data.compute_batched_claim();
    let num_oracles = evaluator.get_oracles().len();

    let main_segment = trace.main_segment();
    let num_cols = main_segment.num_cols();
    let num_rows = main_segment.num_rows();
    let mean = c / E::from(E::BaseField::from(num_rows as u32));

    #[cfg(not(feature = "concurrent"))]
    let result = {
        let mut result = Vec::with_capacity(num_rows);
        let mut last_value = E::ZERO;
        result.push(last_value);

        let mut query = vec![E::BaseField::ZERO; num_oracles];
        let mut main_frame = EvaluationFrame::new(num_cols);

        for (i, item) in lagrange_kernel_col.iter().enumerate().take(num_rows - 1) {
            trace.read_main_frame(i, &mut main_frame);

            evaluator.build_query(&main_frame, &mut query);
            let cur_value = last_value - mean + gkr_data.compute_batched_query(&query) * *item;

            result.push(cur_value);
            last_value = cur_value;
        }

        result
    };

    #[cfg(feature = "concurrent")]
    let result = {
        let mut deltas = unsafe { uninit_vector(num_rows) };
        deltas[0] = E::ZERO;
        let batch_size = num_rows / rayon_num_threads().next_power_of_two();
        batch_iter_mut!(&mut deltas[1..], batch_size, |batch: &mut [E], batch_offset: usize| {
            let mut query = vec![E::BaseField::ZERO; num_oracles];
            let mut main_frame = EvaluationFrame::<E::BaseField>::new(num_cols);

            for (i, v) in batch.iter_mut().enumerate() {
                trace.read_main_frame(i + batch_offset, &mut main_frame);

                evaluator.build_query(&main_frame, &mut query);
                *v = gkr_data.compute_batched_query(&query) * lagrange_kernel_col[i + batch_offset]
                    - mean;
            }
        });

        // note that `deltas[0]` is set `0` and thus `deltas` satisfies the conditions for invoking
        // the function
        let mut cumulative_sum = deltas;
        prefix_sum_parallel(&mut cumulative_sum, batch_size);
        cumulative_sum
    };

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

// HELPER
// =================================================================================================

/// Computes the cumulative sum, also called prefix sum, of a vector of field elements using
/// parallelism, in place.
///
/// The function divides the vector into non-overlapping segments and then computes an array of sums
/// for each segment. The function then applies the naive serial implementation to each segment and
/// uses the pre-computed sums in each segment in order to coordinate the results in the different
/// segments.
///
/// The input vector is of the form `0 || values` where `values` are the values the cumulative sum
/// vector will be computed for, in place.
#[cfg(feature = "concurrent")]
fn prefix_sum_parallel<E: FieldElement>(vector: &mut [E], batch_size: usize) {
    let num_partitions = vector.len().div_ceil(batch_size);
    let mut sum_per_partition = vec![E::ZERO; num_partitions];

    chunks!(vector, batch_size)
        .zip(iter_mut!(sum_per_partition))
        .for_each(|(chunk, entry)| *entry = chunk.iter().fold(E::ZERO, |acc, term| acc + *term));

    prefix_sum_truncate_right(&mut sum_per_partition);

    chunks_mut!(vector, batch_size)
        .zip(iter!(sum_per_partition))
        .for_each(|(chunk, sum_so_far)| prefix_sum_truncate_left(chunk, *sum_so_far));
}

/// Computes the cumulative sum of a vector but omits the final cumulative sum.
#[cfg(feature = "concurrent")]
fn prefix_sum_truncate_right<E: FieldElement>(values: &mut [E]) {
    let mut sum = E::ZERO;
    values.iter_mut().for_each(|v| {
        let tmp = *v;
        *v = sum;
        sum += tmp;
    });
}

/// Computes the cumulative sum of a vector but omits the initial cumulative sum, namely zero.
#[cfg(feature = "concurrent")]
fn prefix_sum_truncate_left<E: FieldElement>(values: &mut [E], sum: E) {
    let mut sum = sum;
    values.iter_mut().for_each(|v| {
        sum += *v;
        *v = sum;
    });
}
