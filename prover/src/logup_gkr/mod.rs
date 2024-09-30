use alloc::vec::Vec;

use air::{EvaluationFrame, GkrData, LogUpGkrEvaluator};
use math::FieldElement;
use sumcheck::{CircuitLayerPolys, CircuitWire, EqFunction, SumCheckProverError};
use tracing::instrument;
use utils::{batch_iter_mut, uninit_vector};

use crate::Trace;

mod prover;
pub use prover::prove_gkr;
#[cfg(feature = "concurrent")]
pub use utils::{
    rayon::{current_num_threads as rayon_num_threads, prelude::*},
    {chunks, chunks_mut, iter, iter_mut},
};

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
    layer_polys: Vec<Vec<CircuitLayerPolys<E>>>,
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

        let input_layer =
            Self::generate_input_layer(main_trace_columns, evaluator, log_up_randomness);

        let mut current_layer =
            Self::generate_second_layer(input_layer, evaluator.get_num_fractions());
        while current_layer[0].len() > 1 {
            let next_layer = Self::compute_next_layer(&current_layer);

            layer_polys.push(CircuitLayerPolys::from_circuit_layer(&current_layer));

            current_layer = next_layer;
        }

        Ok(Self { layer_polys })
    }

    /// Returns all layers of the evaluated circuit, starting from the input layer.
    ///
    /// Note that the return type is a slice of [`CircuitLayerPolys`] as opposed to
    /// [`CircuitLayer`], since the evaluated layers are stored in a representation which can be
    /// proved using GKR.
    pub fn layers(self) -> Vec<Vec<CircuitLayerPolys<E>>> {
        self.layer_polys
    }

    /// Returns the numerator/denominator polynomials representing the output layer of the circuit.
    pub fn output_layers(&self) -> &Vec<CircuitLayerPolys<E>> {
        self.layer_polys.last().expect("circuit has at least one layer")
    }

    /// Evaluates the output layer at `query`, where the numerators of the output layer are treated
    /// as evaluations of a multilinear polynomial, and similarly for the denominators.
    pub fn evaluate_output_layer(&self, query: E) -> Vec<(E, E)> {
        let mut res = Vec::with_capacity(self.output_layers().len());
        for output_layer in self.output_layers().iter() {
            let CircuitLayerPolys { numerators, denominators } = output_layer;

            res.push((numerators.evaluate(&[query]), denominators.evaluate(&[query])))
        }
        res
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    /// Generates the input layer of the circuit from the main trace columns and some randomness
    /// provided by the verifier.
    fn generate_input_layer(
        trace: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> Vec<CircuitWire<E>> {
        let num_fractions = evaluator.get_num_fractions();
        let periodic_values = evaluator.build_periodic_values(trace.main_segment().num_rows());

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
        input_layer_wires
    }

    /// Computes the subsequent layer of the circuit from a given layer.
    fn compute_next_layer(prev_layers: &[Vec<CircuitWire<E>>]) -> Vec<Vec<CircuitWire<E>>> {
        let mut next_layers: Vec<Vec<CircuitWire<E>>> =
            vec![unsafe { uninit_vector(prev_layers[0].len() / 2) }; prev_layers.len()];

        #[cfg(feature = "concurrent")]
        if prev_layers[0].len() >= 16 {
            next_layers.par_iter_mut().enumerate().for_each(|(circuit_idx, circuit)| {
                prev_layers[circuit_idx].chunks(2).enumerate().for_each(
                    |(row, fractions_at_row)| {
                        let left = fractions_at_row[0];
                        let right = fractions_at_row[1];
                        circuit[row] = left + right;
                    },
                );
            });
        } else {
            next_layers.iter_mut().enumerate().for_each(|(circuit_idx, circuit)| {
                prev_layers[circuit_idx].chunks(2).enumerate().for_each(
                    |(row, fractions_at_row)| {
                        let left = fractions_at_row[0];
                        let right = fractions_at_row[1];
                        circuit[row] = left + right;
                    },
                );
            });
        }

        #[cfg(not(feature = "concurrent"))]
        next_layers.iter_mut().enumerate().for_each(|(circuit_idx, circuit)| {
            prev_layers[circuit_idx]
                .chunks(2)
                .enumerate()
                .for_each(|(row, fractions_at_row)| {
                    let left = fractions_at_row[0];
                    let right = fractions_at_row[1];
                    circuit[row] = left + right;
                });
        });

        next_layers
    }

    fn generate_second_layer(
        current_layer: Vec<CircuitWire<E>>,
        num_fractions: usize,
    ) -> Vec<Vec<CircuitWire<E>>> {
        let mut result: Vec<Vec<CircuitWire<E>>> =
            vec![
                unsafe { uninit_vector(current_layer.len() / (num_fractions * 2)) };
                num_fractions
            ];

        #[cfg(feature = "concurrent")]
        result.par_iter_mut().enumerate().for_each(|(circuit_idx, circuit)| {
            current_layer.chunks(2 * num_fractions).enumerate().for_each(
                |(row, fractions_at_row)| {
                    let left = fractions_at_row[circuit_idx];
                    let right = fractions_at_row[circuit_idx + num_fractions];
                    circuit[row] = left + right;
                },
            );
        });

        #[cfg(not(feature = "concurrent"))]
        result.iter_mut().enumerate().for_each(|(circuit_idx, circuit)| {
            current_layer.chunks(2 * num_fractions).enumerate().for_each(
                |(row, fractions_at_row)| {
                    let left = fractions_at_row[circuit_idx];
                    let right = fractions_at_row[circuit_idx + num_fractions];
                    circuit[row] = left + right;
                },
            );
        });

        result
    }
}

/// Represents a claim to be proven by a subsequent call to the sum-check protocol.
#[derive(Debug)]
pub struct GkrClaim<E: FieldElement> {
    pub evaluation_point: Vec<E>,
    pub claimed_evaluations_per_circuit: Vec<(E, E)>,
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
/// The following function's purpose is to build the column in point 2 given the one in point 1.
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
    let num_partitions = (vector.len() + batch_size - 1) / batch_size;
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
