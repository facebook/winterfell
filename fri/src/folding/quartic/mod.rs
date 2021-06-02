// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::Hasher;
use math::{
    field::{FieldElement, StarkField},
    utils::batch_inversion,
};
use utils::{batch_iter_mut, group_vector_elements, iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================
pub const FOLDING_FACTOR: usize = 4;

// PUBLIC FUNCTIONS
// ================================================================================================

/// Evaluates degree 3 polynomial `p` at coordinate `x`. This function is about 30% faster than
/// the `polynom::eval` function.
pub fn eval<E: FieldElement>(p: &[E], x: E) -> E {
    debug_assert!(p.len() == 4, "Polynomial must have 4 terms");
    // Horner's evaluation
    let mut y = p[3] * x;
    y = (y + p[2]) * x;
    y = (y + p[1]) * x;
    y += p[0];
    y
}

/// Evaluates a batch of degree 3 polynomials at the provided X coordinate.
pub fn evaluate_batch<E: FieldElement>(polys: &[[E; FOLDING_FACTOR]], x: E) -> Vec<E> {
    let mut result: Vec<E> = uninit_vector(polys.len());
    iter_mut!(result, 1024)
        .zip(polys)
        .for_each(|(result, poly)| {
            *result = eval(poly, x);
        });
    result
}

/// Interpolates a set of X, Y coordinates into a batch of degree 3 polynomials. X coordinates
/// must be specified over the base field.
///
/// This function is many times faster than using `polynom::interpolate` function in a loop.
/// This is primarily due to amortizing inversions over the entire batch.
pub fn interpolate_batch<B, E>(xs: &[[B; 4]], ys: &[[E; 4]]) -> Vec<[E; 4]>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    debug_assert!(
        xs.len() == ys.len(),
        "number of X coordinates must be equal to number of Y coordinates"
    );
    let mut result: Vec<[E; FOLDING_FACTOR]> = uninit_vector(xs.len());
    batch_iter_mut!(
        &mut result,
        128, // min batch size
        |batch: &mut [[E; FOLDING_FACTOR]], batch_offset: usize| {
            let start = batch_offset;
            let end = start + batch.len();
            interpolate_batch_into(&xs[start..end], &ys[start..end], batch);
        }
    );

    result
}

/// Transposes the source vector into a matrix of quartic elements.
pub fn transpose<E: FieldElement>(source: &[E], stride: usize) -> Vec<[E; 4]> {
    assert!(
        source.len() % (FOLDING_FACTOR * stride) == 0,
        "vector length must be divisible by {}",
        FOLDING_FACTOR * stride
    );
    let row_count = source.len() / (FOLDING_FACTOR * stride);

    let mut result = to_quartic_vec(uninit_vector(row_count * FOLDING_FACTOR));
    iter_mut!(result, 1024)
        .enumerate()
        .for_each(|(i, element)| {
            *element = [
                source[i * stride],
                source[(i + row_count) * stride],
                source[(i + 2 * row_count) * stride],
                source[(i + 3 * row_count) * stride],
            ];
        });
    result
}

/// Re-interprets a vector of field elements as a vector of quartic elements.
pub fn to_quartic_vec<E: FieldElement>(vector: Vec<E>) -> Vec<[E; 4]> {
    group_vector_elements::<E, 4>(vector)
}

/// Computes hashes for all quartic elements using the specified hash function.
pub fn hash_values<H: Hasher, E: FieldElement>(values: &[[E; 4]]) -> Vec<H::Digest> {
    let mut result: Vec<H::Digest> = uninit_vector(values.len());
    iter_mut!(result, 1024).zip(values).for_each(|(r, v)| {
        *r = H::hash_elements(v);
    });
    result
}

// HELPER FUNCTION
// ================================================================================================

fn interpolate_batch_into<B, E>(xs: &[[B; 4]], ys: &[[E; 4]], result: &mut [[E; 4]])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let n = xs.len();
    let mut equations: Vec<[E; 4]> = Vec::with_capacity(n * 4);
    let mut inverses: Vec<E> = Vec::with_capacity(n * 4);
    unsafe {
        equations.set_len(n * 4);
        inverses.set_len(n * 4);
    }

    for (i, j) in (0..n).zip((0..equations.len()).step_by(4)) {
        let xs = xs[i];

        let x0 = E::from(xs[0]);
        let x1 = E::from(xs[1]);
        let x2 = E::from(xs[2]);
        let x3 = E::from(xs[3]);

        let x01 = x0 * x1;
        let x02 = x0 * x2;
        let x03 = x0 * x3;
        let x12 = x1 * x2;
        let x13 = x1 * x3;
        let x23 = x2 * x3;

        // eq0
        equations[j] = [-x12 * x3, x12 + x13 + x23, -x1 - x2 - x3, E::ONE];
        inverses[j] = eval(&equations[j], x0);

        // eq1
        equations[j + 1] = [-x02 * x3, x02 + x03 + x23, -x0 - x2 - x3, E::ONE];
        inverses[j + 1] = eval(&equations[j + 1], x1);

        // eq2
        equations[j + 2] = [-x01 * x3, x01 + x03 + x13, -x0 - x1 - x3, E::ONE];
        inverses[j + 2] = eval(&equations[j + 2], x2);

        // eq3
        equations[j + 3] = [-x01 * x2, x01 + x02 + x12, -x0 - x1 - x2, E::ONE];
        inverses[j + 3] = eval(&equations[j + 3], x3);
    }

    let inverses = batch_inversion(&inverses);

    for (i, j) in (0..n).zip((0..equations.len()).step_by(4)) {
        let ys = ys[i];

        // iteration 0
        let mut inv_y = ys[0] * inverses[j];
        result[i][0] = inv_y * equations[j][0];
        result[i][1] = inv_y * equations[j][1];
        result[i][2] = inv_y * equations[j][2];
        result[i][3] = inv_y * equations[j][3];

        // iteration 1
        inv_y = ys[1] * inverses[j + 1];
        result[i][0] += inv_y * equations[j + 1][0];
        result[i][1] += inv_y * equations[j + 1][1];
        result[i][2] += inv_y * equations[j + 1][2];
        result[i][3] += inv_y * equations[j + 1][3];

        // iteration 2
        inv_y = ys[2] * inverses[j + 2];
        result[i][0] += inv_y * equations[j + 2][0];
        result[i][1] += inv_y * equations[j + 2][1];
        result[i][2] += inv_y * equations[j + 2][2];
        result[i][3] += inv_y * equations[j + 2][3];

        // iteration 3
        inv_y = ys[3] * inverses[j + 3];
        result[i][0] += inv_y * equations[j + 3][0];
        result[i][1] += inv_y * equations[j + 3][1];
        result[i][2] += inv_y * equations[j + 3][2];
        result[i][3] += inv_y * equations[j + 3][3];
    }
}
