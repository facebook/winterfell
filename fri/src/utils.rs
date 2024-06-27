// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use crypto::{ElementHasher, Hasher, VectorCommitment};
use math::FieldElement;
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{iter_mut, uninit_vector};

/// Maps positions in the evaluation domain to indexes of of the vector commitment.
pub fn map_positions_to_indexes(
    positions: &[usize],
    source_domain_size: usize,
    folding_factor: usize,
    num_partitions: usize,
) -> Vec<usize> {
    // if there was only 1 partition, order of elements in the commitment tree
    // is the same as the order of elements in the evaluation domain
    if num_partitions == 1 {
        return positions.to_vec();
    }

    let target_domain_size = source_domain_size / folding_factor;
    let partition_size = target_domain_size / num_partitions;

    let mut result = Vec::new();
    for position in positions {
        let partition_idx = position % num_partitions;
        let local_idx = (position - partition_idx) / num_partitions;
        let position = partition_idx * partition_size + local_idx;
        result.push(position);
    }

    result
}

/// Hashes each of the arrays in the provided slice and returns a vector of resulting hashes.
pub fn hash_values<H, E, V: VectorCommitment<H>, const N: usize>(
    values: &[[E; N]],
) -> Vec<<V as VectorCommitment<H>>::Item>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    <V as VectorCommitment<H>>::Item: From<<H as Hasher>::Digest>,
{
    let mut result: Vec<V::Item> = unsafe { uninit_vector(values.len()) };
    iter_mut!(result, 1024).zip(values).for_each(|(r, v)| {
        let digest: V::Item = H::hash_elements(v).into();
        *r = digest
    });
    result
}
