// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

/// Maps positions in the evaluation domain to indexes of of the vector commitment.
pub fn map_positions_to_indexes(
    positions: &[usize],
    source_domain_size: usize,
    folding_factor: usize,
    num_partitions: usize,
) -> Vec<usize> {
    // if there was only 1 partition, order of elements in the vector commitment
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
