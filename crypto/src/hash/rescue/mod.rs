// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Digest, ElementHasher, Hasher, StarkField};

mod rp62_248;
pub use rp62_248::Rp62_248;

mod rp64_256;
pub use rp64_256::Rp64_256;

mod rp64_256_jive;
pub use rp64_256_jive::RpJive64_256;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn exp_acc<B: StarkField, const N: usize, const M: usize>(base: [B; N], tail: [B; N]) -> [B; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }
    result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
    result
}
