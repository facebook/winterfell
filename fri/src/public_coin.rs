// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{Hasher, RandomElementGenerator};
use math::field::FieldElement;

pub trait PublicCoin {
    type Hasher: Hasher;

    /// Draws a pseudo-random value from the field based on the FRI commitment for the
    /// specified layer. This value is used to compute a random linear combination of
    /// evaluations during folding of the next FRI layer.
    fn draw_fri_alpha<E: FieldElement>(&self, layer_idx: usize) -> E {
        let seed = self.fri_layer_commitments()[layer_idx];
        let mut generator = RandomElementGenerator::<Self::Hasher>::new(seed, 0);
        generator.draw()
    }

    fn fri_layer_commitments(&self) -> &[<<Self as PublicCoin>::Hasher as Hasher>::Digest];
}
