// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{hash, DefaultRandomElementGenerator, RandomElementGenerator};
use math::field::f128::BaseElement;

#[test]
fn random_generator_draw() {
    let mut generator = DefaultRandomElementGenerator::<hash::Blake3_256>::new([0; 32], 0);

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        result,
        BaseElement::new(257367016314067561345826246336977956381)
    );

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        result,
        BaseElement::new(71356866342624880993791800984977673254)
    );

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        result,
        BaseElement::new(209866678167327876517963759170433911820)
    );
}
