// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{hash, RandomElementGenerator};
use math::field::f128::BaseElement;

#[test]
fn random_generator_draw() {
    let mut generator = RandomElementGenerator::<hash::Blake3_256>::new([0; 32], 0);

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        BaseElement::new(23082770466498516169280811354265446740),
        result
    );

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        BaseElement::new(283161480371354245851401812181584896944),
        result
    );

    let result = generator.draw::<BaseElement>();
    assert_eq!(
        BaseElement::new(141982828080004524273101818251591279665),
        result
    );
}
