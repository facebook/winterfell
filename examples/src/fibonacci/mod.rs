// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::math::fields::f128::BaseElement;

pub mod fib2;
pub mod fib8;
pub mod fib_small;
pub mod mulfib2;
pub mod mulfib8;

mod utils;

pub(crate) type Blake3_192 = winterfell::crypto::hashers::Blake3_192<BaseElement>;
pub(crate) type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;
pub(crate) type Sha3_256 = winterfell::crypto::hashers::Sha3_256<BaseElement>;
