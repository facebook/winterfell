// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod high_degree;
pub use high_degree::sum_check_prove_higher_degree;

mod plain;
pub use plain::sumcheck_prove_plain;

mod error;
pub use error::SumCheckProverError;

#[cfg(feature = "concurrent")]
const MINIMAL_MLE_SIZE: usize = 1 << 6;