// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "alloc")]
pub use alloc::string::{String, ToString};

#[cfg(feature = "std")]
pub use std::string::{String, ToString};
