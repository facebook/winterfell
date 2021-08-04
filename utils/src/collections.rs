// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "alloc")]
pub use alloc::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "alloc")]
pub use alloc::vec::{self as vec, Vec};

#[cfg(feature = "alloc")]
pub use hashbrown::HashMap;

#[cfg(feature = "std")]
pub use std::collections::{BTreeMap, BTreeSet, HashMap};

#[cfg(feature = "std")]
pub use std::vec::{self as vec, Vec};
