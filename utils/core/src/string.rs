// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Feature-based re-export of common string components.
//!
//! When `std` feature is enabled, this module exports string components from the Rust standard
//! library. When `alloc` feature is enabled, same components are provided without relying on the
//! Rust standard library.

#[cfg(not(feature = "std"))]
pub use alloc::string::{String, ToString};

#[cfg(feature = "std")]
pub use std::string::{String, ToString};
