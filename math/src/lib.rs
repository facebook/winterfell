// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub mod fft;
pub mod polynom;
pub mod utils;

mod field;
pub use field::{FieldElement, StarkField};
pub mod fields {
    //! Finite field implementations.
    //!
    //! This module contains concrete implementations of base STARK field as well as extensions
    //! these field.

    pub use super::field::f128;
    pub use super::field::f62;
    pub use super::field::QuadExtensionA;
}

mod errors;
pub use errors::{ElementDecodingError, SerializationError};
