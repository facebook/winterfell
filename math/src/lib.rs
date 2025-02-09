// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains modules with mathematical operations needed in STARK proof generation
//! and verification.
//!
//! Unless otherwise stated, all operations happen in [finite fields](https://en.wikipedia.org/wiki/Finite_field).
//!
//! # Finite fields
//! [Finite field](fields) modules implements arithmetic operations in STARK-friendly finite
//! fields. The operation include:
//!
//! * Basic arithmetic operations: addition, multiplication, subtraction, division, inversion.
//! * Drawing random and pseudo-random elements from the field.
//! * Computing roots of unity of a given order.
//!
//! Currently, there are two implementations of finite fields:
//!
//! * A 128-bit field with modulus 2<sup>128</sup> - 45 * 2<sup>40</sup> + 1. This field was not
//!   chosen with any significant thought given to performance, and the implementation of most
//!   operations is sub-optimal as well. Proofs generated in this field can support security level
//!   of ~100 bits. If higher level of security is desired, proofs must be generated in a quadratic
//!   extension of the field.
//! * A 62-bit field with modulus 2<sup>62</sup> - 111 * 2<sup>39</sup> + 1. This field supports
//!   very fast modular arithmetic including branchless multiplication and addition. To achieve
//!   adequate security (i.e. ~100 bits), proofs must be generated in a quadratic extension of this
//!   field. For higher levels of security, a cubic extension field should be used.
//! * A 64-bit field with modulus 2<sup>64</sup> - 2<sup>32</sup> + 1. This field is about 15%
//!   slower than the 62-bit field described above, but it has a number of other attractive
//!   properties. To achieve adequate security (i.e. ~100 bits), proofs must be generated in a
//!   quadratic extension of this field. For higher levels of security, a cubic extension field
//!   should be used.
//!
//! ## Extension fields
//!
//! Currently, the library provides a generic way to create quadratic and cubic extensions of
//! supported STARK fields. This can be done by implementing [ExtensibleField] trait for
//! degrees 2 and 3.
//!
//! Quadratic extension fields are defined using the following irreducible polynomials:
//! * For [f62](crate::fields::f62) field, the polynomial is x<sup>2</sup> - x - 1.
//! * For [f64](crate::fields::f64) field, the polynomial is x<sup>2</sup> - x + 2.
//! * For [f128](crate::fields::f128) field, the polynomial is x<sup>2</sup> - x - 1.
//!
//! Cubic extension fields are defined using the following irreducible polynomials:
//! * For [f62](crate::fields::f62) field, the polynomial is x<sup>3</sup> + 2x + 2.
//! * For [f64](crate::fields::f64) field, the polynomial is x<sup>3</sup> - x - 1.
//! * For [f128](crate::fields::f128) field, cubic extensions are not supported.
//!
//! # Polynomials
//! [Polynomials](polynom) module implements basic polynomial operations such as:
//!
//! * Evaluation of a polynomial at a single or multiple point.
//! * Interpolation of a polynomial from a set of points (using [Lagrange](https://en.wikipedia.org/wiki/Lagrange_polynomial)
//!   interpolation).
//! * Addition, multiplication, subtraction, and division of polynomials.
//! * Synthetic polynomial division (using [Ruffini's](https://en.wikipedia.org/wiki/Ruffini%27s_rule)
//!   method).
//!
//! # Fast Fourier transform
//! [FFT](fft) module contains operations for computing Fast Fourier transform in a prime
//! field (also called [Number-theoretic transform](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)#Number-theoretic_transform)).
//! This can be used to interpolate and evaluate polynomials in *O(n log n)* time as long as
//! the domain of the polynomial is a multiplicative subgroup with size which is a power of 2.
//!
//! # Concurrent execution
//!
//! When the crate is compiled with `concurrent` feature enabled, some operations will be
//! executed in multiple threads (usually, as many threads as there are logical cores on
//! the machine). These operations are:
//!
//! * crate:
//!   - [get_power_series()]
//!   - [get_power_series_with_offset()]
//!   - [add_in_place()]
//!   - [mul_acc()]
//!   - [batch_inversion()]
//! * `fft` module:
//!   - [evaluate_poly()](fft::evaluate_poly())
//!   - [evaluate_poly_with_offset()](fft::evaluate_poly_with_offset())
//!   - [interpolate_poly()](fft::interpolate_poly())
//!   - [interpolate_poly_with_offset()][fft::interpolate_poly_with_offset()]
//!   - [get_twiddles()](fft::get_twiddles())
//!   - [get_inv_twiddles()](fft::get_twiddles())
//!
//! Number of threads can be configured via `RAYON_NUM_THREADS` environment variable

#![no_std]

#[macro_use]
extern crate alloc;

pub mod fft;
pub mod polynom;

mod field;
pub use field::{ExtensibleField, ExtensionOf, FieldElement, StarkField, ToElements};
pub mod fields {
    //! Finite field implementations.
    //!
    //! This module contains concrete implementations of base STARK fields as well as extensions
    //! of these field.

    pub use super::field::{f128, f62, f64, CubeExtension, QuadExtension};
}

mod utils;
pub use crate::utils::{
    add_in_place, batch_inversion, get_power_series, get_power_series_with_offset, mul_acc,
};
