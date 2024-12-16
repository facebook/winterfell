# Winter math
This crate contains modules with mathematical operations needed in STARK proof generation and verification.

## Finite field
[Finite field](src/field) module implements arithmetic operations in STARK-friendly finite fields. The operations include:

* Basic arithmetic operations: addition, multiplication, subtraction, division, inversion.
* Drawing random and pseudo-random elements from the field.
* Computing roots of unity of a given order.

Currently, there are three implementations of finite fields:

* A 128-bit field with modulus 2<sup>128</sup> - 45 * 2<sup>40</sup> + 1. This field was not chosen with any significant thought given to performance, and the implementation of most operations is sub-optimal as well. Proofs generated in this field can support security level of ~100 bits. If higher level of security is desired, proofs must be generated in a quadratic extension of the field.
* A 62-bit field with modulus 2<sup>62</sup> - 111 * 2<sup>39</sup> + 1. This field supports very fast modular arithmetic including branchless multiplication and addition. To achieve adequate security (i.e. ~100 bits), proofs must be generated in a quadratic extension of this field. For higher levels of security, a cubic extension field should be used.
* A 64-bit field with modulus 2<sup>64</sup> - 2<sup>32</sup> + 1. This field supports very fast modular arithmetic (comparable to the 62-bit field described above), provides a fully constant-time implementation, and has a number of other attractive properties. To achieve adequate security (i.e. ~100 bits), proofs must be generated in a quadratic extension of this field. For higher levels of security, a cubic extension field should be used.

### Extension fields
Currently, the library provides a generic way to create quadratic and cubic extensions of supported STARK fields. This can be done by implementing 'ExtensibleField' trait for degrees 2 and 3.
 
Quadratic extension fields are defined using the following irreducible polynomials:
* For `f62` field, the polynomial is x<sup>2</sup> - x - 1.
* For `f64` field, the polynomial is x<sup>2</sup> - x + 2.
* For `f128` field, the polynomial is x<sup>2</sup> - x - 1.

Cubic extension fields are defined using the following irreducible polynomials:
* For `f62` field, the polynomial is x<sup>3</sup> + 2x + 2.
* For `f64` field, the polynomial is x<sup>3</sup> - x - 1.
* For `f128` field, cubic extensions are not supported.

## Polynomials
[Polynomials](src/polynom) module implements basic polynomial operations such as:

* Evaluation of a polynomial at a single point.
* Interpolation of a polynomial from a set of points (using [Lagrange](https://en.wikipedia.org/wiki/Lagrange_polynomial) interpolation).
* Addition, multiplication, subtraction, and division of polynomials.
* Synthetic polynomial division (using [Ruffini's](https://en.wikipedia.org/wiki/Ruffini%27s_rule) method).

## Fast Fourier transform
[FFT](src/fft) module contains operations for computing Fast Fourier transform in a prime field (also called [Number-theoretic transform](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)#Number-theoretic_transform)). This can be used to interpolate and evaluate polynomials in *O(n log n)* time as long as the domain of the polynomial is a multiplicative subgroup with size which is a power of 2.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also enables multi-threaded execution for some of the crate functions.
* `no_std` - does not rely on Rust's standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent execution
When compiled with `concurrent` feature enabled, the following operations will be executed in multiple threads:

* fft module:
  - `evaluate_poly()`
  - `evaluate_poly_with_offset()`
  - `interpolate_poly()`
  - `interpolate_poly_with_offset()`
  - `get_twiddles()`
  - `get_inv_twiddles()`
* utils module:
  - `get_power_series()`
  - `get_power_series_with_offset()`
  - `add_in_place()`
  - `mul_acc()`
  - `batch_inversion()`

The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

License
-------

This project is [MIT licensed](../LICENSE).
