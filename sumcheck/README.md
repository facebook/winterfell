# Winter sum-check
This crate contains an implementation of the sum-check protocol intended to be used for [LogUp-GKR](https://eprint.iacr.org/2023/1284) by the Winterfell STARK prover and verifier.

The crate provides two implementations of the sum-check protocol:

* An implementation for the sum-check protocol as used in [LogUp-GKR](https://eprint.iacr.org/2023/1284).
* An implementation which generalizes the previous one to the case where the numerators and denominators appearing in the fractional sum-checks in Section 3 of [LogUp-GKR](https://eprint.iacr.org/2023/1284) can be non-linear compositions of multi-linear polynomials.

The first implementation is intended to be used by the GKR protocol for proving the correct evaluation of all of the layers of the fractionl sum circuit except for the input layer. The second implementation is intended to be used for proving the correct evaluation of the input layer.


## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also re-exports `rayon` crate and enables multi-threaded execution for some of the crate functions.
* `no_std` - does not rely on Rust's standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

License
-------

This project is [MIT licensed](../LICENSE).