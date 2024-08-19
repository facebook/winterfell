# Winter sum-check
This crate contains an implementation of the sum-check protocol intended to be used for LogUp-GKR by the Winterfell STARK prover and verifier. 

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also re-exports `rayon` crate and enables multi-threaded execution for some of the crate functions.
* `no_std` - does not rely on Rust's standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

License
-------

This project is [MIT licensed](../LICENSE).