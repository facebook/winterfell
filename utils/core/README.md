# Winter utils
This crate contains utilities used by the Winterfell STARK prover and verifier. These utilities fall into the following broad categories:

* Traits used for serialization and deserialization.
* Functions for transmuting vectors and slices.
* Macros for easily switching between regular and parallel iterators.
* Feature-based re-exports of collections and strings.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `std` + `concurrent` - same as `std` but also re-exports `rayon` crate and enables multi-threaded execution for some of the crate functions.
* `no_std` + `alloc` - does not rely on Rust's standard library and enables compilation to WebAssembly.

### Concurrent execution

When compiled with `concurrent` feature enabled, this crate re-exports `rayon` crate and executes the following functions using multiple threads:

* `transpose_slice()`

The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

### WebAssembly support
To compile this crate to WebAssembly, disable default features and enable the `alloc` feature.

License
-------

This project is [MIT licensed](../LICENSE).