# Winter utils
This crate contains utilities used by the Winterfell STARK prover and verifier. These utilities fall into the following broad categories:

* Traits used for serialization and deserialization.
* Functions for transmuting vectors and slices.
* Macros for easily switching between regular and parallel iterators.
* Feature-based re-exports of collections and strings.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also re-exports `rayon` crate and enables multi-threaded execution for some of the crate functions.
* `no_std` - does not rely on Rust's standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent execution

When compiled with `concurrent` feature enabled, this crate re-exports `rayon` crate and executes the following functions using multiple threads:

* `transpose_slice()`

The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

License
-------

This project is [MIT licensed](../LICENSE).