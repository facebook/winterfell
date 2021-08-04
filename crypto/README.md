# Winter crypto
This crate contains modules with cryptographic operations needed in STARK proof generation and verification.

## Hash
[Hash](src/hash) module defines a set of hash functions available for cryptographic operations. Currently, two hash functions are supported: BLAKE3 and SHA3. Support of additional hash functions is planned, including arithmetization-friendly hash functions such as [Rescue](https://eprint.iacr.org/2020/1143).

## Merkle
[Merkle](src/merkle) module contains an implementation of a Merkle tree which supports batch proof generation and verification. Batch proofs are based on the Octopus algorithm described [here](https://eprint.iacr.org/2017/933).

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `std` + `concurrent` - same as `std` but enables multi-threaded execution for some of the crate functions.
* `no_std` + `alloc` - does not rely on the Rust standard library and enables compilation to WebAssembly.

### Concurrent execution
When compiled with `concurrent` feature enabled, the following operations will be executed in multiple threads:

* `MerkleTree::new()` - i.e., a Merkle tree will be constructed in multiple threads.

The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

### WebAssembly support
To compile this crate to WebAssembly, disable default features and enable the `alloc` feature.

License
-------

This project is [MIT licensed](../LICENSE).