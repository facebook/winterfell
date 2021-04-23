# Crypto
This crate contains modules with cryptographic operations needed in STARK proof generation and verification.

## Hash
[Hash](src/hash) module defines a set of hash functions available for cryptographic operations. Currently, two hash functions are supported: BLAKE3 and SHA3. Support of additional hash functions is planned, including arithmetization-friendly hash functions such as [Rescue](https://eprint.iacr.org/2020/1143).

## Merkle
[Merkle](src/merkle) module contains an implementation of a Merkle tree which supports batch proof generation and verification. Batch proofs are based on the Octopus algorithm described [here](https://eprint.iacr.org/2017/933).

When the crate is compiled with `concurrent` feature enabled, Merkle tree construction will be done using multiple threads (usually, as many threads as there are logical cores on the machine). Number of threads can be configured via `RAYON_NUM_THREADS` environment variable.

License
-------

This project is [MIT licensed](../LICENSE).