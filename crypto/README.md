# Winter crypto
This crate contains modules with cryptographic operations needed in STARK proof generation and verification.

## Hash
[Hash](src/hash) module defines a set of hash functions available for cryptographic operations. Currently, the following hash functions are supported:
 
* SHA3 with 256-bit output.
* BLAKE3 with either 256-bit or 192-bit output. The smaller output version can be used to reduce STARK proof size, however, it also limits proof security level to at most 96 bits.
* Rescue Prime over a 64-bit field with 256-bit output and over a 62-bit field with 248-bit output. Rescue is an arithmetization-friendly hash function and can be used in the STARK protocol when recursive proof composition is desired. However, using this function is not yet supported by the Winterfell STARK prover and verifier.

### Rescue hash function implementation
Rescue hash function is implemented according to the Rescue Prime [specifications](https://eprint.iacr.org/2020/1143.pdf) with the following exception:
* We set the number of rounds to 7, which implies a 40% security margin instead of the 50% margin used in the specifications (a 50% margin rounds up to 8 rounds). The primary motivation for this is that having the number of rounds be one less than a power of two simplifies AIR design for computations involving the hash function.
* For instantiation `RP64_256`, we use the first 4 elements of the state (rather than the last 4 elements of the state) for capacity and the remaining 8 elements for rate. The output of the hash function comes from the first four elements of the rate portion of the state (elements 4, 5, 6, and 7). This effectively applies a fixed bit permutation before and after XLIX permutation. We assert without proof that this does not affect the security of the construction.
* When hashing a sequence of elements, we do not append Fp(1) followed by Fp(0) elements to the end of the sequence as padding. Instead, we initialize one of the capacity elements to the number of elements to be hashed, and pad the sequence with Fp(0) elements only. This ensures that output of the hash function is the same when we hash 8 field elements to compute a 2-to-1 hash using `merge()` function (e.g., for building a Merkle tree) and when we hash 8 field elements as a sequence of elements using `hash_elements()` function. However, this also means that our instantiation of Rescue Prime cannot be used in a stream mode as the number of elements to be hashed must be known upfront.

The parameters used to instantiate the functions are:
* For `RP64_256`:
  - Field: 64-bit prime field with modulus 2<sup>64</sup> - 2<sup>32</sup> + 1.
  - State width: 12 field elements.
  - Capacity size: 4 field elements.
  - Digest size: 4 field elements (can be serialized into 32 bytes).
  - Number of founds: 7.
  - S-Box degree: 7.
  - Target security level: 128-bits.
* For `RP62_248`:
  - Field: 62-bit prime field with modulus 2<sup>62</sup> - 111 * 2<sup>39</sup> + 1.
  - State width: 12 field elements.
  - Capacity size: 4 field elements.
  - Digest size: 4 field elements (can be serialized into 31 bytes).
  - Number of founds: 7.
  - S-Box degree: 3.
  - Target security level: 124-bits.

### Hash function performance
One of the core operations performed during STARK proof generation is construction of Merkle trees. We care greatly about building these trees as quickly as possible, and thus, for the purposes of STARK protocol, 2-to-1 hash operation (e.g., computing a hash of two 32-byte values) is especially important. The table below contains rough benchmarks for computing a 2-to-1 hash for all currently implemented hash functions.

| CPU                         | BLAKE3_256 | SHA3_256 | RP64_256 | RP62_248 |
| --------------------------- | :--------: | :------: | :------: | :------: |
| Apple M1 Pro                | 76 ns      | 227 ns   | 6.9 us   | 7.1 us   |
| AMD Ryzen 9 5950X @ 3.4 GHz | 62 ns      | 310 ns   | 7.4 us   | 6.9 us   |
| Core i9-9980KH @ 2.4 GHz    | 66 ns      | 400 ns   | -        | 6.6 us   |
| Core i5-7300U @ 2.6 GHz     | 81 ns      | 540 ns   | -        | 9.5 us   |
| Core i5-4300U @ 1.9 GHz     | 106 ns     | 675 ns   | -        | 13.9 us  |

As can be seen from the table, BLAKE3 is by far the fastest hash function, while our implementation of Rescue Prime is roughly 100x slower than BLAKE3 and about 20x slower than SHA3.

## Merkle
[Merkle](src/merkle) module contains an implementation of a Merkle tree which supports batch proof generation and verification. Batch proofs are based on the Octopus algorithm described [here](https://eprint.iacr.org/2017/933).

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also enables multi-threaded execution for some of the crate functions.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent execution
When compiled with `concurrent` feature enabled, the following operations will be executed in multiple threads:

* `MerkleTree::new()` - i.e., a Merkle tree will be constructed in multiple threads.

The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

License
-------

This project is [MIT licensed](../LICENSE).