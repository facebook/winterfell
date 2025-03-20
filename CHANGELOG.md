# Changelog

## 0.12.2 (2025-03-19) - `fri`, `prover`, and `verifier` crates only

- Commit to coefficients of FRI remainder polynomial in reverse order (#373).

## 0.12.1 (2025-02-12) - `air` crate only
- Fixed `Context` struct serialization.

## 0.12.0 (2025-02-08)
- [BREAKING] Added security estimate in unique decoding regime  (#356).
- [BREAKING] Added option for algebraic batching to build DEEP polynomial (#357).
- [BREAKING] Updated serialization logic of the OOD frame (#358).
- [BREAKING] Removed GKR-related code (#359).
- Update security estimator to take batching method into account (#361).
- [BREAKING] Added option for algebraic batching to build constraint composition polynomial (#363).
- Updated minimum supported Rust version to 1.84.

## 0.11.0 (2024-11-24)
- [BREAKING] Made the prover generic over the `ConstraintCommitment` type (#343).

## 0.10.3 (2024-11-19) - `air`, `prover`, and `verifier` crates only
- Fixed partition size calculations in `PartitionOptions` (#340).

## 0.10.2 (2024-11-18)
- Implemented `core::error::Error` for error types (#341).

## 0.10.1 (2024-10-30)
- Fixed partition hashing and add logging to aux trace building (#338).

## 0.10.0 (2024-10-25)
- [BREAKING] Refactored maybe-async macro into simpler maybe-async and maybe-await macros (#283).
- [BREAKING] Introduced `VectorCommitment` abstraction (#285).
- Added `maybe-async-trait` procedural macro (#334).
- [BREAKING] Added options for partitioned trace commitments (#336).
- Updated minimum supported Rust version to 1.82.

## 0.9.3 (2024-09-25) - `utils/core` and `math` crates only
- Implemented `get_size_hint()` for default impls (#332).

## 0.9.2 (2024-09-06) - `utils/core` crate only
- Fixed `read_slice` impl for ReadAdapter` (#309).

## 0.9.1 (2024-06-24) - `utils/core` crate only
- Fixed `usize` serialization in `ByteWriter`.

## 0.9.0 (2024-05-09)
- [BREAKING] Merged `TraceLayout` into `TraceInfo` (#245).
- Implemented Lagrange Kernel constraints (#247, )
- [BREAKING] refactored `TraceOodFrame` struct (#266, #274).
- [BREAKING] explicitly limited the number of auxiliary trace segments to 1 (#267).
- Implemented additional field conversions for the `f64` field (#268).
- [BREAKING] Added support for auxiliary proofs (#271).
- Introduced async prover (enabled via `async` feature) (#280).
- [BREAKING] removed `group_vector_elements()` utility function (#282).
- [BREAKING] removed `FieldElement::zeroed_vector()` function (#282).
- [BREAKING] removed previously deprecated re-exports of core modules.
- Updated minimum supported Rust version to 1.78.

## 0.8.4 (2024-03-28) - `math` crate only
* Added more to/from conversions for `f64` field (#268).

## 0.8.4 (2024-03-18) - `utils/core` crate only
* Re-added unintentionally removed re-exported liballoc macros (#263).

## 0.8.3 (2024-03-15)
* Implemented `Serializable` and `Deserializable` on `String` (#258).
* Extended range of possible implementations of `ByteReader` and `ByteWriter`. (#262).

## 0.8.2 (2024-02-27) - `utils/core` crate only
* Extended `write_many` to support `IntoIterator` (#251)

## 0.8.1 (2024-02-21)
* Refactored utils module re-exports to comply with latest clippy updates (#250).

## 0.8.0 (2024-02-06)
* Added variable-length serialization and deserialization for `usize` type (#238).
* [BREAKING] Removed `Serializable` and `Deserializable` implementations from slices and vectors (#239).
* Moved from `log` to `tracing` for logging and added `tracing-forest` feature (#241).
* Updated provable security estimation to explicitly use the number of openings (#242).
* [BREAKING] Removed `From<u64>` and `From<u128>` implementations from field elements (#243).
* Increased min version of `rustc` to 1.75.

## 0.7.4 (2023-12-18) - `air` crate only
* Fixed a bug in `StarkProof` deserialization (#236).

## 0.7.4 (2023-12-07) - `utils/core` crate only
* Added `Clone` derive to `DeserializationError`.

## 0.7.3 (2023-12-06) - `utils/core` crate only
* Added default deserializer implementations (#233)

## 0.7.3 (2023-12-01) - `air` crate only
* Fixed `StarkProof::new_dummy()` constructor (#234).

## 0.7.2 (2023-11-30) - `air`, `fri`, and `utils/core` crates only
* Minor proof serialization and deserialization refactoring (#231).
* Added `StarkProof::new_dummy()` constructor to simplify testing (#232).

## 0.7.1 (2023-11-17) - `math` crate only
* Changed `Debug` format for field elements (#228).

## 0.7.1 (2023-10-28) - `air` crate only
* Changed most methods for `ProofOption` to be `const fn`.

## 0.7.0 (2023-10-23)
* [BREAKING] replaced the `TraceLde` struct with a trait (#207).
* [BREAKING] refactored `RandomCoin` trait (#214).
* Improved proven security estimation (#215).
* [BREAKING] replaced the `ConstraintEvaluator` struct with a trait (#217).
* Added support for proven security estimation in `no_std` context (#218).
* [BREAKING] refactored `verify()` function to take `AcceptableOptions` as a parameter (#219).
* Increased min version of `rustc` to 1.73 (#221).
* Allowed duplicate query positions (#224).

## 0.6.5 (2023-08-09) - math crate only
* Added conditional support for serde on field elements (#209)

## 0.6.4 (2023-05-26)
* Simplified construction of constraint composition polynomial (#198).
* Refactored serialization of OOD frame in STARK proofs (#199).
* Re-exported `btree_map` and `btree_set` modules from core collections (#202).
* Simplified construction of DEEP composition polynomial (#203).

## 0.6.3 (2023-05-03)
* Sped up proof verification using batch inverse (#190).
* Updated `ConstraintCommitment` to use `RowMatrix` internally (#191).
* Sped up FRI prover via more efficient `get_inv_offsets` implementation (#193).
* Exposed `build_segments()` method publicly (#194).

## 0.6.2 (2023-04-15)
* Updated `MerkleTree` and matrix structs to make them more suitable for HW acceleration (#185).
* Replaced `log2()` usage with native `.ilog2()` (#186).

## 0.6.1 (2023-03-29)
* Disabled proven security estimation in `no-std` context.

## 0.6.0 (2023-03-24)
* Implemented more efficient remainder handling in FRI (#139)
* Removed term involving conjugate OOD challenge z from deep composition polynomial (#166).
* Added `FieldElement::EXTENSION_DEGREE` constant.
* Added `FieldElement::base_element` and `FieldElement::slice_from_base_elements` methods.
* [BREAKING] Renamed `FieldElement::as_base_elements` into `FieldElement::slice_as_base_elements`.
* Added `Matrix::num_base_cols` and `Matrix::get_base_element` methods.
* [BREAKING] Renamed `Matrix` into `ColMatrix`.
* [BREAKING] Replaced `ColMatrix` with `RowMatrix` to hold LDE trace in the prover (#168).
* Updated conjectured security computation and added estimation of proven security (#151).
* Changed root of unity for `f64` field (#169).
* Implemented reduction of public inputs and proof context to field elements (#172).
* [BREAKING] Replaced `RandomCoin` struct with a trait (#176).

## 0.5.1 (2023-02-20)
* Fix no-std build for winter-utils (#153)

## 0.5.0 (2023-02-20)
* [BREAKING]: Refactored prover/verifier to take hash function as a generic parameter (#111).
* Introduced `FftInputs` trait (#124).
* Optimized `as_int()` method for `f64` field (#127, #146).
* Improved FRI remainder commitment methodology (#128).
* Added new arithmetization-friendly hash functions: Griffin and Rescue Prime Jive (#129).
* Fixed panic in prover when debugging with concurrent feature enabled (#130, #132).
* Added variable-time exponentiation option to `f64` field (#134).
* Optimized squaring for degree 2 and 3 extension fields of `f64` field (#138).
* Simplified conversion to base elements for degree 2 and 3 extension field elements (#147).
* Made closure types less restrictive for `TraceTable::fill()` (#149).
* [BREAKING] Refactored serialization/deserialization traits (#150).

## 0.4.2 (2022-11-14)
* Removed most exponentiations from the constraint evaluation step for the Prover.

## 0.4.1 (2022-10-24)
* Increased transition constraint exemption limit by 1.
* Implemented custom doubling for `f64` and `f62` field.
* Moved `f64` field arithmetic to Montgomery form (constant time).
* Updated MDS matrix and related-multiplication routine for `Rp64_256` hash function.
* Improved performance of `Matrix::interpolate_columns` function.
* Added ability to "unbatch" a `BatchMerkleProof` (via `BatchMerkleProof::into_paths()` method).
* Changed visibility of FRI utils (made them public).
* Added support for FRI folding factor of 2 (in addition to 4, 8, and 16).

## 0.4.0 (2022-04-29)
* Added support for Randomized AIR (with example).
* Added support for custom number of transition constraint exemptions.
* Enabled transition constraints of degree *n + 1* when blowup factor is *n*.
* Moved trace and constraint commitment construction into separate functions in the `Prover` trait.
* Introduced `Matrix` struct in the prover which is used as a backing type for trace and constraint evaluations.
* Added `ExtensionOf` trait and implemented it for all supported fields.
* Sped up inversion in `f64` field by using inversion method based on Fermat’s little theorem.
* Implemented `Randomizable` trait for `u32`, `u16`, and `u8` types.
* [BREAKING] `AirContext::new()` now requires `num_assertions` parameter.
* [BREAKING] Various interface changes in the `Air` trait to support multi-segment traces.
* Increased min version of `rustc` to 1.60.

## 0.3.2 (2022-01-20) - crypto
* Implemented into byte conversion for Rp64_256 digest.
* Moved capacity elements to the front of the state for Rp64_256.

## 0.3.1 (2022-01-13) - crypto
* Implemented digest to array conversion for Rp64_256 digest.
* Exposed some internal functions of Rp64_256 publicly.

## 0.3.0 (2022-01-04)
* Added `f64` field.
* Added support for cubic field extensions.
* Added an implementation of Rescue Prime hash function in `f64` field.
* Switched to Rust 2021 and increased min version of `rustc` to 1.57.
* [BREAKING] Renamed `Air::BaseElement` to `Air::BaseField`.
* [BREAKING] Replaced `prover::prove()` function with `Prover` trait.
* [BREAKING] Split `ExecutionTrace` struct into `Trace` trait and `TraceTable` struct.

## 0.2.0 (2021-08-23)
* Added `Blake3_192` as hash function option.
* Implemented high-performance version of Rescue Prime hash function.
* Removed `alloc` feature in favor of turning on `no_std` via `--no-default-features` flag only.
* Moved `rand` dependency to `dev-dependencies` only and removed `hashbrown` dependency.
* Increased min version of `rustc` to 1.54.

## 0.1.0 (2021-08-03)
* Initial release
