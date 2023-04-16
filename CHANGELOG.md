# Changelog

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
