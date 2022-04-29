# Changelog

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