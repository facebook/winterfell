# FRI
This crate contains an implementation of FRI prover and verifier used in STARK proof generation and verification.

FRI stands for Fast Reed-Solomon Interactive Oracle Proof of Proximity, and is used in the STARK protocol for low-degree testing. Specifically, given a commitment to a set of evaluations of some function over domain *D*, the verifier can be convinced that the function is a polynomial of degree at most *d*, by making a small number of queries to the commitment.

### Provers
FRI provers are located in the [prover](src/prover) module. Currently, the only available prover is a monolith prover. This prover supports multi-threaded proof generation but is limited to a single machine. A fully distributed prover will be added in the future.

To generate proofs using multiple threads, the crate must be compiled with `concurrent` feature enabled.

Proof generation is split into two procedures:
* `build_layers()`, which executes the commit phase of the FRI protocol, and
* `build_proof()`, which executes the query phase of the FRI protocol.

The end result of the `build_proof()` procedure is a `FriProof` which gets included into a `StarkProof` when full STARK protocol is executed.

### Verifier
There is a single FRI verifier which is located in the [verifier](src/verifier) module. The module exposes a `verify()` function which assumes that `FriProof` has already been parsed into relevant components (which is currently done in the STARK verifier crate).


### Parameters
This crates supports executing FRI protocol with dynamically configurable parameters including:

* Base STARK field,
* Extension field,
* Domain blowup factor,
* Hash function (used for Merkle commitments),
* Folding factor (used for degree reduction for each FRI layer),
* Maximum size of the last FRI layer.

## References

* StarkWare's blog post on [Low Degree Testing](https://medium.com/starkware/low-degree-testing-f7614f5172db)
* [Fast Reed-Solomon Interactive Oracle Proofs of Proximity](https://eccc.weizmann.ac.il/report/2017/134/)
* [DEEP-FRI: Sampling Outside the Box Improves Soundness](https://eprint.iacr.org/2019/336)
* Swastik Kooparty's [talk on DEEP-FRI](https://www.youtube.com/watch?v=txo_kPSn59Y&list=PLcIyXLwiPilWvjvNkhMn283LV370Pk5CT&index=6)


License
-------

This project is [MIT licensed](../LICENSE).