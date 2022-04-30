// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains Winterfell STARK prover and verifier.
//!
//! A STARK is a novel proof-of-computation scheme to create efficiently verifiable proofs of the
//! correct execution of a computation. The scheme was developed by Eli Ben-Sasson, Michael Riabzev
//! et al. at Technion - Israel Institute of Technology. STARKs do not require an initial trusted
//! setup, and rely on very few cryptographic assumptions. See [references](#references) for more
//! info.
//!
//! ## Proof generation
//! To generate a proof that a computation was executed correctly, you'll need to do the
//! following:
//!
//! 1. Define an *algebraic intermediate representation* (AIR) for your computation. This can
//!    be done by implementing [Air] trait.
//! 2. Define an execution trace for your computation. This can be done by implementing [Trace]
//!    trait. Alternatively, you can use [TraceTable] struct which already implements [Trace]
//!    trait in cases when this generic implementation works for your use case.
//! 3. Execute your computation and record its execution trace.
//! 4. Define your prover by implementing [Prover] trait. Then execute [Prover::prove()] function
//!    passing the trace generated in the previous step into it as a parameter. The function will
//!    return a instance of [StarkProof].
//!
//! This `StarkProof` can be serialized and sent to a STARK verifier for verification. The size
//! of proof depends on the specifics of a given computation, but for most computations it should
//! be in the range between 15 KB (for very small computations) and 300 KB (for very large
//! computations).
//!
//! Proof generation time is also highly dependent on the specifics of a given computation, but
//! also depends on the capabilities of the machine used to generate the proofs (i.e. on number
//! of CPU cores and memory bandwidth).
//!
//! When the crate is compiled with `concurrent` feature enabled, proof generation will be
//! performed in multiple threads (usually, as many threads as there are logical cores on the
//! machine). The number of threads can be configured via `RAYON_NUM_THREADS` environment
//! variable.
//!
//! ## Prof verification
//! To verify a [StarkProof] generated as described in the previous sections, you'll need to
//! do the following:
//!
//! 1. Define an *algebraic intermediate representation* (AIR) for you computation. This AIR
//!    must be the same as the one used during proof generation process.
//! 2. Execute [verify()] function and supply the AIR of your computation together with the
//!    [StarkProof] and related public inputs as parameters.
//!
//! Proof verification is extremely fast and is nearly independent of the complexity of the
//! computation being verified. In vast majority of cases proofs can be verified in 3 - 5 ms
//! on a modern mid-range laptop CPU (using a single core).
//!
//! There is one exception, however: if a computation requires a lot of `sequence` assertions
//! (see [Assertion] for more info), the verification time will grow linearly in the number of
//! asserted values. But for the impact to be noticeable, the number of asserted values would
//! need to be in tens of thousands. And even for hundreds of thousands of asserted values, the
//! verification time should not exceed 50 ms.
//!
//! # Examples
//! The best way to understand the STARK proof generation and verification process is to go
//! through a trivial example from start to finish. First, we'll need to pick a computation for
//! which we'll be generating and verifying STARK proofs. To keep things simple, we'll use the
//! following:
//!
//! ```no_run
//! use winterfell::math::{fields::f128::BaseElement, FieldElement};
//!
//! fn do_work(start: BaseElement, n: usize) -> BaseElement {
//!    let mut result = start;
//!    for _ in 1..n {
//!        result = result.exp(3) + BaseElement::new(42);
//!    }
//!    result
//! }
//! ```
//!
//! This computation starts with an element in a finite field and then, for the specified number
//! of steps, cubes the element and adds value `42` to it.
//!
//! Suppose, we run this computation for a million steps and get some result. Using STARKs we can
//! prove that we did the work correctly without requiring any verifying party to re-execute the
//! computation. Here is how to do it:
//!
//! First, we need to define an *execution trace* for our computation. This trace should capture
//! the state of the computation at every step of its execution. In our case, the trace is just a
//! single column of intermediate values after each execution of the loop. For example, if we start
//! with value `3` and run the computation for 1,048,576 (same as 2<sup>20</sup>) steps, the
//! execution trace will look like this:
//!
//! | Step      | State  |
//! | :-------: | :----- |
//! | 0         | 3      |
//! | 1         | 69     |
//! | 2         | 328551 |
//! | 3         | 35465687262668193 |
//! | 4         | 237280320818395402166933071684267763523 |
//! | ...       |
//! | 1,048,575 | 247770943907079986105389697876176586605 |
//!
//! To record the trace, we'll use the [TraceTable] struct. The function below, is just a
//! modified version of the `do_work()` function which records every intermediate state of the
//! computation in the [TraceTable] struct:
//!
//! ```no_run
//! use winterfell::{
//!     math::{fields::f128::BaseElement, FieldElement},
//!     TraceTable,
//! };
//!
//! pub fn build_do_work_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
//!     // Instantiate the trace with a given width and length; this will allocate all
//!     // required memory for the trace
//!     let trace_width = 1;
//!     let mut trace = TraceTable::new(trace_width, n);
//!
//!     // Fill the trace with data; the first closure initializes the first state of the
//!     // computation; the second closure computes the next state of the computation based
//!     // on its current state.
//!     trace.fill(
//!         |state| {
//!             state[0] = start;
//!         },
//!         |_, state| {
//!             state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
//!         },
//!     );
//!
//!     trace
//! }
//! ```
//!
//! Next, we need to define *algebraic intermediate representation* (AIR) for our computation.
//! This process is usually called *arithmetization*. We do this by implementing the [Air] trait.
//! At the high level, the code below does three things:
//!
//! 1. Defines what the public inputs for our computation should look like. These inputs are
//!    called "public" because they must be known to both, the prover and the verifier.
//! 2. Defines a transition function with a single transition constraint. This transition
//!    constraint must evaluate to zero for all valid state transitions, and to non-zero for any
//!    invalid state transition. The degree of this constraint is 3 (see more about constraint
//!    degrees "Constraint degrees" section of [Air] trait documentation).
//! 3. Define two assertions against an execution trace of our computation. These assertions tie
//!    a specific set of public inputs to a specific execution trace (see more about assertions
//!    "Trace assertions" section of [Air] trait documentation).
//!
//! Here is the actual code:
//!
//! ```no_run
//! use winterfell::{
//!     math::{fields::f128::BaseElement, FieldElement},
//!     Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable,
//!     TraceInfo, TransitionConstraintDegree,
//! };
//!
//! // Public inputs for our computation will consist of the starting value and the end result.
//! pub struct PublicInputs {
//!     start: BaseElement,
//!     result: BaseElement,
//! }
//!
//! // We need to describe how public inputs can be converted to bytes.
//! impl Serializable for PublicInputs {
//!     fn write_into<W: ByteWriter>(&self, target: &mut W) {
//!         target.write(self.start);
//!         target.write(self.result);
//!     }
//! }
//!
//! // For a specific instance of our computation, we'll keep track of the public inputs and
//! // the computation's context which we'll build in the constructor. The context is used
//! // internally by the Winterfell prover/verifier when interpreting this AIR.
//! pub struct WorkAir {
//!     context: AirContext<BaseElement>,
//!     start: BaseElement,
//!     result: BaseElement,
//! }
//!
//! impl Air for WorkAir {
//!     // First, we'll specify which finite field to use for our computation, and also how
//!     // the public inputs must look like.
//!     type BaseField = BaseElement;
//!     type PublicInputs = PublicInputs;
//!
//!     // Here, we'll construct a new instance of our computation which is defined by 3
//!     // parameters: starting value, number of steps, and the end result. Another way to
//!     // think about it is that an instance of our computation is a specific invocation of
//!     // the do_work() function.
//!     fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
//!         // our execution trace should have only one column.
//!         assert_eq!(1, trace_info.width());
//!
//!         // Our computation requires a single transition constraint. The constraint itself
//!         // is defined in the evaluate_transition() method below, but here we need to specify
//!         // the expected degree of the constraint. If the expected and actual degrees of the
//!         // constraints don't match, an error will be thrown in the debug mode, but in release
//!         // mode, an invalid proof will be generated which will not be accepted by any verifier.
//!         let degrees = vec![TransitionConstraintDegree::new(3)];
//!
//!         // We also need to specify the exact number of assertions we will place against the
//!         // execution trace. This number must be the same as the number of items in a vector
//!         // returned from the get_assertions() method below.
//!         let num_assertions = 2;
//!
//!         WorkAir {
//!             context: AirContext::new(trace_info, degrees, num_assertions, options),
//!             start: pub_inputs.start,
//!             result: pub_inputs.result,
//!         }
//!     }
//!
//!     // In this method we'll define our transition constraints; a computation is considered to
//!     // be valid, if for all valid state transitions, transition constraints evaluate to all
//!     // zeros, and for any invalid transition, at least one constraint evaluates to a non-zero
//!     // value. The `frame` parameter will contain current and next states of the computation.
//!     fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
//!         &self,
//!         frame: &EvaluationFrame<E>,
//!         _periodic_values: &[E],
//!         result: &mut [E],
//!     ) {
//!         // First, we'll read the current state, and use it to compute the expected next state
//!         let current_state = &frame.current()[0];
//!         let next_state = current_state.exp(3u32.into()) + E::from(42u32);
//!
//!         // Then, we'll subtract the expected next state from the actual next state; this will
//!         // evaluate to zero if and only if the expected and actual states are the same.
//!         result[0] = frame.next()[0] - next_state;
//!     }
//!
//!     // Here, we'll define a set of assertions about the execution trace which must be
//!     // satisfied for the computation to be valid. Essentially, this ties computation's
//!     // execution trace to the public inputs.
//!     fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
//!         // for our computation to be valid, value in column 0 at step 0 must be equal to the
//!         // starting value, and at the last step it must be equal to the result.
//!         let last_step = self.trace_length() - 1;
//!         vec![
//!             Assertion::single(0, 0, self.start),
//!             Assertion::single(0, last_step, self.result),
//!         ]
//!     }
//!
//!     // This is just boilerplate which is used by the Winterfell prover/verifier to retrieve
//!     // the context of the computation.
//!     fn context(&self) -> &AirContext<Self::BaseField> {
//!         &self.context
//!     }
//! }
//! ```
//!
//! Next, we need define our prover. This can be done by implementing [Prover] trait. The trait is
//! pretty simple and has just a few required methods. Here is how our implementation could look
//! like:
//!
//! ```no_run
//! use winterfell::{
//!     math::{fields::f128::BaseElement, FieldElement},
//!     ProofOptions, Prover, Trace, TraceTable
//! };
//!
//! # use winterfell::{
//! #   Air, AirContext, Assertion, ByteWriter, EvaluationFrame, Serializable,
//! #   TraceInfo, TransitionConstraintDegree,
//! # };
//! #
//! # pub struct PublicInputs {
//! #     start: BaseElement,
//! #     result: BaseElement,
//! # }
//! #
//! # impl Serializable for PublicInputs {
//! #     fn write_into<W: ByteWriter>(&self, target: &mut W) {
//! #         target.write(self.start);
//! #         target.write(self.result);
//! #     }
//! # }
//! #
//! # pub struct WorkAir {
//! #     context: AirContext<BaseElement>,
//! #     start: BaseElement,
//! #     result: BaseElement,
//! # }
//! #
//! # impl Air for WorkAir {
//! #     type BaseField = BaseElement;
//! #     type PublicInputs = PublicInputs;
//! #
//! #     fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
//! #         assert_eq!(1, trace_info.width());
//! #         let degrees = vec![TransitionConstraintDegree::new(3)];
//! #         WorkAir {
//! #             context: AirContext::new(trace_info, degrees, 2, options),
//! #             start: pub_inputs.start,
//! #             result: pub_inputs.result,
//! #         }
//! #     }
//! #
//! #     fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
//! #         &self,
//! #         frame: &EvaluationFrame<E>,
//! #         _periodic_values: &[E],
//! #         result: &mut [E],
//! #     ) {
//! #         let current_state = &frame.current()[0];
//! #         let next_state = current_state.exp(3u32.into()) + E::from(42u32);
//! #         result[0] = frame.next()[0] - next_state;
//! #     }
//! #
//! #     fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
//! #         let last_step = self.trace_length() - 1;
//! #         vec![
//! #             Assertion::single(0, 0, self.start),
//! #             Assertion::single(0, last_step, self.result),
//! #         ]
//! #     }
//! #
//! #     fn context(&self) -> &AirContext<Self::BaseField> {
//! #         &self.context
//! #     }
//! # }
//! #
//! // Our prover needs to hold STARK protocol parameters which are specified via ProofOptions
//! // struct.
//! struct WorkProver {
//!     options: ProofOptions
//! }
//!
//! impl WorkProver {
//!     pub fn new(options: ProofOptions) -> Self {
//!         Self { options }
//!     }
//! }
//!
//! // When implementing Prover trait we set the `Air` associated type to the AIR of the
//! // computation we defined previously, and set the `Trace` associated type to `TraceTable`
//! // struct as we don't need to define a custom trace for our computation.
//! impl Prover for WorkProver {
//!     type BaseField = BaseElement;
//!     type Air = WorkAir;
//!     type Trace = TraceTable<Self::BaseField>;
//!
//!     // Our public inputs consist of the first and last value in the execution trace.
//!     fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
//!         let last_step = trace.length() - 1;
//!         PublicInputs {
//!             start: trace.get(0, 0),
//!             result: trace.get(0, last_step),
//!         }
//!     }
//!
//!     fn options(&self) -> &ProofOptions {
//!         &self.options
//!     }
//! }
//! ```
//!
//! Now, we are finally ready to generate and verify STARK proofs.
//!
//! In the code below, we will execute our computation and get the result together with the proof
//! that the computation was executed correctly. Then, we will use this proof (together with the
//! public inputs) to verify that we did in fact execute the computation and got the claimed
//! result.
//!
//! ```
//! # use winterfell::{
//! #    math::{fields::f128::BaseElement, FieldElement},
//! #    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, Serializable,
//! #    TraceInfo, TransitionConstraintDegree, TraceTable, FieldExtension,
//! #    HashFunction, Prover, ProofOptions, StarkProof, Trace,
//! # };
//! #
//! # pub fn build_do_work_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
//! #     let trace_width = 1;
//! #     let mut trace = TraceTable::new(trace_width, n);
//! #     trace.fill(
//! #         |state| {
//! #             state[0] = start;
//! #         },
//! #         |_, state| {
//! #             state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
//! #         },
//! #     );
//! #     trace
//! # }
//! #
//! #
//! # pub struct PublicInputs {
//! #     start: BaseElement,
//! #     result: BaseElement,
//! # }
//! #
//! # impl Serializable for PublicInputs {
//! #     fn write_into<W: ByteWriter>(&self, target: &mut W) {
//! #         target.write(self.start);
//! #         target.write(self.result);
//! #     }
//! # }
//! #
//! # pub struct WorkAir {
//! #     context: AirContext<BaseElement>,
//! #     start: BaseElement,
//! #     result: BaseElement,
//! # }
//! #
//! # impl Air for WorkAir {
//! #     type BaseField = BaseElement;
//! #     type PublicInputs = PublicInputs;
//! #
//! #     fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
//! #         assert_eq!(1, trace_info.width());
//! #         let degrees = vec![TransitionConstraintDegree::new(3)];
//! #         WorkAir {
//! #             context: AirContext::new(trace_info, degrees, 2, options),
//! #             start: pub_inputs.start,
//! #             result: pub_inputs.result,
//! #         }
//! #     }
//! #
//! #     fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
//! #         &self,
//! #         frame: &EvaluationFrame<E>,
//! #         _periodic_values: &[E],
//! #         result: &mut [E],
//! #     ) {
//! #         let current_state = &frame.current()[0];
//! #         let next_state = current_state.exp(3u32.into()) + E::from(42u32);
//! #         result[0] = frame.next()[0] - next_state;
//! #     }
//! #
//! #     fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
//! #         let last_step = self.trace_length() - 1;
//! #         vec![
//! #             Assertion::single(0, 0, self.start),
//! #             Assertion::single(0, last_step, self.result),
//! #         ]
//! #     }
//! #
//! #     fn context(&self) -> &AirContext<Self::BaseField> {
//! #         &self.context
//! #     }
//! # }
//! #
//! # struct WorkProver {
//! #    options: ProofOptions
//! # }
//! #
//! # impl WorkProver {
//! #    pub fn new(options: ProofOptions) -> Self {
//! #        Self { options }
//! #    }
//! # }
//! #
//! # impl Prover for WorkProver {
//! #    type BaseField = BaseElement;
//! #    type Air = WorkAir;
//! #    type Trace = TraceTable<Self::BaseField>;
//! #
//! #    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
//! #        let last_step = trace.length() - 1;
//! #        PublicInputs {
//! #            start: trace.get(0, 0),
//! #            result: trace.get(0, last_step),
//! #        }
//! #    }
//! #
//! #    fn options(&self) -> &ProofOptions {
//! #        &self.options
//! #    }
//! #  }
//! #
//! // We'll just hard-code the parameters here for this example. We'll also just run the
//! // computation just for 1024 steps to save time during testing.
//! let start = BaseElement::new(3);
//! let n = 1024;
//!
//! // Build the execution trace and get the result from the last step.
//! let trace = build_do_work_trace(start, n);
//! let result = trace.get(0, n - 1);
//!
//! // Define proof options; these will be enough for ~96-bit security level.
//! let options = ProofOptions::new(
//!     32, // number of queries
//!     8,  // blowup factor
//!     0,  // grinding factor
//!     HashFunction::Blake3_256,
//!     FieldExtension::None,
//!     8,   // FRI folding factor
//!     128, // FRI max remainder length
//! );
//!
//! // Instantiate the prover and generate the proof.
//! let prover = WorkProver::new(options);
//! let proof = prover.prove(trace).unwrap();
//!
//! // Verify the proof. The number of steps and options are encoded in the proof itself,
//! // so we don't need to pass them explicitly to the verifier.
//! let pub_inputs = PublicInputs { start, result };
//! assert!(winterfell::verify::<WorkAir>(proof, pub_inputs).is_ok());
//! ```
//!
//! That's all there is to it!
//!
//! # References
//!
//! If you are interested in learning how STARKs work under the hood, here are a few links to get
//! you started. From the standpoint of this library, *arithmetization* is by far the most
//! important concept to understand.
//!
//! * STARKs whitepaper: [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
//! * STARKs vs. SNARKs: [A Cambrian Explosion of Crypto Proofs](https://nakamoto.com/cambrian-explosion-of-crypto-proofs/)
//!
//! Vitalik Buterin's blog series on zk-STARKs:
//! * [STARKs, part 1: Proofs with Polynomials](https://vitalik.ca/general/2017/11/09/starks_part_1.html)
//! * [STARKs, part 2: Thank Goodness it's FRI-day](https://vitalik.ca/general/2017/11/22/starks_part_2.html)
//! * [STARKs, part 3: Into the Weeds](https://vitalik.ca/general/2018/07/21/starks_part_3.html)
//!
//! StarkWare's STARK Math blog series:
//! * [STARK Math: The Journey Begins](https://medium.com/starkware/stark-math-the-journey-begins-51bd2b063c71)
//! * [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
//! * [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
//! * [Low Degree Testing](https://medium.com/starkware/low-degree-testing-f7614f5172db)
//! * [A Framework for Efficient STARKs](https://medium.com/starkware/a-framework-for-efficient-starks-19608ba06fbe)

#![cfg_attr(not(feature = "std"), no_std)]

pub use prover::{
    crypto, iterators, math, Air, AirContext, Assertion, AuxTraceRandElements, BoundaryConstraint,
    BoundaryConstraintGroup, ByteReader, ByteWriter, ConstraintCompositionCoefficients,
    ConstraintDivisor, DeepCompositionCoefficients, Deserializable, DeserializationError,
    EvaluationFrame, FieldExtension, HashFunction, Matrix, ProofOptions, Prover, ProverError,
    Serializable, SliceReader, StarkProof, Trace, TraceInfo, TraceLayout, TraceTable,
    TraceTableFragment, TransitionConstraintDegree, TransitionConstraintGroup,
};
pub use verifier::{verify, VerifierError};
