# Winterfell 🐺

<a href="https://github.com/novifinancial/winterfell/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
<a href="https://github.com/facebook/winterfell/actions/workflows/ci.yml"><img src="https://github.com/novifinancial/winterfell/workflows/CI/badge.svg?branch=main">
<a href="https://deps.rs/repo/github/novifinancial/winterfell"><img src="https://deps.rs/repo/github/novifinancial/winterfell/status.svg"></a>
<img src="https://img.shields.io/badge/prover-rustc_1.84+-lightgray.svg">
<img src="https://img.shields.io/badge/verifier-rustc_1.84+-lightgray.svg">
<a href="https://crates.io/crates/winterfell"><img src="https://img.shields.io/crates/v/winterfell"></a>

A STARK prover and verifier for arbitrary computations.

**WARNING:** This is a research project. It has not been audited and may contain bugs and security flaws. This implementation is NOT ready for production use.

## Overview

A STARK is a novel proof-of-computation scheme to create efficiently verifiable proofs of the correct execution of a computation. The scheme was developed by Eli Ben-Sasson, Michael Riabzev et al. at Technion - Israel Institute of Technology. STARKs do not require an initial trusted setup, and rely on very few cryptographic assumptions. See [references](#References) for more info.

The aim of this project is to build a feature-rich, easy to use, and highly performant STARK prover which can generate integrity proofs for very large computations.

### Status and features

Winterfell is a fully-functional, multi-threaded STARK prover and verifier with the following nice properties:

**A simple interface.** The library provides a relatively simple interface for describing general computations. See [usage](#Usage) for a quick tutorial, [air crate](air) for the description of the interface, and [examples crate](examples) for a few real-world examples.

**Randomized AIR support.** The library supports multi-stage trace commitments, which enables support for [randomized AIR](air/#randomized-air). This greatly increases the expressivity of AIR constraints, and enables, among other things, multiset and permutation checks similar to the ones available in PLONKish systems.

**Multi-threaded proof generation.** When compiled with `concurrent` feature enabled, the proof generation process will run in multiple threads. The library also supports concurrent construction of execution trace tables. The [performance](#Performance) section showcases the benefits of multi-threading.

**Configurable fields and hash functions.** The library is generic over the selection of fields (both base field and extension field) and hash functions (including arithmetization-friendly hashes). This simplifies fine-tuning of proof generation for specific performance and security targets. Some options for both are provided in the [math](math) and [crypto](crypto) crates, but the library can work with any implementation that complies with the specified interfaces.

**WebAssembly support.** The library is written in pure Rust and can be compiled to WebAssembly. The `std` standard library is enabled as feature by default for both prover and verifier crates. For WASM targets, one can compile with default features disabled by using `--no-default-features` flag.

**Async prover.** The library supports both sync and async variants of the `Prover` trait. By default, the sync version is exported. The async version of the trait can be enabled via the `async` feature flag.

#### Planned features

Over time, we hope extend the library with additional features:

**Perfect zero-knowledge.** The current implementation provides succinct proofs but NOT perfect zero-knowledge. This means that, in its current form, the library may not be suitable for use cases where proofs must not leak any info about secret inputs.


### Project structure
The project is organized into several crates like so:

| Crate                | Description |
| -------------------- | ----------- |
| [examples](examples) | Contains examples of generating/verifying proofs for several toy and real-world computations. |
| [prover](prover)     | Contains an implementation of a STARK prover which can be used to generate computational integrity proofs. |
| [verifier](verifier) | Contains an implementation of a STARK verifier which can verify proofs generated by the Winterfell prover. |
| [winterfell](winterfell) | Re-exports prover and verifier crates as a single create for simplified dependency management. |
| [air](air)           | Contains components needed to describe arbitrary computations in a STARK-specific format. |
| [fri](fri)           | Contains implementation of a FRI prover and verifier. These are used internally by the STARK prover and verifier. |
| [math](math)         | Contains modules with math operations needed in STARK proof generation/verification. These include: finite field arithmetic, polynomial arithmetic, and FFTs. |
| [crypto](crypto)     | Contains modules with cryptographic operations needed in STARK proof generation/verification. Specifically: hash functions and Merkle trees. |
| [utils](utils)       | Contains a set of utility traits, functions, and macros used throughout the library. |

## Usage
Generating STARK proofs for a computation is a relatively complicated process. This library aims to abstract away most of the complexity, however, the users are still expected to provide descriptions of their computations in a STARK-specific format. This format is called *algebraic intermediate representation*, or AIR, for short.

This library contains several higher-level constructs which make defining AIRs for computations a little easier, and there are also examples of AIRs for several computations available in the [examples crate](examples). However, the best way to understand the STARK proof generation process is to go through a trivial example from start to finish.

First, we'll need to pick a computation for which we'll be generating and verifying STARK proofs. To keep things simple, we'll use the following:

```Rust
use winterfell::math::{fields::f128::BaseElement, FieldElement};

fn do_work(start: BaseElement, n: usize) -> BaseElement {
    let mut result = start;
    for _ in 1..n {
        result = result.exp(3) + BaseElement::new(42);
    }
    result
}
```

This computation starts with an element in a finite field and then, for the specified number of steps, cubes the element and adds value `42` to it.

Suppose, we run this computation for a million steps and get some result. Using STARKs we can prove that we did the work correctly without requiring any verifying party to re-execute the computation. Here is how to do it.

First, we need to define an *execution trace* for our computation. This trace should capture the state of the computation at every step of its execution. In our case, the trace is just a single column of intermediate values after each execution of the loop. For example, if we start with value `3` and run the computation for 1,048,576 (same as 2<sup>20</sup>) steps, the execution trace will look like this:

| Step      | State  |
| :-------: | :----- |
| 0         | 3      |
| 1         | 69     |
| 2         | 328551 |
| 3         | 35465687262668193 |
| 4         | 237280320818395402166933071684267763523 |
| ...       |
| 1,048,575 | 247770943907079986105389697876176586605 |

To record the trace, we'll use the `TraceTable` struct provided by the library. The function below, is just a modified version of the `do_work()` function which records every intermediate state of the computation in the `TraceTable` struct:

```Rust
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    TraceTable,
};

pub fn build_do_work_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
    // Instantiate the trace with a given width and length; this will allocate all
    // required memory for the trace
    let trace_width = 1;
    let mut trace = TraceTable::new(trace_width, n);

    // Fill the trace with data; the first closure initializes the first state of the
    // computation; the second closure computes the next state of the computation based
    // on its current state.
    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
        },
    );

    trace
}
```

Next, we need to define *algebraic intermediate representation* (AIR) for our computation. This process is usually called *arithmetization*. We do this by implementing the `Air` trait. At the high level, the code below does three things:

1. Defines what the public inputs for our computation should look like. These inputs are called "public" because they must be known to both, the prover and the verifier.
2. Defines a transition function with a single transition constraint. This transition constraint must evaluate to zero for all valid state transitions, and to non-zero for any invalid state transition. The degree of this constraint is 3 (see more about constraint degrees [here](air/#Constraint-degrees)).
3. Define two assertions against an execution trace of our computation. These assertions tie a specific set of public inputs to a specific execution trace (see more about assertions [here](air/#Trace-assertions)).

For more information about arithmetization see [air crate](air#Arithmetization), and here is the actual code:

```Rust
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// Public inputs for our computation will consist of the starting value and the end result.
pub struct PublicInputs {
    start: BaseElement,
    result: BaseElement,
}

// We need to describe how public inputs can be converted to field elements.
impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

// For a specific instance of our computation, we'll keep track of the public inputs and
// the computation's context which we'll build in the constructor. The context is used
// internally by the Winterfell prover/verifier when interpreting this AIR.
pub struct WorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
}

impl Air for WorkAir {
    // First, we'll specify which finite field to use for our computation, and also how
    // the public inputs must look like.
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // Here, we'll construct a new instance of our computation which is defined by 3 parameters:
    // starting value, number of steps, and the end result. Another way to think about it is
    // that an instance of our computation is a specific invocation of the do_work() function.
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // our execution trace should have only one column.
        assert_eq!(1, trace_info.width());

        // Our computation requires a single transition constraint. The constraint itself
        // is defined in the evaluate_transition() method below, but here we need to specify
        // the expected degree of the constraint. If the expected and actual degrees of the
        // constraints don't match, an error will be thrown in the debug mode, but in release
        // mode, an invalid proof will be generated which will not be accepted by any verifier.
        let degrees = vec![TransitionConstraintDegree::new(3)];

        // We also need to specify the exact number of assertions we will place against the
        // execution trace. This number must be the same as the number of items in a vector
        // returned from the get_assertions() method below.
        let num_assertions = 2;

        WorkAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
        }
    }

    // In this method we'll define our transition constraints; a computation is considered to
    // be valid, if for all valid state transitions, transition constraints evaluate to all
    // zeros, and for any invalid transition, at least one constraint evaluates to a non-zero
    // value. The `frame` parameter will contain current and next states of the computation.
    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        // First, we'll read the current state, and use it to compute the expected next state
        let current_state = frame.current()[0];
        let next_state = current_state.exp(3u32.into()) + E::from(42u32);

        // Then, we'll subtract the expected next state from the actual next state; this will
        // evaluate to zero if and only if the expected and actual states are the same.
        result[0] = frame.next()[0] - next_state;
    }

    // Here, we'll define a set of assertions about the execution trace which must be satisfied
    // for the computation to be valid. Essentially, this ties computation's execution trace
    // to the public inputs.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // for our computation to be valid, value in column 0 at step 0 must be equal to the
        // starting value, and at the last step it must be equal to the result.
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
        ]
    }

    // This is just boilerplate which is used by the Winterfell prover/verifier to retrieve
    // the context of the computation.
    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}
```

Next, we need define our prover. This can be done by implementing [Prover] trait. The trait is
pretty simple and has just a few required methods. Here is how our implementation could look
like:
```Rust
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f128::BaseElement, FieldElement},
    matrix::ColMatrix,
    DefaultConstraintEvaluator, DefaultTraceLde, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable,
};

// We'll use BLAKE3 as the hash function during proof generation.
type Blake3 = Blake3_256<BaseElement>;

// Our prover needs to hold STARK protocol parameters which are specified via ProofOptions
// struct.
struct WorkProver {
    options: ProofOptions,
}

impl WorkProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

// When implementing the Prover trait we set the `Air` associated type to the AIR of the
// computation we defined previously, and set the `Trace` associated type to `TraceTable`
// struct as we don't need to define a custom trace for our computation. For other
// associated types, we'll use default implementation provided by Winterfell.
impl Prover for WorkProver {
    type BaseField = BaseElement;
    type Air = WorkAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Blake3>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, WorkAir, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;

    // Our public inputs consist of the first and last value in the execution trace.
    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    // We'll use the default trace low-degree extension.
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    // We'll use the default constraint evaluator to evaluate AIR constraints.
    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a WorkAir,
        aux_rand_elements: Option<Self::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    // We'll use the default constraint commitment.
    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
```

Now, we are finally ready to generate a STARK proof. The function below, will execute our computation, and will return the result together with the proof that the computation was executed correctly.

```Rust
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    FieldExtension, HashFunction, ProofOptions, Proof,
};

pub fn prove_work() -> (BaseElement, Proof) {
    // We'll just hard-code the parameters here for this example.
    let start = BaseElement::new(3);
    let n = 1_048_576;

    // Build the execution trace and get the result from the last step.
    let trace = build_do_work_trace(start, n);
    let result = trace.get(0, n - 1);

    // Define proof options; these will be enough for ~96-bit security level.
    let options = ProofOptions::new(
        32, // number of queries
        8,  // blowup factor
        0,  // grinding factor
        FieldExtension::None,
        8,   // FRI folding factor
        127, // FRI remainder max degree
    );

    // Instantiate the prover and generate the proof.
    let prover = WorkProver::new(options);
    let proof = prover.prove(trace).unwrap();

    (result, proof)
}
```

We can then give this proof (together with the public inputs) to anyone, and they can verify that we did in fact execute the computation and got the claimed result. They can do this like so:

```Rust
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::fields::f128::BaseElement,
    verify, AcceptableOptions, Proof,
};

type Blake3 = Blake3_256<BaseElement>;

pub fn verify_work(start: BaseElement, result: BaseElement, proof: Proof) {
    // The verifier will accept proofs with parameters which guarantee 95 bits or more of
    // conjectured security
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);

    // The number of steps and options are encoded in the proof itself, so we don't need to
    // pass them explicitly to the verifier.
    let pub_inputs = PublicInputs { start, result };
    match verify::<WorkAir, Blake3, DefaultRandomCoin<Blake3>>(proof, pub_inputs, &min_opts) {
        Ok(_) => println!("yay! all good!"),
        Err(_) => panic!("something went terribly wrong!"),
    }
}
```

That's all there is to it! As mentioned above, the [examples](examples) crate contains examples of much more interesting computations (together with instructions on how to compile and run these examples). So, do check it out.

## Performance
The Winterfell prover's performance depends on a large number of factors including the nature of the computation itself, efficiency of encoding the computation in AIR, proof generation parameters, hardware setup etc. Thus, the benchmarks below should be viewed as directional: they illustrate the general trends, but concrete numbers will be different for different computations, choices of parameters etc.

The computation we benchmark here is a chain of Rescue hash invocations (see [examples](examples/#Rescue-hash-chain) for more info). The benchmarks were run on Intel Core i9-9980KH @ 2.4 GHz and 32 GB of RAM using all 8 cores.

<table style="text-align:center">
    <thead>
        <tr>
            <th rowspan=2 style="text-align:left">Chain length</th>
            <th rowspan=2 style="text-align:center">Trace time</th>
            <th colspan=2 style="text-align:center">96 bit security</th>
            <th colspan=2 style="text-align:center">128 bit security</th>
            <th rowspan=2 style="text-align:center">R1CS equiv.</th>
        </tr>
        <tr>
            <th>Proving time</th>
            <th>Proof size</th>
            <th>Proving time</th>
            <th>Proof size</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align:left">2<sup>10</sup></td>
            <td>0.1 sec</td>
            <td>0.04 sec</td>
            <td>51 KB</td>
            <td>0.07 sec</td>
            <td>102 KB</td>
            <td>2<sup>18</sup> constr.</td>
        </tr>
        <tr>
            <td style="text-align:left">2<sup>12</sup></td>
            <td>0.4 sec</td>
            <td>0.14 sec</td>
            <td>65 KB</td>
            <td>0.25 sec</td>
            <td>128 KB</td>
            <td>2<sup>20</sup> constr.</td>
        </tr>
        <tr>
            <td style="text-align:left">2<sup>14</sup></td>
            <td>1.4 sec</td>
            <td>0.6 sec</td>
            <td>80 KB</td>
            <td>1 sec</td>
            <td>156 KB</td>
            <td>2<sup>22</sup> constr.</td>
        </tr>
        <tr>
            <td style="text-align:left">2<sup>16</sup></td>
            <td>6 sec</td>
            <td>2.5 sec</td>
            <td>94 KB</td>
            <td>4 sec</td>
            <td>184 KB</td>
            <td>2<sup>24</sup> constr.</td>
        </tr>
        <tr>
            <td style="text-align:left">2<sup>18</sup></td>
            <td>24 sec</td>
            <td>11 sec</td>
            <td>112 KB</td>
            <td>18 sec </td>
            <td>216 KB </td>
            <td>2<sup>26</sup> constr.</td>
        </tr>
        <tr>
            <td style="text-align:left">2<sup>20</sup></td>
            <td>94 sec</td>
            <td>50 sec</td>
            <td>128 KB</td>
            <td>89 sec </td>
            <td>252 KB </td>
            <td>2<sup>28</sup> constr.</td>
        </tr>
    </tbody>
</table>

A few remarks about these benchmarks:
* **Trace time** is the time it takes to generate an execution trace for the computation. This time does not depend on the chosen security level. For this specific computation, trace generation must be sequential, and thus, cannot take advantage of multiple cores. However, for other computations, where execution trace can be generated in parallel, trace time would be much smaller in relation to the proving time (see below).
* **R1CS equiv.** is a very rough estimate of how many R1CS constraints would be required for this computation. The assumption here is that a single invocation of Rescue hash function requires ~250 R1CS constraints.
* Not included in the table, the time it takes to verify proofs in all benchmarks above is between 2 ms and 6 ms using a single CPU core.
* As can be seen from the table, with STARKs, we can dynamically trade off proof size, proof security level, and proving time against each other.

Let's benchmark another example. This time our computation will consist of verifying many Lamport+ signatures (see [example](examples/#LamportPlus-signatures)). This is a much more complicated computation. For comparison, execution trace for Rescue hash chain requires only 4 columns, but for Lamport+ signature verification we use 22 columns. The table below shows benchmarks for verifying different numbers of signatures on the same 8-core machine (at 123-bit security level).

| # of signatures | Trace time | Proving time | Prover RAM | Proof size | Verifier time |
| --------------- | :--------: | :----------: | :--------: | :--------: | :-----------: |
| 64              | 0.2 sec    | 1.2 sec      | 0.5 GB     | 110 KB     | 4.4 ms        |
| 128             | 0.4 sec    | 2.6 sec      | 1.0 GB     | 121 KB     | 4.4 ms        |
| 256             | 0.8 sec    | 5.3 sec      | 1.9 GB     | 132 KB     | 4.5 ms        |
| 512             | 1.6 sec    | 10.9 sec     | 3.8 GB     | 139 KB     | 4.9 ms        |
| 1024            | 3.2 sec    | 20.5 sec     | 7.6 GB     | 152 KB     | 5.9 ms        |

A few observations about these benchmarks:
* Trace time and prover RAM (RAM consumed by the prover during proof generation) grow pretty much linearly with the size of the computation.
* Proving time grows very slightly faster than linearly with the size of the computation.
* Proof size and verifier time grow much slower than linearly (actually logarithmically) with the size of the computation.

Another difference between this example and Rescue hash chain is that we can generate execution trace for each signature verification independently, and thus, we can build the entire trace in parallel using multiple threads. In general, Winterfell prover performance scales nearly linearly with every additional CPU core. This is because nearly all steps of STARK proof generation process can be parallelized. The table below illustrates this relationship on the example of verifying 1024 Lamport+ signatures (at 123-bit security level). This time, our benchmark machine is AMD EPYC 7003 with 64 CPU cores.

| Threads | Trace time  | Proving time | Total time (trace + proving) | Improvement |
| ------- | :---------: | :----------: | :--------------------------: | :---------: |
| 1       | 28 sec      | 127 sec      | 155 sec                      |  1x         |
| 2       | 14 sec      | 64 sec       | 78 sec                       |  2x         |
| 4       | 6.7 sec     | 33 sec       | 39.7 sec                     |  3.9x       |
| 8       | 3.8 sec     | 17 sec       | 20.8 sec                     |  7.5x       |
| 16      | 2 sec       | 10.3 sec     | 12.3 sec                     |  12.6x      |
| 32      | 1 sec       | 6 sec        | 7 sec                        |  22.1x      |
| 64      | 0.6 sec     | 3.8 sec      | 4.4 sec                      |  35.2x      |


## References
If you are interested in learning how STARKs work under the hood, here are a few links to get you started. From the standpoint of this library, *arithmetization* is by far the most important concept to understand.

* STARKs whitepaper: [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
* STARKs vs. SNARKs: [A Cambrian Explosion of Crypto Proofs](https://nakamoto.com/cambrian-explosion-of-crypto-proofs/)

Vitalik Buterin's blog series on zk-STARKs:
* [STARKs, part 1: Proofs with Polynomials](https://vitalik.eth.limo/general/2017/11/09/starks_part_1.html)
* [STARKs, part 2: Thank Goodness it's FRI-day](https://vitalik.eth.limo/general/2017/11/22/starks_part_2.html)
* [STARKs, part 3: Into the Weeds](https://vitalik.eth.limo/general/2018/07/21/starks_part_3.html)

Alan Szepieniec's STARK tutorial:
* [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/)

StarkWare's STARK Math blog series:
* [STARK Math: The Journey Begins](https://medium.com/starkware/stark-math-the-journey-begins-51bd2b063c71)
* [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
* [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
* [Low Degree Testing](https://medium.com/starkware/low-degree-testing-f7614f5172db)
* [A Framework for Efficient STARKs](https://medium.com/starkware/a-framework-for-efficient-starks-19608ba06fbe)

License
-------

This project is [MIT licensed](./LICENSE).

Acknowledgements
-------

The original codebase was developed by Irakliy Khaburzaniya ([@irakliyk](https://github.com/irakliyk)) with contributions from François Garillot ([@huitseeker](https://github.com/huitseeker)), Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)), Konstantinos Chalkias ([@kchalkias](https://github.com/kchalkias)), and Jasleen Malvai ([@Jasleen1](https://github.com/Jasleen1)).
