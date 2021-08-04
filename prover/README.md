# STARK prover
This crate contains Winterfell STARK prover.

This prover can be used to generate proof of computational integrity using the STARK protocol. The prover supports multi-threaded proof generation (including multi-threaded execution trace generation) but is limited to a single machine.

To generate proofs using multiple threads, the crate must be compiled with `concurrent` feature enabled. The number of threads used during proof generation can be configured via `RAYON_NUM_THREADS` environment variable. The default number of threads is set to the number of logical cores on the machine.

## WebAssembly support
To compile this crate to WebAssembly, disable default features and enable the `alloc` feature.

## Usage
To generate a proof that a computation was executed correctly, you will need to do the following:

1. Define *algebraic intermediate representation* (AIR) for your computation. This can be done by implementing `Air` trait (see [air crate](../air) for more info).
2. Execute your computation and record its [execution trace](#Execution-trace).

Then, to generate the proof you can use `prover::prove()` function, which has the following signature:
```Rust
pub fn prove<AIR: Air>(
    trace: ExecutionTrace<AIR::BaseElement>,
    pub_inputs: AIR::PublicInputs,
    options: ProofOptions,
) -> Result<StarkProof, ProverError>
```
where:

* `AIR` is a type implementing `Air` trait for your computation.
* `trace` is the execution trace of the computation executed against some set of public inputs.
* `pub_inputs` is the set of public inputs against which the computation was executed. These inputs will need to be shared with the verifier in order for them to verify the proof.
* `options` defines basic properties for proof generation such as: number of queries, blowup factor, grinding factor, hash function to be used during proof generation etc.. These properties directly inform such metrics as proof generation time, proof size, and proof security level. See [air crate](../air) for more info.

The resulting `StarkProof` object can be serialized and sent to a [verifier](../verifier) for verification. The size of proof depends on the specifics of a given computation, but for most computations it should be in the range between 15 KB (for very small computations) and 300 KB (for very large computations).

Proof generation time is also highly dependent on the specifics of a given computation, but also depends on the capabilities of the machine used to generate the proofs (i.e. on number of CPU cores and memory bandwidth). For some high level benchmarks, see the [performance](..#Performance) section of the root README.

### Execution trace
Execution trace is a two-dimensional matrix in which each row represents the state of the computation at a single point in time and each column corresponds to an algebraic register tracked over all steps of the computation. A big part of defining AIR for a computation is coming up with an efficient way to represent the computation's execution trace. Check out the [examples crate](../examples) for more info.

In Winterfell, an execution trace can be represented using an `ExecutionTrace` struct. There are two ways to instantiate this struct.

First, you can use the `ExecutionTrace::init()` function which takes a set of vectors as a parameter, where each vector contains values for a given column of the trace. This approach allows you to build the execution trace as you see fit, as long as it meets basic execution trace requirements. These requirements are:

1. Lengths of all columns in the execution trace must be the same.
2. The length of the columns must be some power of two.

The other approach is to instantiate `ExecutionTrace` struct using `ExecutionTrace::new()` function, which takes trace width and length as parameters. This function will allocate memory for the trace, but will not fill it with data. To fill the execution trace, you can use the `fill()` method, which takes two closures as parameters:

1. The first closure is responsible for initializing the first state of the computation (the first row of the execution trace).
2. The second closure receives the previous state of the execution trace as input, and must update it to the next state of the computation.

This second option is usually simpler to use and also makes it easy to implement concurrent trace generation.

#### Concurrent trace generation
For computations which consist of many small independent computations, we can generate the execution trace of the entire computation by building fragments of the trace in parallel, and then joining these fragments together.

For this purpose, `ExecutionTrace` struct exposes `fragments()` method, which takes fragment length as a parameter and breaks the execution trace into equally sized fragments. You can then use fragment's `fill()` method to fill all fragments with data in parallel. The semantics of the fragment's `fill()` method are identical to the `fill()` method of the execution trace.

License
-------

This project is [MIT licensed](../LICENSE).