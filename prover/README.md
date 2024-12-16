# Winterfell STARK prover
This crate contains Winterfell STARK prover.

This prover can be used to generate proof of computational integrity using the STARK protocol. The prover supports multi-threaded proof generation (including multi-threaded execution trace generation) but is limited to a single machine.

## Usage
To generate a proof that a computation was executed correctly, you will need to do the following:

1. Define *algebraic intermediate representation* (AIR) for your computation. This can be done by implementing `Air` trait (see [air crate](../air) for more info).
2. Define an [execution trace](#Execution-trace) for your computation. This can be done by implementing `Trace` trait. Alternatively, you can use `TraceTable` struct which already implements `Trace` trait in cases when this generic implementation works for your use case.
3. Execute your computation and record its execution trace.
4. Define your prover(#Prover) by implementing `Prover` trait. Then execute `Prover::prove()` function passing the trace generated in the previous step into it as a parameter. The function will return an instance of `Proof`.

The resulting `Proof` object can be serialized and sent to a [verifier](../verifier) for verification. The size of proof depends on the specifics of a given computation, but for most computations it should be in the range between 15 KB (for very small computations) and 300 KB (for very large computations).

Proof generation time is also highly dependent on the specifics of a given computation, but also depends on the capabilities of the machine used to generate the proofs (i.e. on number of CPU cores and memory bandwidth). For some high level benchmarks, see the [performance](..#Performance) section of the root README.

### Prover
To define a prover for a computation, you'll need implement the `Prover` trait. This trait specifies the computation's AIR (via the `Air` associated type) and the shape of its execution trace (via the `Trace` associated type). The trait also requires specifying several other associated types, but for most of these default implementations provided by Winterfell should be used. Besides these, a prover must provide implementations for three methods:

* `get_pub_inputs()`, which describes how a set of public inputs can be extracted from a given instance of an execution trace. These inputs will need to be shared with the verifier in order for them to verify the proof.
* `new_trace_lde()`, which constructs a new instance of trace low-degree extension. Unless your prover needs to implement specialized optimizations for performing low-degree extensions, this method can just return a default trace low-degree extension provided by Winterfell.
* `new_evaluator()`, which constructs a new instance of the AIR constraint evaluator. Unless your prover needs to implement specialized optimizations for evaluating constraints, this method can just return a default constraint evaluator provided by Winterfell.
* `build_constraint_commitment()`, which constructs a new instance of constraint commitment. Unless your prover needs to implement specialized optimizations for committing to constraints, this method can just return a default constraint commitment provided by Winterfell.
* `options()`, which defines STARK protocol parameters to be used during proof generation. These parameters include number of queries, blowup factor, grinding factor, hash function to be used during proof generation etc.. Values of these parameters directly inform such metrics as proof generation time, proof size, and proof security level. See [air crate](../air) for more info.

A prover exposes a `prove()` method which can be used to generate a STARK proof using a given execution trace as a witness.

### Execution trace
Execution trace is a two-dimensional matrix in which each row represents the state of the computation at a single point in time and each column corresponds to an algebraic register tracked over all steps of the computation. A big part of defining AIR for a computation is coming up with an efficient way to represent the computation's execution trace. Check out the [examples crate](../examples) for more info.

In Winterfell, an execution trace can be represented by any struct which implements the `Trace` trait. This trait defines a few property accessors (e.g., width and length) and defines a way of converting the struct into a vector of columns.

In most cases, defining a custom structure for an execution trace may be an overkill. Thus, Winterfell also provides a `TraceTable` struct which already implements the `Trace` trait. There are two ways to instantiate this struct.

First, you can use the `TraceTable::init()` function which takes a set of vectors as a parameter, where each vector contains values for a given column of the trace. This approach allows you to build the execution trace as you see fit, as long as it meets basic execution trace requirements. These requirements are:

1. Lengths of all columns in the execution trace must be the same.
2. The length of the columns must be some power of two.

The other approach is to instantiate `TraceTable` struct using `TraceTable::new()` function, which takes trace width and length as parameters. This function will allocate memory for the trace, but will not fill it with data. To fill the execution trace, you can use the `fill()` method, which takes two closures as parameters:

1. The first closure is responsible for initializing the first state of the computation (the first row of the execution trace).
2. The second closure receives the previous state of the execution trace as input, and must update it to the next state of the computation.

This second option is usually simpler to use and also makes it easy to implement concurrent trace generation.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also enables multi-threaded proof generation.
* `no_std` - does not rely on the Rust standard library and enables compilation to WebAssembly.
* `async` - converts all functions defined by the `Prover` trait into `async` functions.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation
When this crate is compiled with `concurrent` feature enabled, proof generation will be performed in multiple threads. The number of threads can be configured via `RAYON_NUM_THREADS` environment variable, and usually defaults to the number of logical cores on the machine.

For computations which consist of many small independent computations, we can generate the execution trace of the entire computation by building fragments of the trace in parallel, and then joining these fragments together.

For this purpose, `TraceTable` struct exposes `fragments()` method, which takes fragment length as a parameter, breaks the execution trace into equally sized fragments, and returns an iterator over these fragments. You can then use fragment's `fill()` method to fill all fragments with data in parallel. The semantics of the fragment's `fill()` method are identical to the `fill()` method of the execution trace.

License
-------

This project is [MIT licensed](../LICENSE).
