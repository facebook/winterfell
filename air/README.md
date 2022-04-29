# Winter AIR
This crate contains components needed to describe arbitrary computations in a STARK-specific format.

## Arithmetization
Before we can generate proofs attesting that some computations were executed correctly, we need to reduce these computations to algebraic statements involving a set of bounded-degree polynomials. This step is usually called *arithmetization*. For basics of AIR arithmetization please refer to the excellent posts from StarkWare:

* [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
* [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
* [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)

Coming up with efficient arithmetizations for computations is highly non-trivial, and describing arithmetizations could be tedious and error-prone. `Air` trait aims to help with the latter, which, hopefully, also makes the former a little simpler.

To define AIR for a given computation, you'll need to implement the `Air` trait which involves the following:

1. Define base field for your computation via the `BaseField` associated type (see [math crate](../math) for available field options).
2. Define a set of public inputs which are required for your computation via the `PublicInputs` associated type.
3. Implement `Air::new()` function. As a part of this function you should create a `AirContext` struct which takes degrees for all transition constraints as one of the constructor parameters.
4. Implement `context()` method which should return a reference to the `AirContext` struct created in `Air::new()` function.
5. Implement `evaluate_transition()` method which should evaluate [transition constraints](#Transition-constraints) over a given evaluation frame.
6. Implement `get_assertions()` method which should return a vector of [assertions](#Trace-assertions) for a given instance of your computation.
7. If your computation requires [periodic values](#Periodic-values), you can also override the default `get_periodic_column_values()` method.

For more information, take a look at the definition at the [Air trait](src/air/mod.rs) and check out [examples crate](../examples) which illustrates how to implement the trait for a several different computations.

### Transition constraints
Transition constraints define algebraic relations between two consecutive steps of a computation. In Winterfell, transition constraints are evaluated inside `evaluate_transition()` function which takes the following parameters:

- **frame**: `&EvaluationFrame<FieldElement>`, which contains vectors with current and next states of the computation.
- **periodic_values**: `&[FieldElement]`, when periodic columns are defined for a computation, this will contain values of periodic columns at the current step of the computation. Otherwise, this will be an empty slice.
- **result**: `&mut [FieldElement]`, this is the slice where constraint evaluation results should be written to.

The constraints are considered to be satisfied if and only if, after the function returns, the `result` slice contains all zeros. In general, it is important for the transition constraint evaluation function to work as follows:

* For all valid transitions between consecutive computation steps, transition constraints should evaluation to all zeros.
* For any invalid transition, at least one constraint must evaluate to a non-zero value.

Keep in mind is that since transition constraints define algebraic relations, they should be described using only algebraic operations: additions, subtractions, and multiplications (divisions can be emulated using inverse of multiplication).

#### Constraint degrees
One of the main factors impacting proof generation time and proof size is the maximum degree of transition constraints. The higher is this degree, the larger our blowup factor needs to be. Usually, we want to keep this degree as low as possible - e.g. under 4 or 8. To accurately describe degrees of your transition constraints, keep the following in mind:

* All trace columns have degree `1`.
* When multiplying trace columns together, the degree increases by `1`. For example, if our constraint involves multiplication of two columns, the degree of this constraint will be `2`. We can describe this constraint using `TransitionConstraintDegree` struct as follows: `TransitionConstraintDegree::new(2)`.
* Degrees of periodic columns depend on the length of their cycles, but in most cases, these degrees are very close to `1`.
* To describe a degree of a constraint involving multiplication of trace columns and periodic columns, use the `with_cycles()` constructor of `TransitionConstraintDegree` struct. For example, if our constraint involves multiplication of one trace column and one periodic column with a cycle of 32 steps, the degree can be described as: `TransitionConstraintDegree::with_cycles(1, vec![32])`.

In general, multiplications should be used judiciously - though, there are ways to ease this restriction a bit (check out [mulfib8](../examples/src/fibonacci/mulfib8/air.rs) example).

### Trace assertions
Assertions are used to specify that a valid execution trace of a computation must contain certain values in certain cells. They are frequently used to tie public inputs to a specific execution trace, but can be used to constrain a computation in other ways as well. Internally within Winterfell, assertions are converted into *boundary constraints*.

To define assertions for your computation, you'll need to implement `get_assertions()` function of the `Air` trait. Every computation must have at least one assertion. Assertions can be of the following types:

* A single assertion - such assertion specifies that a single cell of an execution trace must be equal to a specific value. For example: *value in column 0, step 0, must be equal to 1*.
* A periodic assertion - such assertion specifies that values in a given column at specified intervals should be equal to some values. For example: *values in column 0, steps 0, 8, 16, 24 etc. must be equal to 2*.
* A sequence assertion - such assertion specifies that values in a given column at specific intervals must be equal to a sequence of provided values. For example: *values in column 0, step 0 must be equal to 1, step 8 must be equal to 2, step 16 must be equal to 3 etc.*

For more information on how to define assertions see the [assertions](src/air/assertions/mod.rs) module and check out the examples in the [examples crate](../examples).

### Periodic values
Sometimes, it may be useful to define a column in an execution trace which contains a set of repeating values. For example, let's say we have a column which contains value 1 on every 4th step, and 0 otherwise. Such a column can be described with a simple periodic sequence of `[1, 0, 0, 0]`.

To define such columns for your computation, you can override `get_periodic_column_values()` method of the `Air` trait. The values of the periodic columns at a given step of the computation will be supplied to the `evaluate_transition()` method via the `periodic_values` parameter.

### Randomized AIR
Randomized AIR is a powerful extension of AIR which enables, among other things, multiset and permutation checks similar to the ones available in PLONKish systems. These, in turn, allow efficient descriptions of "non-local" constraints which can be used to build such components as efficient range checks, random access memory, and many others.

With Randomized AIR, construction of the execution trace is split into multiple stages. During the first stage, the *main trace segment* is built in a manner similar to how the trace is built for regular AIR. In the subsequent stages, *auxiliary trace segments* are built. When building auxiliary trace segments, the prover has access to extra randomness sent by the verifier (in the non-interactive version of the protocol, this randomness is derived from the previous trace segment commitments). Currently, the number of auxiliary trace segments is limited to one.

To describe Randomized AIR, you will need to do the following when implementing the `Air` trait:
* The `AirContext` struct returned from `Air::context()` method must be instantiated using `AirContext::new_multi_segment()` constructor. When building AIR context in this way, you will need to provide a `TraceLayout` which describes the shape of a multi-segment execution trace.
* Override `Air::evaluate_aux_transition()` method. This method is similar to the `Air::evaluate_transition()` method but it also accepts two extra parameters: `aux_evaluation_frame` and `aux_rand_elements`. These parameters are needed for evaluating transition constraints over the auxiliary trace segments.
* Override `Air::get_aux_assertions()` method. This method is similar to the `Air::get_assertions()` method, but it should return assertions against columns of the auxiliary trace segments.

## Protocol parameters
`ProofOptions` struct defines a set of options which are used during STARK proof generation and verification. These options have a direct impact on the security of the generated proofs as well as the proof generation time. Specifically, security of STARK proofs depends on:

1. Hash function - proof security is limited by the collision resistance of the hash function used by the protocol. For example, if a hash function with 128-bit collision resistance is used, security of a STARK proof cannot exceed 128 bits.
2. Finite field - proof security is limited by the finite field used by the protocol. This means, that for small fields (e.g. smaller than ~128 bits), field extensions must be used to achieve adequate security. And even for ~128 bit fields, to achieve security over 100 bits, a field extension may be required.
3. Number of queries - higher values increase proof security, but also increase proof size.
4. Blowup factor - higher values increase proof security, but also increase proof generation time and proof size. However, higher blowup factors require fewer queries for the same security level. Thus, it is frequently possible to increase blowup factor and at the same time decrease the number of queries in such a way that the proofs become smaller.
5. Grinding factor - higher values increase proof security, but also may increase proof generation time.

See [options.rs](src/options.rs) for more info on currently available options and their meaning. Additionally, security level of a proof can be estimated using `StarkProof::security_level()` function.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` - does not rely on the Rust standard library and enables compilation to WebAssembly.

To compile with `no_std`, disable default features via `--no-default-features` flag.

License
-------

This project is [MIT licensed](../LICENSE).