# Examples
This crate contains examples illustrating how to use Winterfell library.

## Running examples
To run examples of generating and verifying proofs, do the following:

First, compile an optimized version of the `winterfell` binary by running:
```
cargo build --release
```
Or, if you want to compile with multi-threaded support enabled, run:
```
cargo build --release --manifest-path examples/Cargo.toml --features concurrent
```

In either case, the binary will be located in `target/release` directory, and you can run it like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] <SUBCOMMAND>
```
Where each example can be invoked using a distinct subcommand. To view the list of all available options and examples you can look up help like so:

```
./target/release/winterfell -h
```

Default parameters for each example target proof security of 100-bits. You can adjust them to see how each of the parameters affects proof generation time, proof size, and security level.

The most interesting file in each example is `air.rs`. It contains the encoding of each example's computation in AIR. At the high level, this consists of:

1. A `build_trace()` function which is responsible for generating an execution trace for the computation.
2. An implementation of `Air` trait which describes the constraints for the computation (see [air](../air) crate for more info).

Available examples are described below.

### Fibonacci sequence
There are several examples illustrating how to generate (and verify) proofs for computing an n-th term of the [Fibonacci sequence](https://en.wikipedia.org/wiki/Fibonacci_number). The examples illustrate different ways of describing this simple computation using AIR. The examples are:

* `fib` - computes the n-th term of a Fibonacci sequence using trace table with 2 columns. Each step in the trace table advances Fibonacci sequence by 2 terms.
* `fib8` - also computes the n-th term of a Fibonacci sequence and also uses trace table with 2 columns. But unlike the previous example, each step in the trace table advances Fibonacci sequence by 8 terms.
* `mulfib` - a variation on Fibonacci sequence where addition is replaced with multiplication. The example uses a trace table with 2 columns, and each step in the trace table advances the sequence by 2 terms.
* `mulfib8` - also computes the n-th term of the multiplicative Fibonacci sequence, but unlike the previous example, each step in the trace table advances the sequence by 8 terms. Unlike `fib8` example, this example uses a trace table with 8 columns.

It is interesting to note that `fib`/`fib8` and `mulfib`/`mulfib8` examples encode identical computations but these different encodings have significant impact on performance. Specifically, proving time for `fib8` example is 4x times faster than for `fib` example, while proving time for `mulfib8` example is about 2.4x times faster than for `mulfib` example. The difference stems from the fact that when we deal with additions only, we can omit intermediate states from the execution trace. But when multiplications are involved, we need to introduce additional columns to record intermediate results (another option would be to increase constraint degree, but this is not covered here).

Additionally, proof sizes for `fib8` and `mulfib8` are about 15% smaller than their "uncompressed" counterparts.

These improvements come at the expense of slightly more complex proof verification: constraint evaluation now involves 4 times more work for each of the "compressed" examples. But in case of Fibonacci sequences, this additional work is negligible and has no measurable impact on verifier performance.

You can run these examples like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] [fib|fib8|mulfib] [sequence length]
```
where:

* **sequence length** is the term of the Fibonacci sequence to compute. Currently, this must be a power of 2. The default is 1,048,576 (same as 2<sup>20</sup>).

For example, the following command will generate and verify a proof for computing a Fibonacci sequence up to 1024th term.
```
./target/release/winterfell fib -n 1024 
```

### Rescue hash chain
This example generates (and verifies) proofs for computing a hash chain of [Rescue hashes](https://eprint.iacr.org/2019/426). A hash chain is defined as follows:

*H(...H(H(seed))) = result*

where *H* is Rescue hash function.

You can run the example like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] rescue [chain length]
```
where:

* **chain length** is length of the hash chain (the number of times the hash function is invoked). Currently, this must be a power of 2. The default is 1024.

### Rescue RAPs hash chains
This example generates (and verifies) proofs for computing two parallel hash chains of [Rescue hashes](https://eprint.iacr.org/2019/426) absorbing a
sequence of inputs. The AIR program enforces that the sequence absorbed by the second hash chain is a permutation of the first one.

You can run the example like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] rescue-raps [chain length]
```
where:

* **chain length** is length of the hash chains (the number of times the hash function is invoked). Currently, this must be a power of 2 at least 4. The default is 1024.

### Merkle authentication path
This example generates (and verifies) proofs for verifying a Merkle authentication path. Specifically, given some Merkle tree known to both the prover and the verifier, the prover can prove that they know some value *v*, such that *hash(v)* is a valid tree leaf. This can be used to anonymously prove membership in a Merkle tree.

You can run the example like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] merkle [tree depth]
```
where:

* **tree depth** is the depth of the Merkle tree for which to verify a Merkle authentication path. Currently, the depth must be one less than a power of 2 (e.g. 3, 7, 15). Note that, in a single-threaded mode, a tree of depth 15 takes about 3 seconds to construct.

### LamportPlus signatures
These examples generate (and verify) proofs for aggregating many LamportPlus signatures. Currently, the examples illustrate two types of signature aggregation: multi-message, multi-key signatures and threshold signatures. The specific instantiation of LamportPlus we use has the following properties:

* Public key size: 32 bytes
* Signature size: 8 KB
* Hash function: Rescue-Prime
* Target security level: 123 bits (post-quantum)

You can run the examples like so:
```
./target/release/winterfell [FLAGS] [OPTIONS] lamport-a [num signatures]
./target/release/winterfell [FLAGS] [OPTIONS] lamport-t [num signers]
```
where:

* **num signatures** is the number of signatures (over distinct messages signed by different parties) to aggregate. Currently, number of signatures must be a power of 2.
* **num signers** is the total number of signers participating in the threshold signature scheme (the threshold is always assumed to be 2/3). Currently, the number of signers must be one less than a power of 2 (e.g. 3, 7, 15).

This example also illustrates how an execution trace can be built using multiple threads.

License
-------

This project is [MIT licensed](../LICENSE).
