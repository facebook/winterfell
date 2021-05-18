// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::io::Write;
use std::time::Instant;
use structopt::StructOpt;
use winterfell::{fibonacci, lamport, merkle, rescue, ExampleOptions, ExampleType};

// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    // read command-line args
    let options = ExampleOptions::from_args();

    debug!("============================================================");

    // instantiate and prepare the example
    let example = match options.example {
        ExampleType::Fib { sequence_length } => {
            fibonacci::fib2::get_example(options, sequence_length)
        }
        ExampleType::Fib8 { sequence_length } => {
            fibonacci::fib8::get_example(options, sequence_length)
        }
        ExampleType::Mulfib { sequence_length } => {
            fibonacci::mulfib2::get_example(options, sequence_length)
        }
        ExampleType::Mulfib8 { sequence_length } => {
            fibonacci::mulfib8::get_example(options, sequence_length)
        }
        ExampleType::Rescue { chain_length } => rescue::get_example(options, chain_length),
        ExampleType::Merkle { tree_depth } => merkle::get_example(options, tree_depth),
        ExampleType::LamportA { num_signatures } => {
            lamport::aggregate::get_example(options, num_signatures)
        }
        ExampleType::LamportT { num_signers } => {
            lamport::threshold::get_example(options, num_signers)
        }
    };

    // generate proof
    let now = Instant::now();
    let proof = example.prove();
    debug!(
        "---------------------\nProof generated in {} ms",
        now.elapsed().as_millis()
    );
    let proof_bytes = bincode::serialize(&proof).unwrap();
    debug!("Proof size: {:.1} KB", proof_bytes.len() as f64 / 1024f64);
    debug!("Proof security: {} bits", proof.security_level(true));

    // verify the proof
    debug!("---------------------");
    let proof = bincode::deserialize(&proof_bytes).expect("proof deserialization failed");
    let now = Instant::now();
    match example.verify(proof) {
        Ok(_) => debug!("Proof verified in {} ms", now.elapsed().as_millis()),
        Err(msg) => debug!("Failed to verify proof: {}", msg),
    }
    debug!("============================================================");
}
