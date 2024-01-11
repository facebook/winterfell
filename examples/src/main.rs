// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Instant;
use structopt::StructOpt;
use tracing::{event, level_filters::LevelFilter, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use winterfell::StarkProof;

use examples::{fibonacci, rescue, vdf, ExampleOptions, ExampleType};
#[cfg(feature = "std")]
use examples::{lamport, merkle, rescue_raps};

// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    let format = tracing_subscriber::fmt::layer()
        .with_level(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .without_time()
        .with_filter(LevelFilter::DEBUG);

    tracing_subscriber::registry().with(format).init();

    // read command-line args
    let options = ExampleOptions::from_args();

    event!(Level::DEBUG, "============================================================");

    // instantiate and prepare the example
    let example = match options.example {
        ExampleType::Fib { sequence_length } => {
            fibonacci::fib2::get_example(&options, sequence_length)
        }
        ExampleType::Fib8 { sequence_length } => {
            fibonacci::fib8::get_example(&options, sequence_length)
        }
        ExampleType::Mulfib { sequence_length } => {
            fibonacci::mulfib2::get_example(&options, sequence_length)
        }
        ExampleType::Mulfib8 { sequence_length } => {
            fibonacci::mulfib8::get_example(&options, sequence_length)
        }
        ExampleType::FibSmall { sequence_length } => {
            fibonacci::fib_small::get_example(&options, sequence_length)
        }
        ExampleType::Vdf { num_steps } => vdf::regular::get_example(&options, num_steps),
        ExampleType::VdfExempt { num_steps } => vdf::exempt::get_example(&options, num_steps),
        ExampleType::Rescue { chain_length } => rescue::get_example(&options, chain_length),
        #[cfg(feature = "std")]
        ExampleType::RescueRaps { chain_length } => {
            rescue_raps::get_example(&options, chain_length)
        }
        #[cfg(feature = "std")]
        ExampleType::Merkle { tree_depth } => merkle::get_example(&options, tree_depth),
        #[cfg(feature = "std")]
        ExampleType::LamportA { num_signatures } => {
            lamport::aggregate::get_example(&options, num_signatures)
        }
        #[cfg(feature = "std")]
        ExampleType::LamportT { num_signers } => {
            lamport::threshold::get_example(&options, num_signers)
        }
    }
    .expect("The example failed to initialize.");

    // generate proof
    let now = Instant::now();
    let example = example.as_ref();
    let proof = example.prove();
    event!(
        Level::DEBUG,
        "---------------------\nProof generated in {} ms",
        now.elapsed().as_millis()
    );

    let proof_bytes = proof.to_bytes();
    event!(Level::DEBUG, "Proof size: {:.1} KB", proof_bytes.len() as f64 / 1024f64);
    let conjectured_security_level = options.get_proof_security_level(&proof, true);

    #[cfg(feature = "std")]
    {
        let proven_security_level = options.get_proof_security_level(&proof, false);
        event!(
            Level::DEBUG,
            "Proof security: {} bits ({} proven)",
            conjectured_security_level,
            proven_security_level,
        );
    }

    #[cfg(not(feature = "std"))]
    event!(Level::DEBUG, "Proof security: {} bits", conjectured_security_level);

    #[cfg(feature = "std")]
    event!(
        Level::DEBUG,
        "Proof hash: {}",
        hex::encode(blake3::hash(&proof_bytes).as_bytes())
    );

    // verify the proof
    event!(Level::DEBUG, "---------------------");
    let parsed_proof = StarkProof::from_bytes(&proof_bytes).unwrap();
    assert_eq!(proof, parsed_proof);
    let now = Instant::now();
    match example.verify(proof) {
        Ok(_) => event!(
            Level::DEBUG,
            "Proof verified in {:.1} ms",
            now.elapsed().as_micros() as f64 / 1000f64
        ),
        Err(msg) => event!(Level::DEBUG, "Failed to verify proof: {}", msg),
    }
    event!(Level::DEBUG, "============================================================");
}
