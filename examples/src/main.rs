// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Instant;
use structopt::StructOpt;
use tracing::info_span;
#[cfg(feature = "tracing-forest")]
use tracing_forest::ForestLayer;
#[cfg(not(feature = "tracing-forest"))]
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use winterfell::StarkProof;

use examples::{fibonacci, rescue, vdf, ExampleOptions, ExampleType};
#[cfg(feature = "std")]
use examples::{lamport, merkle, rescue_raps};

// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    if std::env::var("WINTER_LOG").is_err() {
        std::env::set_var("WINTER_LOG", "info");
    }
    let registry =
        tracing_subscriber::registry::Registry::default().with(EnvFilter::from_env("WINTER_LOG"));

    #[cfg(feature = "tracing-forest")]
    registry.with(ForestLayer::default()).init();

    #[cfg(not(feature = "tracing-forest"))]
    {
        let format = tracing_subscriber::fmt::layer()
            .with_level(false)
            .with_target(false)
            .with_thread_names(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .compact();

        registry.with(format).init();
    }

    // read command-line args
    let options = ExampleOptions::from_args();

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
    let proof = info_span!("generate_proof").in_scope(|| example.as_ref().prove());
    println!("---------------------\nProof generated in {} ms", now.elapsed().as_millis());

    let proof_bytes = proof.to_bytes();
    println!("Proof size: {:.1} KB", proof_bytes.len() as f64 / 1024f64);
    let conjectured_security_level = options.get_proof_security_level(&proof, true);

    #[cfg(feature = "std")]
    {
        let proven_security_level = options.get_proof_security_level(&proof, false);
        println!(
            "Proof security: {} bits ({} proven)",
            conjectured_security_level, proven_security_level,
        );
    }

    #[cfg(not(feature = "std"))]
    println!("Proof security: {} bits", conjectured_security_level);

    #[cfg(feature = "std")]
    println!("Proof hash: {}", hex::encode(blake3::hash(&proof_bytes).as_bytes()));

    // verify the proof
    println!("---------------------");
    let parsed_proof = StarkProof::from_bytes(&proof_bytes).unwrap();
    assert_eq!(proof, parsed_proof);
    let now = Instant::now();
    match example.verify(proof) {
        Ok(_) => println!("Proof verified in {:.1} ms", now.elapsed().as_micros() as f64 / 1000f64),
        Err(msg) => println!("Failed to verify proof: {}", msg),
    }
}
