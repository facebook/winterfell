// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::FriOptions;
use crypto::Hasher;
use math::{log2, FieldElement, StarkField};

/// Defines a set of properties for a specific execution of the FRI protocol.
///
/// These properties include:
/// * Finite field used in the protocol. This is specified via `B` and `E` type parameters.
///   In cases when FRI is run in the base filed of the STARK protocol, `B` and `E` parameters
///   will be equal. If FRI is run in an extension of the field used in the STARK protocol, `E`
///   will be an extension field with base equal to `B`.
/// * Hash function used by the prover to commit to polynomial evaluations. This is specified
///   via `H` type parameter.
/// * A set of parameters for the protocol such as `folding_factor` and `blowup_factor`
///   (specified via [FriOptions] parameter) as well as the number of partitions used during
///   proof generation (specified via `num_partitions` parameter).
/// * Maximum degree of a polynomial accepted by this instantiation of FRI (specified via
///   `max_poly_degree` parameter). In combination with `blowup_factor` parameter, this also
///   defines the domain over which the tested polynomial is evaluated.
/// * Information exchanged between the prover and the verifier during the commit phase of
///   the FRI protocol. This includes `layer_commitments` sent from the prover to the
///   verifier, and `layer_alphas` sent from the verifier to the prover.
pub struct VerifierContext<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: B,
    layer_commitments: Vec<H::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
}

impl<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> VerifierContext<B, E, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of verifier context created from the specified parameters.
    pub fn new(
        max_poly_degree: usize,
        layer_commitments: Vec<H::Digest>,
        layer_alphas: Vec<E>,
        num_partitions: usize,
        options: FriOptions,
    ) -> Self {
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = B::get_root_of_unity(log2(domain_size));
        VerifierContext {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum degree of a polynomial accepted by the FRI protocol with this context.
    pub fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    /// Returns size of the domain over which a polynomial tested by the FRI protocol with this
    /// context has been evaluated.
    ///
    /// The domain size can be computed by rounding `max_poly_degree` to the next power of two
    /// and multiplying the result by the `blowup_factor` from context options.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Returns returns the generator of the evaluation domain.
    ///
    /// The generator is the n-th root of unity, where n is equal to the evaluation domain size.
    pub fn domain_generator(&self) -> B {
        self.domain_generator
    }

    /// Returns layer commitments made by the prover during the commit phase of FRI protocol.
    pub fn layer_commitments(&self) -> &[H::Digest] {
        &self.layer_commitments
    }

    /// Returns a list of α values (one per FIR layer) sent to the prover by the verifier during
    /// the commit phase of FRI protocol.
    ///
    /// In the interactive version of the protocol, the verifier sends an α, randomly sampled from
    /// the entire field, to the prover after the prover commits to each FRI layer. The prover
    /// uses this α value to perform a degree-respecting projection and build the next FRI layer.
    pub fn layer_alphas(&self) -> &[E] {
        &self.layer_alphas
    }

    /// Returns number of partitions used during FRI proof generation.
    ///
    /// For non-distributed proof generation, number of partitions is usually set to 1.
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    // FRI OPTIONS PASS-THROUGH METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the offset by which the evaluation domain is shifted.
    ///
    /// The domain is shifted by multiplying every element in the domain by the offset value.
    pub fn domain_offset(&self) -> B {
        self.options.domain_offset()
    }

    /// Returns the factor by which the degree of a polynomial is reduced with each FRI layer.
    pub fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    /// Returns a blowup factor of the evaluation domain.
    ///
    /// Specifically, if the polynomial for which the FRI protocol is executed is of degree `d`
    /// where `d` is one less than a power of two, then the evaluation domain size will be
    /// equal to `(d + 1) * blowup_factor`.
    pub fn blowup_factor(&self) -> usize {
        self.options.blowup_factor()
    }

    /// Returns the number of FRI layers required for the domain specified by this context.
    ///
    /// The remainder layer (the last FRI layer) is not included in the returned value.
    ///
    /// The number of layers for a given domain size is defined by the `folding_factor` and
    /// `max_remainder_length` specified by the context options.
    pub fn num_fri_layers(&self) -> usize {
        self.options.num_fri_layers(self.domain_size)
    }

    /// Returns the size of the remainder layer (the last FRI layer) for a domain of specified
    /// by this context.
    ///
    /// The size of the remainder layer for a given domain size is defined by the `folding_factor`
    /// and `max_remainder_length` specified by the context options.
    pub fn fri_remainder_size(&self) -> usize {
        self.options.fri_remainder_size(self.domain_size)
    }
}
