// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ProofSerializationError;
use crypto::{BatchMerkleProof, Hasher};
use math::{
    utils::{log2, read_elements_into_vec},
    FieldElement,
};
use utils::{ByteReader, ByteWriter, DeserializationError};

// FRI PROOF
// ================================================================================================

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FriProof {
    layers: Vec<FriProofLayer>,
    remainder: Vec<u8>,
    num_partitions: u8, // stored as power of 2
}

impl FriProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new FRI proof from the provided layers and remainder values.
    pub fn new<E: FieldElement>(
        layers: Vec<FriProofLayer>,
        remainder: Vec<E>,
        num_partitions: usize,
    ) -> Self {
        FriProof {
            layers,
            remainder: E::elements_as_bytes(&remainder).to_vec(),
            num_partitions: num_partitions.trailing_zeros() as u8,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of layers in this FRI proof.
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Returns the number of partitions used during proof generation.
    pub fn num_partitions(&self) -> usize {
        2usize.pow(self.num_partitions as u32)
    }

    // PARSING
    // --------------------------------------------------------------------------------------------

    /// Decomposes this proof into vectors of query values for each FRI layer and corresponding
    /// Merkle paths for each query (grouped into batch Merkle proofs)
    #[allow(clippy::type_complexity)]
    pub fn parse_layers<H: Hasher, E: FieldElement>(
        self,
        mut domain_size: usize,
        folding_factor: usize,
    ) -> Result<(Vec<Vec<E>>, Vec<BatchMerkleProof<H>>), ProofSerializationError> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            folding_factor.is_power_of_two(),
            "folding factor must be a power of two"
        );

        let mut layer_proofs = Vec::new();
        let mut layer_queries = Vec::new();

        // parse all layers
        for (i, layer) in self.layers.into_iter().enumerate() {
            domain_size /= folding_factor;
            let (qv, mp) = layer.parse::<H, E>(i, domain_size, folding_factor)?;
            layer_proofs.push(mp);
            layer_queries.push(qv);
        }

        // make sure the remaining domain size matches remainder length
        let num_remainder_elements = self.remainder.len() / E::ELEMENT_BYTES;
        if domain_size != num_remainder_elements {
            return Err(ProofSerializationError::InvalidRemainderDomain(
                num_remainder_elements,
                domain_size,
            ));
        }

        Ok((layer_queries, layer_proofs))
    }

    /// Returns a vector of remainder values (last FRI layer)
    pub fn parse_remainder<E: FieldElement>(&self) -> Result<Vec<E>, ProofSerializationError> {
        let remainder = read_elements_into_vec(&self.remainder)
            .map_err(|err| ProofSerializationError::RemainderParsingError(err.to_string()))?;
        Ok(remainder)
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes `self` and writes the resulting bytes into the `target` writer.
    pub fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write layers
        target.write_u8(self.layers.len() as u8);
        for layer in self.layers.iter() {
            layer.write_into(target);
        }

        // write remainder
        target.write_u8(self.remainder.len().trailing_zeros() as u8);
        target.write_u8_slice(&self.remainder);

        // write number of partitions
        target.write_u8(self.num_partitions);
    }

    /// Reads a FRI proof from the specified source starting at the specified position. Returns
    /// an error if a valid proof could not be read from the source.
    pub fn read_from<R: ByteReader>(
        source: &R,
        pos: &mut usize,
    ) -> Result<Self, DeserializationError> {
        // read layers
        let num_layers = source.read_u8(pos)? as usize;
        let mut layers = Vec::new();
        for _ in 0..num_layers {
            let layer = FriProofLayer::read_from(source, pos)?;
            layers.push(layer);
        }

        // read remainder
        let remainder_bytes = 2usize.pow(source.read_u8(pos)? as u32);
        let remainder = source.read_u8_vec(pos, remainder_bytes)?;

        // read number of partitions
        let num_partitions = source.read_u8(pos)?;

        Ok(FriProof {
            layers,
            remainder,
            num_partitions,
        })
    }
}

// FRI PROOF LAYER
// ================================================================================================

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FriProofLayer {
    values: Vec<u8>,
    paths: Vec<u8>,
}

impl FriProofLayer {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new proof layer from the specified query values and the corresponding Merkle
    /// paths aggregated into a single batch Merkle proof.
    pub fn new<H: Hasher, E: FieldElement, const N: usize>(
        query_values: Vec<[E; N]>,
        merkle_proof: BatchMerkleProof<H>,
    ) -> Self {
        assert!(!query_values.is_empty(), "query values cannot be empty");

        // TODO: add debug check that values actually hash into the leaf nodes of the batch proof

        // concatenate all query values together into a single vector of bytes
        let mut values = Vec::with_capacity(query_values.len() * N * E::ELEMENT_BYTES);
        for elements in query_values.iter() {
            values.extend_from_slice(E::elements_as_bytes(elements));
        }

        // concatenate all internal proof nodes together into a single vector of bytes; we care
        // about internal nodes only because leaf nodes can be reconstructed from hashes of query
        // values
        let paths = merkle_proof.serialize_nodes();

        FriProofLayer { values, paths }
    }

    // PARSING
    // --------------------------------------------------------------------------------------------

    /// Decomposes this layer into a combination of query values and corresponding Merkle
    /// paths (grouped together into a single batch Merkle proof).
    pub fn parse<H: Hasher, E: FieldElement>(
        self,
        layer_depth: usize,
        domain_size: usize,
        folding_factor: usize,
    ) -> Result<(Vec<E>, BatchMerkleProof<H>), ProofSerializationError> {
        // these will fail only if the struct was constructed incorrectly
        assert!(!self.values.is_empty(), "empty values vector");
        assert!(!self.paths.is_empty(), "empty paths vector");

        // make sure the number of value bytes can be parsed into a whole number of queries
        let num_query_bytes = E::ELEMENT_BYTES * folding_factor;
        if self.values.len() % num_query_bytes != 0 {
            return Err(ProofSerializationError::LayerParsingError(
                layer_depth,
                format!(
                    "number of value bytes ({}) does not divide into whole number of queries",
                    self.values.len()
                ),
            ));
        }

        let num_queries = self.values.len() / num_query_bytes;
        let mut hashed_queries = vec![H::Digest::default(); num_queries];
        let mut query_values = Vec::with_capacity(num_queries * folding_factor);

        // read bytes corresponding to each query, convert them into field elements,
        // and also hash them to build leaf nodes of the batch Merkle proof
        for (query_bytes, query_hash) in self
            .values
            .chunks(num_query_bytes)
            .zip(hashed_queries.iter_mut())
        {
            let mut qe = read_elements_into_vec::<E>(query_bytes).map_err(|err| {
                ProofSerializationError::LayerParsingError(layer_depth, err.to_string())
            })?;
            *query_hash = H::hash_elements(&qe);
            query_values.append(&mut qe);
        }

        // build batch Merkle proof
        let tree_depth = log2(domain_size) as u8;
        let merkle_proof = BatchMerkleProof::deserialize(&self.paths, hashed_queries, tree_depth)
            .map_err(|err| {
            ProofSerializationError::LayerParsingError(layer_depth, err.to_string())
        })?;

        Ok((query_values, merkle_proof))
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this proof layer and writes the resulting bytes to the specified `target`.
    pub fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write value bytes
        target.write_u32(self.values.len() as u32);
        target.write_u8_slice(&self.values);

        // write path bytes
        target.write_u32(self.paths.len() as u32);
        target.write_u8_slice(&self.paths);
    }

    /// Reads a single proof layer form the `source` starting at the specified position,
    /// and increments `pos` to point to a position right after the end of read-in layer bytes.
    /// Returns an error if a valid layer could not be read from the specified source.
    pub fn read_from<R: ByteReader>(
        source: &R,
        pos: &mut usize,
    ) -> Result<Self, DeserializationError> {
        // read values
        let num_value_bytes = source.read_u32(pos)?;
        let values = source.read_u8_vec(pos, num_value_bytes as usize)?;

        // read paths
        let num_paths_bytes = source.read_u32(pos)?;
        let paths = source.read_u8_vec(pos, num_paths_bytes as usize)?;

        Ok(FriProofLayer { values, paths })
    }
}
