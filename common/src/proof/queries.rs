// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::ProofSerializationError;
use crypto::{BatchMerkleProof, Hasher};
use math::{
    field::FieldElement,
    utils::{log2, read_elements_into_vec},
};
use utils::{ByteReader, DeserializationError};

// QUERIES
// ================================================================================================

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Queries {
    paths: Vec<u8>,
    values: Vec<u8>,
}

impl Queries {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a set of queries constructed from a batch Merkle proof and corresponding elements.
    pub fn new<H: Hasher, E: FieldElement>(
        merkle_proof: BatchMerkleProof<H>,
        query_values: Vec<Vec<E>>,
    ) -> Self {
        assert!(!query_values.is_empty(), "query values cannot be empty");
        let elements_per_query = query_values[0].len();
        assert_ne!(
            elements_per_query, 0,
            "a query must contain at least one value"
        );

        // TODO: add debug check that values actually hash into the leaf nodes of the batch proof

        // concatenate all elements together into a single vector of bytes
        let num_queries = query_values.len();
        let mut values = Vec::with_capacity(num_queries * elements_per_query * E::ELEMENT_BYTES);
        for elements in query_values.iter() {
            assert_eq!(
                elements.len(),
                elements_per_query,
                "all queries must contain the same number of values"
            );
            values.extend_from_slice(E::elements_as_bytes(elements));
        }

        // serialize internal nodes of the batch Merkle proof; we care about internal nodes only
        // because leaf nodes can be reconstructed from hashes of query values
        let paths = merkle_proof.serialize_nodes();

        Queries { paths, values }
    }

    // PARSER
    // --------------------------------------------------------------------------------------------
    /// Convert a set of queries into a batch Merkle proof and corresponding query values.
    pub fn parse<H: Hasher, E: FieldElement>(
        self,
        domain_size: usize,
        num_queries: usize,
        elements_per_query: usize,
    ) -> Result<(BatchMerkleProof<H>, Vec<Vec<E>>), ProofSerializationError> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(num_queries > 0, "there must be at least one query");
        assert!(
            elements_per_query > 0,
            "a query must contain at least one element"
        );

        // make sure we have enough bytes to read the expected number of queries
        let num_query_bytes = E::ELEMENT_BYTES * elements_per_query;
        let expected_bytes = num_queries * num_query_bytes;
        if self.values.len() != expected_bytes {
            return Err(ProofSerializationError::FailedToParseQueryValues(format!(
                "expected {} bytes, but was {}",
                expected_bytes,
                self.values.len()
            )));
        }

        let mut hashed_queries = vec![H::Digest::default(); num_queries];
        let mut query_values = Vec::with_capacity(num_queries);

        // read bytes corresponding to each query, convert them into field elements,
        // and also hash them to build leaf nodes of the batch Merkle proof
        for (query_bytes, query_hash) in self
            .values
            .chunks(num_query_bytes)
            .zip(hashed_queries.iter_mut())
        {
            let elements = read_elements_into_vec::<E>(query_bytes).map_err(|err| {
                ProofSerializationError::FailedToParseQueryValues(err.to_string())
            })?;
            *query_hash = H::hash_elements(&elements);
            query_values.push(elements);
        }

        // build batch Merkle proof
        let tree_depth = log2(domain_size) as u8;
        let merkle_proof = BatchMerkleProof::deserialize(&self.paths, hashed_queries, tree_depth)
            .map_err(|err| {
            ProofSerializationError::FailedToParseQueryProofs(err.to_string())
        })?;

        Ok((merkle_proof, query_values))
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this queries struct and appends the resulting bytes to the `target` vector.
    pub fn write_into(&self, target: &mut Vec<u8>) {
        // write value bytes
        target.extend_from_slice(&(self.values.len() as u32).to_le_bytes());
        target.extend_from_slice(&self.values);

        // write path bytes
        target.extend_from_slice(&(self.paths.len() as u32).to_le_bytes());
        target.extend_from_slice(&self.paths);
    }

    /// Reads a query struct from the specified source starting at the specified position and
    /// increments `pos` to point to a position right after the end of read-in query bytes.
    /// Returns an error of a valid query struct could not be read from the specified source.
    pub fn read_from(source: &[u8], pos: &mut usize) -> Result<Self, DeserializationError> {
        // read values
        let num_value_bytes = source.read_u32(pos)?;
        let values = source.read_u8_vec(pos, num_value_bytes as usize)?;

        // read paths
        let num_paths_bytes = source.read_u32(pos)?;
        let paths = source.read_u8_vec(pos, num_paths_bytes as usize)?;

        Ok(Queries { paths, values })
    }
}
