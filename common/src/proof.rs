// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{FieldExtension, ProofOptions};
use crypto::{BatchMerkleProof, Hasher};
use fri::FriProof;
use math::{
    errors::SerializationError,
    field::FieldElement,
    utils::{log2, read_elements_into_vec},
};
use serde::{Deserialize, Serialize};

// CONSTANTS
// ================================================================================================

const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;

// TYPES AND INTERFACES
// ================================================================================================

// TODO: custom serialization should reduce size by 5% - 10%
#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    pub context: Context,
    pub commitments: Commitments,
    pub trace_queries: Queries,
    pub constraint_queries: Queries,
    pub ood_frame: OodEvaluationFrame,
    pub fri_proof: FriProof,
    pub pow_nonce: u64,
}

// TODO: this should be replaced by ProofContext
#[derive(Clone, Serialize, Deserialize)]
pub struct Context {
    pub lde_domain_depth: u8,
    pub ce_blowup_factor: u8,
    pub field_modulus_bytes: Vec<u8>,
    pub options: ProofOptions,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Commitments {
    pub trace_root: [u8; 32],
    pub constraint_root: [u8; 32],
    pub fri_roots: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Queries {
    pub paths: Vec<u8>,
    pub values: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OodEvaluationFrame {
    pub trace_at_z1: Vec<u8>,
    pub trace_at_z2: Vec<u8>,
}

// STARK PROOF IMPLEMENTATION
// ================================================================================================
impl StarkProof {
    /// Returns proof options which were used to generate this proof.
    pub fn options(&self) -> &ProofOptions {
        &self.context.options
    }

    /// Returns trace length for the computation described by this proof.
    pub fn trace_length(&self) -> usize {
        2usize.pow(self.context.lde_domain_depth as u32) / self.context.options.blowup_factor()
    }

    pub fn security_level(&self, optimistic: bool) -> u32 {
        let options = &self.context.options;

        // conjectured security requires half the queries as compared to proven security
        let num_queries = if optimistic {
            options.num_queries()
        } else {
            options.num_queries() / 2
        };

        let one_over_rho =
            (options.blowup_factor() / self.context.ce_blowup_factor as usize) as u32;
        let security_per_query = 31 - one_over_rho.leading_zeros(); // same as log2(one_over_rho)
        let mut result = security_per_query * num_queries as u32;

        // include grinding factor contributions only for proofs adequate security
        if result >= GRINDING_CONTRIBUTION_FLOOR {
            result += options.grinding_factor();
        }

        // Provided by the collision resistance (CR) of the hash function we use
        // TODO: make this dynamic based on the hash function used
        let cr_security = 128;

        // determine number of bits in the field modulus
        let field_modulus_bits = get_num_modulus_bits(&self.context.field_modulus_bytes);

        // field_modulus_bits * field_extension_factor - log2(extended trace length)
        let field_extension_factor = match options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
        };
        let max_fri_security =
            field_modulus_bits * field_extension_factor - self.context.lde_domain_depth as u32;

        std::cmp::min(std::cmp::min(result, max_fri_security), cr_security)
    }
}

// QUERY PROOFS IMPLEMENTATION
// ================================================================================================

impl Queries {
    /// Returns a set of queries constructed from a batch Merkle proof and corresponding elements.
    pub fn new<E: FieldElement>(merkle_proof: BatchMerkleProof, query_values: Vec<Vec<E>>) -> Self {
        assert!(!query_values.is_empty(), "query values cannot be empty");
        let elements_per_query = query_values[0].len();
        assert!(
            elements_per_query != 0,
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

    /// Convert a set of queries into a batch Merkle proof and corresponding query values.
    pub fn deserialize<H: Hasher, E: FieldElement>(
        self,
        domain_size: usize,
        elements_per_query: usize,
    ) -> Result<(BatchMerkleProof, Vec<Vec<E>>), SerializationError> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            elements_per_query >= 1,
            "a query must contain at least one element"
        );
        let hash_fn = H::hash_fn();

        // make sure we have enough bytes to read the expected number of queries
        let num_query_bytes = E::ELEMENT_BYTES * elements_per_query;
        // TODO: pass num_queries as a parameter into this function and change the check to be
        // num_queries * num_query_bytes == self.values.len()
        let num_queries = self.values.len() / num_query_bytes;
        if self.values.len() % num_query_bytes != 0 {
            let expected_bytes = (num_queries + 1) * num_query_bytes;
            return Err(SerializationError::WrongNumberOfBytes(
                expected_bytes,
                self.values.len(),
            ));
        }

        let mut hashed_queries = vec![[0u8; 32]; num_queries];
        let mut query_values = Vec::with_capacity(num_queries);

        // read bytes corresponding to each query, convert them into field elements,
        // and also hash them to build leaf nodes of the batch Merkle proof
        for (query_bytes, query_hash) in self
            .values
            .chunks(num_query_bytes)
            .zip(hashed_queries.iter_mut())
        {
            hash_fn(query_bytes, query_hash);
            let elements = read_elements_into_vec::<E>(query_bytes)?;
            query_values.push(elements);
        }

        // build batch Merkle proof
        let tree_depth = log2(domain_size) as u8;
        let merkle_proof = BatchMerkleProof::deserialize(&self.paths, hashed_queries, tree_depth);

        Ok((merkle_proof, query_values))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns number of bits in the provided modulus; the modulus is assumed to be encoded in
/// little-endian byte order
fn get_num_modulus_bits(modulus_bytes: &[u8]) -> u32 {
    let mut num_bits = modulus_bytes.len() as u32 * 8;
    for &byte in modulus_bytes.iter().rev() {
        if byte != 0 {
            num_bits -= byte.leading_zeros();
            return num_bits;
        }
        num_bits -= 8;
    }

    0
}
