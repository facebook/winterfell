// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use crypto::{ElementHasher, Hasher, VectorCommitment};
use math::FieldElement;
use utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};

use super::Table;

// QUERIES
// ================================================================================================
/// Decommitments to evaluations of a set of functions at multiple points.
///
/// Given a set of functions evaluated over a domain *D*, a commitment is assumed to be a vector
/// commitment where the *i*-th vector entry contains evaluations of all functions at
/// *x<sub>i</sub>*. Thus, a query (i.e. a single decommitment) for position *i* includes
/// evaluations of all functions at *x<sub>i</sub>*, accompanied by an opening proof of leaf *i*
/// against the vector commitment string.
///
/// This struct can contain one or more queries. In cases when more than one query is stored,
/// a batch opening proof is used in order to compress the individual opening proofs.
///
/// Internally, all opening proofs and query values are stored as a sequence of bytes. Thus, to
/// retrieve query values and their corresponding opening proofs, [parse()](Queries::parse)
/// function should be used.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Queries {
    opening_proof: Vec<u8>,
    values: Vec<u8>,
}

impl Queries {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns queries constructed from evaluations of a set of functions at some number of points
    /// in a domain and their corresponding batch opening proof.
    ///
    /// For each evaluation point, the same number of values must be provided.
    ///
    /// # Panics
    /// Panics if:
    /// * No queries were provided (`query_values` is an empty vector).
    /// * Any of the queries does not contain any evaluations.
    /// * Not all queries contain the same number of evaluations.
    pub fn new<H: Hasher, E: FieldElement, V: VectorCommitment<H>>(
        opening_proof: V::MultiProof,
        query_values: Vec<Vec<E>>,
    ) -> Self {
        assert!(!query_values.is_empty(), "query values cannot be empty");
        let elements_per_query = query_values[0].len();
        assert_ne!(elements_per_query, 0, "a query must contain at least one evaluation");

        // concatenate all elements together into a single vector of bytes
        let num_queries = query_values.len();
        let mut values = Vec::with_capacity(num_queries * elements_per_query * E::ELEMENT_BYTES);
        for elements in query_values.iter() {
            assert_eq!(
                elements.len(),
                elements_per_query,
                "all queries must contain the same number of evaluations"
            );
            values.write_many(elements);
        }
        let opening_proof = opening_proof.to_bytes();

        Queries { opening_proof, values }
    }

    // PARSER
    // --------------------------------------------------------------------------------------------
    /// Convert internally stored bytes into a set of query values and the corresponding batch
    /// opening proof.
    ///
    /// # Panics
    /// Panics if:
    /// * `domain_size` is not a power of two.
    /// * `num_queries` is zero.
    /// * `values_per_query` is zero.
    pub fn parse<E, H, V>(
        self,
        domain_size: usize,
        num_queries: usize,
        values_per_query: usize,
    ) -> Result<(V::MultiProof, Table<E>), DeserializationError>
    where
        E: FieldElement,
        H: ElementHasher<BaseField = E::BaseField>,
        V: VectorCommitment<H>,
    {
        assert!(domain_size.is_power_of_two(), "domain size must be a power of two");
        assert!(num_queries > 0, "there must be at least one query");
        assert!(values_per_query > 0, "a query must contain at least one value");

        // make sure we have enough bytes to read the expected number of queries
        let num_query_bytes = E::ELEMENT_BYTES * values_per_query;
        let expected_bytes = num_queries * num_query_bytes;
        if self.values.len() != expected_bytes {
            return Err(DeserializationError::InvalidValue(format!(
                "expected {} query value bytes, but was {}",
                expected_bytes,
                self.values.len()
            )));
        }

        // read bytes corresponding to each query and convert them into field elements.
        let query_values = Table::<E>::from_bytes(&self.values, num_queries, values_per_query)?;

        // build batch opening proof
        let mut reader = SliceReader::new(&self.opening_proof);
        let opening_proof = <V::MultiProof as Deserializable>::read_from(&mut reader)?;

        // check that the opening proof matches the domain length
        if <V as VectorCommitment<H>>::get_multiproof_domain_len(&opening_proof) != domain_size {
            return Err(DeserializationError::InvalidValue(format!(
                "expected a domain of size {} but was {}",
                domain_size,
                <V as VectorCommitment<H>>::get_multiproof_domain_len(&opening_proof),
            )));
        }

        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        Ok((opening_proof, query_values))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Queries {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write value bytes
        self.values.write_into(target);

        // write path bytes
        self.opening_proof.write_into(target);
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    fn get_size_hint(&self) -> usize {
        self.opening_proof.len() + self.values.len() + 8
    }
}

impl Deserializable for Queries {
    /// Reads a query struct from the specified `source` and returns the result
    ///
    /// # Errors
    /// Returns an error of a valid query struct could not be read from the specified source.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read values
        let values = Vec::<_>::read_from(source)?;

        // read paths
        let paths = Vec::<_>::read_from(source)?;

        Ok(Queries { opening_proof: paths, values })
    }
}
