// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use fri::FriOptions;
use math::field::StarkField;
use utils::{ByteReader, DeserializationError};

// TYPES AND INTERFACES
// ================================================================================================

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FieldExtension {
    None = 1,
    Quadratic = 2,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashFunction {
    Blake3_256 = 1,
    Sha3_256 = 2,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofOptions {
    num_queries: u8,
    blowup_factor: u8,
    grinding_factor: u8,
    hash_fn: HashFunction,
    field_extension: FieldExtension,
    fri_folding_factor: u8,
    fri_max_remainder_size: u8, // stored as power of 2
}

// PROOF OPTIONS IMPLEMENTATION
// ================================================================================================
impl ProofOptions {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns new ProofOptions struct constructed from the specified parameters, which must
    /// comply with the following:
    /// * num_queries must be an integer between 1 and 128;
    /// * blowup_factor must be an integer which is a power of two between 4 and 256;
    /// * grinding_factor must be an integer between 0 and 32;
    /// * hash_fn must a supported hash function (currently BLAKE3 or SHA3);
    /// * field_extension must be either None or Quadratic;
    /// * fri_folding_factor must be an integer which is a power of two between 4 and 16;
    /// * fri_max_remainder_size must be an integer which is a power of two between 32 and 1024;
    #[rustfmt::skip]
    pub fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: u32,
        hash_fn: HashFunction,
        field_extension: FieldExtension,
        fri_folding_factor: usize,
        fri_max_remainder_size: usize,
    ) -> ProofOptions {
        // TODO: return errors instead of panicking
        assert!(num_queries > 0, "number of queries must be greater than 0");
        assert!(num_queries <= 128, "number of queries cannot be greater than 128");

        assert!(blowup_factor.is_power_of_two(), "blowup factor must be a power of 2");
        assert!(blowup_factor >= 4, "blowup factor cannot be smaller than 4");
        assert!(blowup_factor <= 128, "blowup factor cannot be greater than 128");

        assert!(grinding_factor <= 32, "grinding factor cannot be greater than 32");

        assert!(fri_folding_factor.is_power_of_two(), "FRI folding factor must be a power of 2");
        assert!(fri_folding_factor >= 4, "FRI folding factor cannot be smaller than 4");
        assert!(fri_folding_factor <= 16, "FRI folding factor cannot be greater than 16");

        assert!(fri_max_remainder_size.is_power_of_two(), "FRI max remainder size must be a power of 2");
        assert!(fri_max_remainder_size >= 32, "FRI max remainder size cannot be smaller than 32");
        assert!(fri_max_remainder_size <= 1024, "FRI max remainder size cannot be greater than 1024");

        ProofOptions {
            num_queries: num_queries as u8,
            blowup_factor: blowup_factor as u8,
            grinding_factor: grinding_factor as u8,
            hash_fn,
            field_extension,
            fri_folding_factor: fri_folding_factor as u8,
            fri_max_remainder_size: fri_max_remainder_size.trailing_zeros() as u8,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of queries for a STARK proof. This directly impacts proof soundness as each
    /// additional query adds roughly log2(blowup_factor) bits of security to a proof. However,
    /// each additional query also increases proof size.
    pub fn num_queries(&self) -> usize {
        self.num_queries as usize
    }

    /// Returns trace blowup factor for a STARK proof (i.e. a factor by which the execution
    /// trace is extended). This directly impacts proof soundness as each query adds roughly
    /// log2(blowup_factor) bits of security to a proof. However, higher blowup factors also
    /// increases prover runtime.
    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor as usize
    }

    /// Returns query seed grinding factor for a STARK proof. Grinding applies Proof-of-Work
    /// to the query position seed. An honest prover needs to perform this work only once,
    /// while a dishonest prover will need to perform it every time they try to change a
    /// commitment. Thus, higher grinding factor makes it more difficult to forge a STARK
    /// proof. However, setting grinding factor too high (e.g. higher than 20) will adversely
    /// affect prover time.
    pub fn grinding_factor(&self) -> u32 {
        self.grinding_factor as u32
    }

    /// Returns a hash functions to be used during STARK proof construction. Security of a
    /// STARK proof is bounded by collision resistance of the used hash function.
    pub fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns a value indicating whether an extension field should be used for the composition
    /// polynomial. Using a field extension increases maximum security level of a proof, but
    /// also has non-negligible impact on prover performance.
    pub fn field_extension(&self) -> FieldExtension {
        self.field_extension
    }

    /// Returns the offset by which the low-degree extension domain is shifted in relation to the
    /// trace domain. Currently, this is hard-coded to the generator of the underlying base field.
    pub fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    /// Returns options for FRI protocol instantiated with parameters from this proof options.
    pub fn to_fri_options(&self) -> FriOptions {
        let folding_factor = self.fri_folding_factor as usize;
        let max_remainder_size = 2usize.pow(self.fri_max_remainder_size as u32);
        FriOptions::new(self.blowup_factor(), folding_factor, max_remainder_size)
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes these options and appends the resulting bytes to the `target` vector.
    pub fn write_into(&self, target: &mut Vec<u8>) {
        target.push(self.num_queries);
        target.push(self.blowup_factor);
        target.push(self.grinding_factor);
        target.push(self.hash_fn as u8);
        target.push(self.field_extension as u8);
        target.push(self.fri_folding_factor);
        target.push(self.fri_max_remainder_size);
    }

    /// Reads proof options from the specified source starting at the specified position and
    /// increments `pos` to point to a position right after the end of read-in option bytes.
    /// Returns an error of a valid proof options could not be read from the specified source.
    pub fn read_from(source: &[u8], pos: &mut usize) -> Result<Self, DeserializationError> {
        Ok(ProofOptions::new(
            source.read_u8(pos)? as usize,
            source.read_u8(pos)? as usize,
            source.read_u8(pos)? as u32,
            HashFunction::read_from(source, pos)?,
            FieldExtension::read_from(source, pos)?,
            source.read_u8(pos)? as usize,
            2usize.pow(source.read_u8(pos)? as u32),
        ))
    }
}

// FIELD EXTENSION IMPLEMENTATION
// ================================================================================================

impl FieldExtension {
    /// Returns `true` if this field extension is set to None.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns extension degree of this field extension.
    pub fn degree(&self) -> u32 {
        match self {
            Self::None => 1,
            Self::Quadratic => 2,
        }
    }

    /// Reads a field extension enum from the byte at the specified position and increments
    /// `pos` by one.
    pub fn read_from(source: &[u8], pos: &mut usize) -> Result<Self, DeserializationError> {
        match source.read_u8(pos)? {
            1 => Ok(FieldExtension::None),
            2 => Ok(FieldExtension::Quadratic),
            value => Err(DeserializationError::InvalidValue(
                value.to_string(),
                "FieldExtension".to_string(),
            )),
        }
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl HashFunction {
    /// Returns collision resistance of this hash function in bits.
    pub fn collision_resistance(&self) -> u32 {
        match self {
            Self::Blake3_256 => 128,
            Self::Sha3_256 => 128,
        }
    }

    /// Reads a hash function enum from the byte at the specified position and increments
    /// `pos` by one.
    pub fn read_from(source: &[u8], pos: &mut usize) -> Result<Self, DeserializationError> {
        match source.read_u8(pos)? {
            1 => Ok(HashFunction::Blake3_256),
            2 => Ok(HashFunction::Sha3_256),
            value => Err(DeserializationError::InvalidValue(
                value.to_string(),
                "HashFunction".to_string(),
            )),
        }
    }
}
