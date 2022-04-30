// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use fri::FriOptions;
use math::StarkField;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// TYPES AND INTERFACES
// ================================================================================================

/// Defines a set of available hash function for STARK protocol.
///
/// Choice of a hash function has a direct impact on proof generation time, proof size, and proof
/// soundness. In general, sounds of the proof is bounded by the collision resistance of the hash
/// function used by the protocol.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashFunction {
    /// BLAKE3 hash function with 192 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 96 bits.
    Blake3_192 = 1,

    /// BLAKE3 hash function with 256 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    Blake3_256 = 2,

    /// SHA3 hash function with 256 bit output.
    ///
    /// When this function is used in the STARK protocol, proof security cannot exceed 128 bits.
    Sha3_256 = 3,
}

/// Defines an extension field for the composition polynomial.
///
/// Choice of a field for a composition polynomial may impact proof soundness, and can also have
/// a non-negligible impact on proof generation time and proof size. Specifically, for small
/// fields, security offered by the base field itself may be inadequate or insufficient, and an
/// extension of the base field may need to be used.
///
/// For example, if the size of base field is ~64-bits, a quadratic extension must be use to
/// achieve ~100 bits of soundness, and a cubic extension must be used to achieve 128+ bits
/// of soundness.
///
/// However, increasing extension degree will increase proof generation time and proof size by
/// as much as 50%.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FieldExtension {
    /// Composition polynomial is constructed in the base field.
    None = 1,
    /// Composition polynomial is constructed in the quadratic extension of the base field.
    Quadratic = 2,
    /// Composition polynomial is constructed in the cubic extension of the base field.
    Cubic = 3,
}

/// STARK protocol parameters.
///
/// These parameters have a direct impact on proof soundness, proof generation time, and proof
/// size. Specifically:
///
/// 1. Hash function - proof soundness is limited by the collision resistance of the hash function
///    used by the protocol. For example, if a hash function with 128-bit collision resistance is
///    used, soundness of a STARK proof cannot exceed 128 bits.
/// 2. Finite field - proof soundness depends on the size of finite field used by the protocol.
///    This means, that for small fields (e.g. smaller than ~128 bits), field extensions must be
///    used to achieve adequate security. And even for ~128 bit fields, to achieve security over
///    100 bits, a field extension may be required.
/// 3. Number of queries - higher values increase proof soundness, but also increase proof size.
/// 4. Blowup factor - higher values increase proof soundness, but also increase proof generation
///    time and proof size. However, higher blowup factors require fewer queries for the same
///    security level. Thus, it is frequently possible to increase blowup factor and at the same
///    time decrease the number of queries in such a way that the proofs become smaller.
/// 5. Grinding factor - higher values increase proof soundness, but also may increase proof
///    generation time. More precisely, proof soundness is bounded by
///    `num_queries * log2(blowup_factor) + grinding_factor`.
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
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Smallest allowed blowup factor which is currently set to 2.
    ///
    /// The smallest allowed blowup factor for a given computation is derived from degrees of
    /// constraints defined for that computation and may be greater than 2. But no computation may
    /// have a blowup factor smaller than 2.
    pub const MIN_BLOWUP_FACTOR: usize = 2;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [ProofOptions] struct constructed from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// * `num_queries` is zero or greater than 128.
    /// * `blowup_factor` is smaller than 4, greater than 256, or is not a power of two.
    /// * `grinding_factor` is greater than 32.
    /// * `fri_folding_factor` is not 4, 8, or 16.
    /// * `fri_max_remainder_size` is smaller than 32, greater than 1024, or is not a power of two.
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
        assert!(blowup_factor >= Self::MIN_BLOWUP_FACTOR,
            "blowup factor cannot be smaller than {}", Self::MIN_BLOWUP_FACTOR);
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

    /// Returns number of queries for a STARK proof.
    ///
    /// This directly impacts proof soundness as each additional query adds roughly
    /// `log2(blowup_factor)` bits of security to a proof. However, each additional query also
    /// increases proof size.
    pub fn num_queries(&self) -> usize {
        self.num_queries as usize
    }

    /// Returns trace blowup factor for a STARK proof.
    ///
    /// This is the factor by which the execution trace is extended during low-degree extension. It
    /// has a direct impact on proof soundness as each query adds roughly `log2(blowup_factor)`
    /// bits of security to a proof. However, higher blowup factors also increases prover runtime,
    /// and may increase proof size.
    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor as usize
    }

    /// Returns query seed grinding factor for a STARK proof.
    ///
    /// Grinding applies Proof-of-Work/ to the query position seed. An honest prover needs to
    /// perform this work only once, while a dishonest prover will need to perform it every time
    /// they try to change a commitment. Thus, higher grinding factor makes it more difficult to
    /// forge a STARK proof. However, setting grinding factor too high (e.g. higher than 20) will
    /// adversely affect prover time.
    pub fn grinding_factor(&self) -> u32 {
        self.grinding_factor as u32
    }

    /// Returns a hash functions to be used during STARK proof construction.
    ///
    /// Security of a STARK proof is bounded by collision resistance of the hash function used
    /// during proof construction. For example, if collision resistance of a hash function is
    /// 128 bits, then soundness of a proof generated using this hash function cannot exceed
    /// 128 bits.
    pub fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Specifies whether composition polynomial should be constructed in an extension field
    /// of STARK protocol.
    ///
    /// Using a field extension increases maximum security level of a proof, but also has
    /// non-negligible impact on prover performance.
    pub fn field_extension(&self) -> FieldExtension {
        self.field_extension
    }

    /// Returns the offset by which the low-degree extension domain is shifted in relation to the
    /// trace domain.
    ///
    /// Currently, this is hard-coded to the primitive element of the underlying base field.
    pub fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    /// Returns options for FRI protocol instantiated with parameters from this proof options.
    pub fn to_fri_options(&self) -> FriOptions {
        let folding_factor = self.fri_folding_factor as usize;
        let max_remainder_size = 2usize.pow(self.fri_max_remainder_size as u32);
        FriOptions::new(self.blowup_factor(), folding_factor, max_remainder_size)
    }
}

impl Serializable for ProofOptions {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.num_queries);
        target.write_u8(self.blowup_factor);
        target.write_u8(self.grinding_factor);
        target.write(self.hash_fn);
        target.write(self.field_extension);
        target.write_u8(self.fri_folding_factor);
        target.write_u8(self.fri_max_remainder_size);
    }
}

impl Deserializable for ProofOptions {
    /// Reads proof options from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid proof options could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ProofOptions::new(
            source.read_u8()? as usize,
            source.read_u8()? as usize,
            source.read_u8()? as u32,
            HashFunction::read_from(source)?,
            FieldExtension::read_from(source)?,
            source.read_u8()? as usize,
            2usize.pow(source.read_u8()? as u32),
        ))
    }
}

// FIELD EXTENSION IMPLEMENTATION
// ================================================================================================

impl FieldExtension {
    /// Returns `true` if this field extension is set to `None`.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns extension degree of this field extension.
    pub fn degree(&self) -> u32 {
        match self {
            Self::None => 1,
            Self::Quadratic => 2,
            Self::Cubic => 3,
        }
    }
}

impl Serializable for FieldExtension {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for FieldExtension {
    /// Reads a field extension enum from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => Ok(FieldExtension::None),
            2 => Ok(FieldExtension::Quadratic),
            3 => Ok(FieldExtension::Cubic),
            value => Err(DeserializationError::InvalidValue(format!(
                "value {} cannot be deserialized as FieldExtension enum",
                value
            ))),
        }
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl HashFunction {
    /// Returns collision resistance of this hash function in bits.
    pub fn collision_resistance(&self) -> u32 {
        match self {
            Self::Blake3_192 => 96,
            Self::Blake3_256 => 128,
            Self::Sha3_256 => 128,
        }
    }
}

impl Serializable for HashFunction {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for HashFunction {
    /// Reads a hash function enum from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => Ok(HashFunction::Blake3_192),
            2 => Ok(HashFunction::Blake3_256),
            3 => Ok(HashFunction::Sha3_256),
            value => Err(DeserializationError::InvalidValue(format!(
                "value {} cannot be deserialized as HashFunction enum",
                value
            ))),
        }
    }
}
