// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use fri::FriOptions;
use math::{StarkField, ToElements};
use utils::{
    collections::Vec, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

// CONSTANTS
// ================================================================================================

// most of these constants are set so that values fit into a u8 integer.

const MAX_NUM_QUERIES: usize = 255;

const MIN_BLOWUP_FACTOR: usize = 2;
const MAX_BLOWUP_FACTOR: usize = 128;

const MAX_GRINDING_FACTOR: u32 = 32;

const FRI_MIN_FOLDING_FACTOR: usize = 2;
const FRI_MAX_FOLDING_FACTOR: usize = 16;
const FRI_MAX_REMAINDER_DEGREE: usize = 255;

// TYPES AND INTERFACES
// ================================================================================================

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
/// 1. Finite field - proof soundness depends on the size of finite field used by the protocol.
///    This means, that for small fields (e.g. smaller than ~128 bits), field extensions must be
///    used to achieve adequate security. And even for ~128 bit fields, to achieve security over
///    100 bits, a field extension may be required.
/// 2. Number of queries - higher values increase proof soundness, but also increase proof size.
/// 3. Blowup factor - higher values increase proof soundness, but also increase proof generation
///    time and proof size. However, higher blowup factors require fewer queries for the same
///    security level. Thus, it is frequently possible to increase blowup factor and at the same
///    time decrease the number of queries in such a way that the proofs become smaller.
/// 4. Grinding factor - higher values increase proof soundness, but also may increase proof
///    generation time. More precisely, conjectured proof soundness is bounded by
///    `num_queries * log2(blowup_factor) + grinding_factor`.
///
/// Another important parameter in defining STARK security level, which is not a part of [ProofOptions]
/// is the hash function used in the protocol. The soundness of a STARK proof is limited by the
/// collision resistance of the hash function used by the protocol. For example, if a hash function
/// with 128-bit collision resistance is used, soundness of a STARK proof cannot exceed 128 bits.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofOptions {
    num_queries: u8,
    blowup_factor: u8,
    grinding_factor: u8,
    field_extension: FieldExtension,
    fri_folding_factor: u8,
    fri_remainder_max_degree: u8,
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
    pub const MIN_BLOWUP_FACTOR: usize = MIN_BLOWUP_FACTOR;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [ProofOptions] struct constructed from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// - `num_queries` is zero or greater than 255.
    /// - `blowup_factor` is smaller than 2, greater than 128, or is not a power of two.
    /// - `grinding_factor` is greater than 32.
    /// - `fri_folding_factor` is not 2, 4, 8, or 16.
    /// - `fri_remainder_max_degree` is greater than 255 or is not a power of two minus 1.
    #[rustfmt::skip]
    pub fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: u32,
        field_extension: FieldExtension,
        fri_folding_factor: usize,
        fri_remainder_max_degree: usize,
    ) -> ProofOptions {
        // TODO: return errors instead of panicking
        assert!(num_queries > 0, "number of queries must be greater than 0");
        assert!(num_queries <= MAX_NUM_QUERIES, "number of queries cannot be greater than {MAX_NUM_QUERIES}");

        assert!(blowup_factor.is_power_of_two(), "blowup factor must be a power of 2");
        assert!(blowup_factor >= MIN_BLOWUP_FACTOR, "blowup factor cannot be smaller than {MIN_BLOWUP_FACTOR}");
        assert!(blowup_factor <= MAX_BLOWUP_FACTOR, "blowup factor cannot be greater than {MAX_BLOWUP_FACTOR}");

        assert!(grinding_factor <= MAX_GRINDING_FACTOR, "grinding factor cannot be greater than {MAX_GRINDING_FACTOR}");

        assert!(fri_folding_factor.is_power_of_two(), "FRI folding factor must be a power of 2");
        assert!(fri_folding_factor >= FRI_MIN_FOLDING_FACTOR, "FRI folding factor cannot be smaller than {FRI_MIN_FOLDING_FACTOR}");
        assert!(fri_folding_factor <= FRI_MAX_FOLDING_FACTOR, "FRI folding factor cannot be greater than {FRI_MAX_FOLDING_FACTOR}");

        assert!(
            (fri_remainder_max_degree + 1).is_power_of_two(),
            "FRI polynomial remainder degree must be one less than a power of two"
        );
        assert!(
            fri_remainder_max_degree <= FRI_MAX_REMAINDER_DEGREE,
            "FRI polynomial remainder degree cannot be greater than {FRI_MAX_REMAINDER_DEGREE}"
        );

        ProofOptions {
            num_queries: num_queries as u8,
            blowup_factor: blowup_factor as u8,
            grinding_factor: grinding_factor as u8,
            field_extension,
            fri_folding_factor: fri_folding_factor as u8,
            fri_remainder_max_degree: fri_remainder_max_degree as u8,
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
    /// Grinding applies Proof-of-Work to the query position seed. An honest prover needs to
    /// perform this work only once, while a dishonest prover will need to perform it every time
    /// they try to change a commitment. Thus, higher grinding factor makes it more difficult to
    /// forge a STARK proof. However, setting grinding factor too high (e.g. higher than 20) will
    /// adversely affect prover time.
    pub fn grinding_factor(&self) -> u32 {
        self.grinding_factor as u32
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
        let remainder_max_degree = self.fri_remainder_max_degree as usize;
        FriOptions::new(self.blowup_factor(), folding_factor, remainder_max_degree)
    }
}

impl<E: StarkField> ToElements<E> for ProofOptions {
    fn to_elements(&self) -> Vec<E> {
        // encode field extension and FRI parameters into a single field element
        let mut buf = self.field_extension as u32;
        buf = (buf << 8) | self.fri_folding_factor as u32;
        buf = (buf << 8) | self.fri_remainder_max_degree as u32;

        vec![
            E::from(buf),
            E::from(self.grinding_factor),
            E::from(self.blowup_factor),
            E::from(self.num_queries),
        ]
    }
}

impl Serializable for ProofOptions {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.num_queries);
        target.write_u8(self.blowup_factor);
        target.write_u8(self.grinding_factor);
        target.write(self.field_extension);
        target.write_u8(self.fri_folding_factor);
        target.write_u8(self.fri_remainder_max_degree);
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
            FieldExtension::read_from(source)?,
            source.read_u8()? as usize,
            source.read_u8()? as usize,
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
                "value {value} cannot be deserialized as FieldExtension enum"
            ))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{FieldExtension, ProofOptions, ToElements};
    use math::fields::f64::BaseElement;

    #[test]
    fn proof_options_to_elements() {
        let field_extension = FieldExtension::None;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;

        let ext_fri = u32::from_le_bytes([
            fri_remainder_max_degree,
            fri_folding_factor,
            field_extension as u8,
            0,
        ]);
        let expected = vec![
            BaseElement::from(ext_fri),
            BaseElement::from(grinding_factor as u32),
            BaseElement::from(blowup_factor as u32),
            BaseElement::from(num_queries as u32),
        ];

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
        );
        assert_eq!(expected, options.to_elements());
    }
}
