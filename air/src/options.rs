// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::cmp;

use fri::FriOptions;
use math::{FieldElement, StarkField, ToElements};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

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
/// 1. Finite field - proof soundness depends on the size of finite field used by the protocol. This
///    means, that for small fields (e.g. smaller than ~128 bits), field extensions must be used to
///    achieve adequate security. And even for ~128 bit fields, to achieve security over 100 bits, a
///    field extension may be required.
/// 2. Number of queries - higher values increase proof soundness, but also increase proof size.
/// 3. Blowup factor - higher values increase proof soundness, but also increase proof generation
///    time and proof size. However, higher blowup factors require fewer queries for the same
///    security level. Thus, it is frequently possible to increase blowup factor and at the same
///    time decrease the number of queries in such a way that the proofs become smaller.
/// 4. Grinding factor - higher values increase proof soundness, but also may increase proof
///    generation time. More precisely, conjectured proof soundness is bounded by `num_queries *
///    log2(blowup_factor) + grinding_factor`.
/// 5. Batching method for constraint composition polynomial - either independent random values per
///    constraint are used in the computation of the constraint composition polynomial or powers of
///    a single random value are used instead. The first type of batching is called `Linear` while
///    the second is called `Algebraic`.
/// 6. Batching method for DEEP polynomial - either independent random values per multi-point
///    quotient are used in the computation of the DEEP polynomial or powers of a single random
///    value are used instead.
///
/// Another important parameter in defining STARK security level, which is not a part of
/// [ProofOptions] is the hash function used in the protocol. The soundness of a STARK proof is
/// limited by the collision resistance of the hash function used by the protocol. For example, if a
/// hash function with 128-bit collision resistance is used, soundness of a STARK proof cannot
/// exceed 128 bits.
///
/// In addition, partition options (see [PartitionOptions]) can be provided to split traces during
/// proving and distribute work across multiple devices. Taking the main segment trace as an
/// example, the prover will split the main segment trace into `num_partitions` parts, and then
/// proceed to hash each part row-wise resulting in `num_partitions` digests per row of the trace.
/// Finally, `num_partitions` digests (per row) are combined into one digest (per row) and at this
/// point a vector commitment scheme can be called. In the case when `num_partitions` is equal to
/// `1` (default) the prover will hash each row in one go producing one digest per row of the trace.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofOptions {
    num_queries: u8,
    blowup_factor: u8,
    grinding_factor: u8,
    field_extension: FieldExtension,
    fri_folding_factor: u8,
    fri_remainder_max_degree: u8,
    batching_constraints: BatchingMethod,
    batching_deep: BatchingMethod,
    partition_options: PartitionOptions,
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
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: u32,
        field_extension: FieldExtension,
        fri_folding_factor: usize,
        fri_remainder_max_degree: usize,
        batching_constraints: BatchingMethod,
        batching_deep: BatchingMethod,
    ) -> ProofOptions {
        // TODO: return errors instead of panicking
        assert!(num_queries > 0, "number of queries must be greater than 0");
        assert!(num_queries <= MAX_NUM_QUERIES, "number of queries cannot be greater than 255");

        assert!(blowup_factor.is_power_of_two(), "blowup factor must be a power of 2");
        assert!(blowup_factor >= MIN_BLOWUP_FACTOR, "blowup factor cannot be smaller than 2");
        assert!(blowup_factor <= MAX_BLOWUP_FACTOR, "blowup factor cannot be greater than 128");

        assert!(
            grinding_factor <= MAX_GRINDING_FACTOR,
            "grinding factor cannot be greater than 32"
        );

        assert!(fri_folding_factor.is_power_of_two(), "FRI folding factor must be a power of 2");
        assert!(
            fri_folding_factor >= FRI_MIN_FOLDING_FACTOR,
            "FRI folding factor cannot be smaller than 2"
        );
        assert!(
            fri_folding_factor <= FRI_MAX_FOLDING_FACTOR,
            "FRI folding factor cannot be greater than 16"
        );

        assert!(
            (fri_remainder_max_degree + 1).is_power_of_two(),
            "FRI polynomial remainder degree must be one less than a power of two"
        );
        assert!(
            fri_remainder_max_degree <= FRI_MAX_REMAINDER_DEGREE,
            "FRI polynomial remainder degree cannot be greater than 255"
        );

        Self {
            num_queries: num_queries as u8,
            blowup_factor: blowup_factor as u8,
            grinding_factor: grinding_factor as u8,
            field_extension,
            fri_folding_factor: fri_folding_factor as u8,
            fri_remainder_max_degree: fri_remainder_max_degree as u8,
            partition_options: PartitionOptions::new(1, 1),
            batching_constraints,
            batching_deep,
        }
    }

    /// Updates the provided [ProofOptions] instance with the specified partition parameters.
    ///
    /// # Panics
    /// Panics if:
    /// - `num_partitions` is zero or greater than 16.
    /// - `hash_rate` is zero or greater than 256.
    pub const fn with_partitions(
        mut self,
        num_partitions: usize,
        hash_rate: usize,
    ) -> ProofOptions {
        self.partition_options = PartitionOptions::new(num_partitions, hash_rate);

        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of queries for a STARK proof.
    ///
    /// This directly impacts proof soundness as each additional query adds roughly
    /// `log2(blowup_factor)` bits of security to a proof. However, each additional query also
    /// increases proof size.
    pub const fn num_queries(&self) -> usize {
        self.num_queries as usize
    }

    /// Returns trace blowup factor for a STARK proof.
    ///
    /// This is the factor by which the execution trace is extended during low-degree extension. It
    /// has a direct impact on proof soundness as each query adds roughly `log2(blowup_factor)`
    /// bits of security to a proof. However, higher blowup factors also increases prover runtime,
    /// and may increase proof size.
    pub const fn blowup_factor(&self) -> usize {
        self.blowup_factor as usize
    }

    /// Returns query seed grinding factor for a STARK proof.
    ///
    /// Grinding applies Proof-of-Work to the query position seed. An honest prover needs to
    /// perform this work only once, while a dishonest prover will need to perform it every time
    /// they try to change a commitment. Thus, higher grinding factor makes it more difficult to
    /// forge a STARK proof. However, setting grinding factor too high (e.g. higher than 20) will
    /// adversely affect prover time.
    pub const fn grinding_factor(&self) -> u32 {
        self.grinding_factor as u32
    }

    /// Specifies whether composition polynomial should be constructed in an extension field
    /// of STARK protocol.
    ///
    /// Using a field extension increases maximum security level of a proof, but also has
    /// non-negligible impact on prover performance.
    pub const fn field_extension(&self) -> FieldExtension {
        self.field_extension
    }

    /// Returns the offset by which the low-degree extension domain is shifted in relation to the
    /// trace domain.
    ///
    /// Currently, this is hard-coded to the primitive element of the underlying base field.
    pub const fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    /// Returns options for FRI protocol instantiated with parameters from this proof options.
    pub fn to_fri_options(&self) -> FriOptions {
        let folding_factor = self.fri_folding_factor as usize;
        let remainder_max_degree = self.fri_remainder_max_degree as usize;
        FriOptions::new(self.blowup_factor(), folding_factor, remainder_max_degree)
    }

    /// Returns the `[PartitionOptions]` used in this instance of proof options.
    pub fn partition_options(&self) -> PartitionOptions {
        self.partition_options
    }

    /// Returns the `[BatchingMethod]` defining the method used for batching the constraints during
    /// the computation of the constraint composition polynomial.
    ///
    /// Linear batching implies that independently drawn random values per constraint will be used
    /// to do the batching, while Algebraic batching implies that powers of a single random value
    /// are used.
    ///
    /// Depending on other parameters, Algebraic batching may lead to a small reduction in the
    /// security level of the generated proofs, but avoids extra calls to the random oracle
    /// (i.e., hash function).
    pub fn constraint_batching_method(&self) -> BatchingMethod {
        self.batching_constraints
    }

    /// Returns the `[BatchingMethod]` defining the method used for batching the multi-point
    /// quotients defining the DEEP polynomial.
    ///
    /// Linear batching implies that independently drawn random values per multi-point quotient
    /// will be used to do the batching, while Algebraic batching implies that powers of a single
    /// random value are used.
    ///
    /// Depending on other parameters, Algebraic batching may lead to a small reduction in the
    /// security level of the generated proofs, but avoids extra calls to the random oracle
    /// (i.e., hash function).
    pub fn deep_poly_batching_method(&self) -> BatchingMethod {
        self.batching_deep
    }
}

impl<E: StarkField> ToElements<E> for ProofOptions {
    /// Encodes these proof options into 3 field elements.
    fn to_elements(&self) -> Vec<E> {
        // encode field extension, FRI parameters, and blowup factor into a single field element
        let mut buf = self.field_extension as u32;
        buf = (buf << 8) | self.fri_folding_factor as u32;
        buf = (buf << 8) | self.fri_remainder_max_degree as u32;
        buf = (buf << 8) | self.blowup_factor as u32;

        vec![E::from(buf), E::from(self.grinding_factor), E::from(self.num_queries)]
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
        target.write(self.batching_constraints);
        target.write(self.batching_deep);
        target.write_u8(self.partition_options.num_partitions);
        target.write_u8(self.partition_options.hash_rate);
    }
}

impl Deserializable for ProofOptions {
    /// Reads proof options from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid proof options could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let result = ProofOptions::new(
            source.read_u8()? as usize,
            source.read_u8()? as usize,
            source.read_u8()? as u32,
            FieldExtension::read_from(source)?,
            source.read_u8()? as usize,
            source.read_u8()? as usize,
            BatchingMethod::read_from(source)?,
            BatchingMethod::read_from(source)?,
        );
        Ok(result.with_partitions(source.read_u8()? as usize, source.read_u8()? as usize))
    }
}

// FIELD EXTENSION IMPLEMENTATION
// ================================================================================================

impl FieldExtension {
    /// Returns `true` if this field extension is set to `None`.
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns extension degree of this field extension.
    pub const fn degree(&self) -> u32 {
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

    /// Returns an estimate of how many bytes are needed to represent self.
    fn get_size_hint(&self) -> usize {
        1
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

// PARTITION OPTION IMPLEMENTATION
// ================================================================================================

/// Defines the parameters used to calculate partition size when committing to the traces
/// generated during the protocol.
///
/// Using multiple partitions will change how vector commitments are calculated:
/// - Input matrix columns are split into at most num_partitions partitions
/// - For each matrix row, a hash is calculated for each partition separately
/// - The results are merged together by one more hash iteration
///
/// This is especially useful when proving with multiple GPU cards where each device holds
/// a subset of data and allows less data reshuffling when generating commitments.
///
/// Hash_rate parameter is used to find the optimal partition size to minimize the number
/// of hash iterations. It specifies how many field elements are consumed by each hash iteration.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PartitionOptions {
    num_partitions: u8,
    hash_rate: u8,
}

impl PartitionOptions {
    /// Returns a new instance of `[PartitionOptions]`.
    pub const fn new(num_partitions: usize, hash_rate: usize) -> Self {
        assert!(num_partitions >= 1, "number of partitions must be greater than or equal to 1");
        assert!(num_partitions <= 16, "number of partitions must be smaller than or equal to 16");

        assert!(hash_rate >= 1, "hash rate must be greater than or equal to 1");
        assert!(hash_rate <= 256, "hash rate must be smaller than or equal to 256");

        Self {
            num_partitions: num_partitions as u8,
            hash_rate: hash_rate as u8,
        }
    }

    /// Returns the size of each partition used when committing to the main and auxiliary traces as
    /// well as the constraint evaluation trace.
    /// The returned size is given in terms of number of columns in the field `E`.
    pub fn partition_size<E: FieldElement>(&self, num_columns: usize) -> usize {
        if self.num_partitions == 1 {
            return num_columns;
        }

        // Don't separate columns that would fit inside one hash iteration. min_partition_size is
        // the number of `E` elements that can be consumed in one hash iteration.
        let min_partition_size = self.hash_rate as usize / E::EXTENSION_DEGREE;

        cmp::max(num_columns.div_ceil(self.num_partitions as usize), min_partition_size)
    }

    /// The actual number of partitions, after the min partition size implied
    /// by the hash rate is taken into account.
    pub fn num_partitions<E: FieldElement>(&self, num_columns: usize) -> usize {
        num_columns.div_ceil(self.partition_size::<E>(num_columns))
    }
}

impl Default for PartitionOptions {
    fn default() -> Self {
        Self { num_partitions: 1, hash_rate: 1 }
    }
}

// BATCHING METHOD
// ================================================================================================

/// Represents the type of batching, using randomness, used in the construction of either
/// the constraint composition polynomial or the DEEP composition polynomial.
///
/// There are currently two types of batching supported:
///
/// 1. Linear, also called affine, where the resulting expression is a multivariate polynomial of
///    total degree 1 in each of the random values.
/// 2. Algebraic, also called parametric or curve batching, where the resulting expression is a
///    univariate polynomial in one random value.
///
/// The main difference between the two types is that algebraic batching has low verifier randomness
/// complexity and hence is light on the number of calls to the random oracle. However, this comes
/// at the cost of an increase in the soundness error of the constraint batching step, i.e.,
/// ALI, on the order of log2(C - 1) where C is the number of constraints being batched and
/// an increase in the soundness error of the FRI batching step, on the order of log2(N - 1)
/// where N is the number of code words being batched. Linear batching does not suffer
/// from such a degradation but has linear verifier randomness complexity in the number of terms
/// being batched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BatchingMethod {
    Linear = 0,
    Algebraic = 1,
}

impl Serializable for BatchingMethod {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for BatchingMethod {
    /// Reads [BatchingMethod] from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error if the value does not correspond to a valid [BatchingMethod].
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ok(BatchingMethod::Linear),
            1 => Ok(BatchingMethod::Algebraic),
            n => Err(DeserializationError::InvalidValue(format!(
                "value {n} cannot be deserialized as a BatchingMethod enum"
            ))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use math::fields::{f64::BaseElement, CubeExtension};
    use utils::{Deserializable, Serializable};

    use super::{FieldExtension, PartitionOptions, ProofOptions, ToElements};
    use crate::options::BatchingMethod;

    #[test]
    fn proof_options_to_elements() {
        let field_extension = FieldExtension::None;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;

        let ext_fri = u32::from_le_bytes([
            blowup_factor as u8,
            fri_remainder_max_degree,
            fri_folding_factor,
            field_extension as u8,
        ]);
        let expected = vec![
            BaseElement::from(ext_fri),
            BaseElement::from(grinding_factor),
            BaseElement::from(num_queries as u32),
        ];

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        assert_eq!(expected, options.to_elements());
    }

    #[test]
    fn correct_partition_sizes() {
        type E1 = BaseElement;
        type E3 = CubeExtension<BaseElement>;

        let options = PartitionOptions::new(4, 8);
        let columns = 7;
        assert_eq!(8, options.partition_size::<E1>(columns));
        assert_eq!(1, options.num_partitions::<E1>(columns));

        let options = PartitionOptions::new(4, 8);
        let columns = 70;
        assert_eq!(18, options.partition_size::<E1>(columns));
        assert_eq!(4, options.num_partitions::<E1>(columns));

        let options = PartitionOptions::new(2, 8);
        let columns = 7;
        assert_eq!(4, options.partition_size::<E3>(columns));
        assert_eq!(2, options.num_partitions::<E3>(columns));

        let options: PartitionOptions = PartitionOptions::new(4, 8);
        let columns = 7;
        assert_eq!(2, options.partition_size::<E3>(columns));
        assert_eq!(4, options.num_partitions::<E3>(columns));

        // don't use all partitions if it would result in sizes smaller than
        // a single hash iteration can handle
        let options: PartitionOptions = PartitionOptions::new(4, 8);
        let columns = 3;
        assert_eq!(2, options.partition_size::<E3>(columns));
        assert_eq!(2, options.num_partitions::<E3>(columns));
    }

    #[test]
    fn serialization_proof_options() {
        let field_extension = FieldExtension::Quadratic;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );

        let options_serialized = options.to_bytes();
        let options_deserialized = ProofOptions::read_from_bytes(&options_serialized).unwrap();

        assert_eq!(options, options_deserialized)
    }
}
