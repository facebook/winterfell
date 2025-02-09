// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::ops::Range;

use math::{fields::f64::BaseElement, FieldElement, StarkField};

use super::{super::mds::mds_f64_12x12::mds_multiply, exp_acc, Digest, ElementHasher, Hasher};

mod digest;
pub use digest::ElementDigest;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of rounds is set to 7 to target 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
const NUM_ROUNDS: usize = 7;

/// S-Box and Inverse S-Box powers;
/// computed using algorithm 6 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of [Hasher] trait for Rescue Prime hash function with 256-bit output.
///
/// The hash function is implemented according to the Rescue Prime
/// [specifications](https://eprint.iacr.org/2020/1143.pdf) with the following exception:
/// * We set the number of rounds to 7, which implies a 40% security margin instead of the 50%
///   margin used in the specifications (a 50% margin rounds up to 8 rounds). The primary motivation
///   for this is that having the number of rounds be one less than a power of two simplifies AIR
///   design for computations involving the hash function.
/// * When hashing a sequence of elements, we do not append Fp(1) followed by Fp(0) elements to the
///   end of the sequence as padding. Instead, we initialize the first capacity element to the
///   number of elements to be hashed, and pad the sequence with Fp(0) elements only. This ensures
///   consistency of hash outputs between different hashing methods (see section below). However, it
///   also means that our instantiation of Rescue Prime cannot be used in a stream mode as the
///   number of elements to be hashed must be known upfront.
/// * We use the first 4 elements of the state (rather than the last 4 elements of the state) for
///   capacity and the remaining 8 elements for rate. The output of the hash function comes from the
///   first four elements of the rate portion of the state (elements 4, 5, 6, and 7). This
///   effectively applies a fixed bit permutation before and after XLIX permutation. We assert
///   without proof that this does not affect security of the construction.
/// * Instead of using Vandermonde matrices as a standard way of generating an MDS matrix as
///   described in Rescue Prime paper, we use a methodology developed by Polygon Zero to find an MDS
///   matrix with coefficients which are small powers of two in frequency domain. This allows us to
///   dramatically reduce MDS matrix multiplication time. Using a different MDS matrix does not
///   affect security of the hash function as any MDS matrix satisfies Rescue Prime construction (as
///   described in section 4.2 of the paper).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * Number of rounds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rp64_256::hash_elements), [merge()](Rp64_256::merge), and
/// [merge_with_int()](Rp64_256::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rp64_256::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rp64_256::hash_elements) function.
///
/// However, [hash()](Rp64_256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rp64_256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rp64_256::hash_elements) function. The reason for
/// this difference is that [hash()](Rp64_256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rp64_256::hash_elements) function rather then hashing the serialized bytes
/// using [hash()](Rp64_256::hash) function.
pub struct Rp64_256();

impl Hasher for Rp64_256 {
    type Digest = ElementDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = BaseElement::new(num_elements as u64);

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut buf = [0_u8; 8];
        for chunk in bytes.chunks(7) {
            if i < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0_u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            state[RATE_RANGE.start + i] += BaseElement::new(u64::from_le_bytes(buf));
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the first capacity element to 8 (the number of elements to
        // be hashed).
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE_RANGE].copy_from_slice(Self::Digest::digests_as_elements(values));
        state[CAPACITY_RANGE.start] = BaseElement::new(RATE_WIDTH as u64);

        // apply the Rescue permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        Self::hash_elements(ElementDigest::digests_as_elements(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the rate portion of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element and
        //   set the first capacity element to 5 (the number of elements to be hashed).
        // - if the value doesn't fit into a single field element, split it into two field elements,
        //   copy them into rate elements 5 and 6, and set the first capacity element to 6.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
        state[INPUT2_RANGE.start] = BaseElement::new(value);
        if value < BaseElement::MODULUS {
            state[CAPACITY_RANGE.start] = BaseElement::new(DIGEST_SIZE as u64 + 1);
        } else {
            state[INPUT2_RANGE.start + 1] = BaseElement::new(value / BaseElement::MODULUS);
            state[CAPACITY_RANGE.start] = BaseElement::new(DIGEST_SIZE as u64 + 2);
        }

        // apply the Rescue permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Rp64_256 {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = BaseElement::new(elements.len() as u64);

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl Rp64_256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level with 40% security margin.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a Rescue Prime round.
    pub const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Inverse of the MDS matrix.
    pub const INV_MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = INV_MDS;

    /// Round constants added to the hasher state in the first half of the Rescue Prime round.
    pub const ARK1: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the Rescue Prime round.
    pub const ARK2: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = ARK2;

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation(state: &mut [BaseElement; STATE_WIDTH]) {
        // implementation is based on algorithm 3 from <https://eprint.iacr.org/2020/1143.pdf>
        // apply round function 7 times; this provides 128-bit security with 40% security margin
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
    pub fn apply_round(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK2[round]);
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    #[inline(always)]
    fn apply_mds(state: &mut [BaseElement; STATE_WIDTH]) {
        mds_multiply(state)
    }

    #[inline(always)]
    fn add_constants(state: &mut [BaseElement; STATE_WIDTH], ark: &[BaseElement; STATE_WIDTH]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    #[inline(always)]
    fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
        state[0] = state[0].exp7();
        state[1] = state[1].exp7();
        state[2] = state[2].exp7();
        state[3] = state[3].exp7();
        state[4] = state[4].exp7();
        state[5] = state[5].exp7();
        state[6] = state[6].exp7();
        state[7] = state[7].exp7();
        state[8] = state[8].exp7();
        state[9] = state[9].exp7();
        state[10] = state[10].exp7();
        state[11] = state[11].exp7();
    }

    #[inline(always)]
    fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
        // compute base^10540996611094048183 using 72 multiplications per array element
        // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

        // compute base^10
        let mut t1 = *state;
        t1.iter_mut().for_each(|t| *t = t.square());

        // compute base^100
        let mut t2 = t1;
        t2.iter_mut().for_each(|t| *t = t.square());

        // compute base^100100
        let t3 = exp_acc::<BaseElement, STATE_WIDTH, 3>(t2, t2);

        // compute base^100100100100
        let t4 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t3, t3);

        // compute base^100100100100100100100100
        let t5 = exp_acc::<BaseElement, STATE_WIDTH, 12>(t4, t4);

        // compute base^100100100100100100100100100100
        let t6 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t5, t3);

        // compute base^1001001001001001001001001001000100100100100100100100100100100
        let t7 = exp_acc::<BaseElement, STATE_WIDTH, 31>(t6, t6);

        // compute base^1001001001001001001001001001000110110110110110110110110110110111
        for (i, s) in state.iter_mut().enumerate() {
            let a = (t7[i].square() * t6[i]).square().square();
            let b = t1[i] * t2[i] * *s;
            *s = a * b;
        }
    }
}

// MDS
// ================================================================================================
/// Rescue MDS matrix
const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = [
    [
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
    ],
    [
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
    ],
    [
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
    ],
    [
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
    ],
    [
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
    ],
    [
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
    ],
    [
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
    ],
    [
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
    ],
    [
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
    ],
    [
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
        BaseElement::new(8),
    ],
    [
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
        BaseElement::new(23),
    ],
    [
        BaseElement::new(23),
        BaseElement::new(8),
        BaseElement::new(26),
        BaseElement::new(13),
        BaseElement::new(10),
        BaseElement::new(9),
        BaseElement::new(7),
        BaseElement::new(6),
        BaseElement::new(22),
        BaseElement::new(21),
        BaseElement::new(8),
        BaseElement::new(7),
    ],
];

/// Rescue Inverse MDS matrix
const INV_MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = [
    [
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
    ],
    [
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
    ],
    [
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
    ],
    [
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
    ],
    [
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
    ],
    [
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
    ],
    [
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
    ],
    [
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
    ],
    [
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
    ],
    [
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
    ],
    [
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
        BaseElement::new(13278298489594233127),
    ],
    [
        BaseElement::new(13278298489594233127),
        BaseElement::new(389999932707070822),
        BaseElement::new(9782021734907796003),
        BaseElement::new(4829905704463175582),
        BaseElement::new(7567822018949214430),
        BaseElement::new(14205019324568680367),
        BaseElement::new(15489674211196160593),
        BaseElement::new(17636013826542227504),
        BaseElement::new(16254215311946436093),
        BaseElement::new(3641486184877122796),
        BaseElement::new(11069068059762973582),
        BaseElement::new(14868391535953158196),
    ],
];

// ROUND CONSTANTS
// ================================================================================================

/// Rescue round constants;
/// computed using algorithm 5 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of Rescue round, and ARK2 contains constants for the second half of Rescue round.
const ARK1: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        BaseElement::new(13917550007135091859),
        BaseElement::new(16002276252647722320),
        BaseElement::new(4729924423368391595),
        BaseElement::new(10059693067827680263),
        BaseElement::new(9804807372516189948),
        BaseElement::new(15666751576116384237),
        BaseElement::new(10150587679474953119),
        BaseElement::new(13627942357577414247),
        BaseElement::new(2323786301545403792),
        BaseElement::new(615170742765998613),
        BaseElement::new(8870655212817778103),
        BaseElement::new(10534167191270683080),
    ],
    [
        BaseElement::new(14572151513649018290),
        BaseElement::new(9445470642301863087),
        BaseElement::new(6565801926598404534),
        BaseElement::new(12667566692985038975),
        BaseElement::new(7193782419267459720),
        BaseElement::new(11874811971940314298),
        BaseElement::new(17906868010477466257),
        BaseElement::new(1237247437760523561),
        BaseElement::new(6829882458376718831),
        BaseElement::new(2140011966759485221),
        BaseElement::new(1624379354686052121),
        BaseElement::new(50954653459374206),
    ],
    [
        BaseElement::new(16288075653722020941),
        BaseElement::new(13294924199301620952),
        BaseElement::new(13370596140726871456),
        BaseElement::new(611533288599636281),
        BaseElement::new(12865221627554828747),
        BaseElement::new(12269498015480242943),
        BaseElement::new(8230863118714645896),
        BaseElement::new(13466591048726906480),
        BaseElement::new(10176988631229240256),
        BaseElement::new(14951460136371189405),
        BaseElement::new(5882405912332577353),
        BaseElement::new(18125144098115032453),
    ],
    [
        BaseElement::new(6076976409066920174),
        BaseElement::new(7466617867456719866),
        BaseElement::new(5509452692963105675),
        BaseElement::new(14692460717212261752),
        BaseElement::new(12980373618703329746),
        BaseElement::new(1361187191725412610),
        BaseElement::new(6093955025012408881),
        BaseElement::new(5110883082899748359),
        BaseElement::new(8578179704817414083),
        BaseElement::new(9311749071195681469),
        BaseElement::new(16965242536774914613),
        BaseElement::new(5747454353875601040),
    ],
    [
        BaseElement::new(13684212076160345083),
        BaseElement::new(19445754899749561),
        BaseElement::new(16618768069125744845),
        BaseElement::new(278225951958825090),
        BaseElement::new(4997246680116830377),
        BaseElement::new(782614868534172852),
        BaseElement::new(16423767594935000044),
        BaseElement::new(9990984633405879434),
        BaseElement::new(16757120847103156641),
        BaseElement::new(2103861168279461168),
        BaseElement::new(16018697163142305052),
        BaseElement::new(6479823382130993799),
    ],
    [
        BaseElement::new(13957683526597936825),
        BaseElement::new(9702819874074407511),
        BaseElement::new(18357323897135139931),
        BaseElement::new(3029452444431245019),
        BaseElement::new(1809322684009991117),
        BaseElement::new(12459356450895788575),
        BaseElement::new(11985094908667810946),
        BaseElement::new(12868806590346066108),
        BaseElement::new(7872185587893926881),
        BaseElement::new(10694372443883124306),
        BaseElement::new(8644995046789277522),
        BaseElement::new(1422920069067375692),
    ],
    [
        BaseElement::new(17619517835351328008),
        BaseElement::new(6173683530634627901),
        BaseElement::new(15061027706054897896),
        BaseElement::new(4503753322633415655),
        BaseElement::new(11538516425871008333),
        BaseElement::new(12777459872202073891),
        BaseElement::new(17842814708228807409),
        BaseElement::new(13441695826912633916),
        BaseElement::new(5950710620243434509),
        BaseElement::new(17040450522225825296),
        BaseElement::new(8787650312632423701),
        BaseElement::new(7431110942091427450),
    ],
];

const ARK2: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        BaseElement::new(7989257206380839449),
        BaseElement::new(8639509123020237648),
        BaseElement::new(6488561830509603695),
        BaseElement::new(5519169995467998761),
        BaseElement::new(2972173318556248829),
        BaseElement::new(14899875358187389787),
        BaseElement::new(14160104549881494022),
        BaseElement::new(5969738169680657501),
        BaseElement::new(5116050734813646528),
        BaseElement::new(12120002089437618419),
        BaseElement::new(17404470791907152876),
        BaseElement::new(2718166276419445724),
    ],
    [
        BaseElement::new(2485377440770793394),
        BaseElement::new(14358936485713564605),
        BaseElement::new(3327012975585973824),
        BaseElement::new(6001912612374303716),
        BaseElement::new(17419159457659073951),
        BaseElement::new(11810720562576658327),
        BaseElement::new(14802512641816370470),
        BaseElement::new(751963320628219432),
        BaseElement::new(9410455736958787393),
        BaseElement::new(16405548341306967018),
        BaseElement::new(6867376949398252373),
        BaseElement::new(13982182448213113532),
    ],
    [
        BaseElement::new(10436926105997283389),
        BaseElement::new(13237521312283579132),
        BaseElement::new(668335841375552722),
        BaseElement::new(2385521647573044240),
        BaseElement::new(3874694023045931809),
        BaseElement::new(12952434030222726182),
        BaseElement::new(1972984540857058687),
        BaseElement::new(14000313505684510403),
        BaseElement::new(976377933822676506),
        BaseElement::new(8407002393718726702),
        BaseElement::new(338785660775650958),
        BaseElement::new(4208211193539481671),
    ],
    [
        BaseElement::new(2284392243703840734),
        BaseElement::new(4500504737691218932),
        BaseElement::new(3976085877224857941),
        BaseElement::new(2603294837319327956),
        BaseElement::new(5760259105023371034),
        BaseElement::new(2911579958858769248),
        BaseElement::new(18415938932239013434),
        BaseElement::new(7063156700464743997),
        BaseElement::new(16626114991069403630),
        BaseElement::new(163485390956217960),
        BaseElement::new(11596043559919659130),
        BaseElement::new(2976841507452846995),
    ],
    [
        BaseElement::new(15090073748392700862),
        BaseElement::new(3496786927732034743),
        BaseElement::new(8646735362535504000),
        BaseElement::new(2460088694130347125),
        BaseElement::new(3944675034557577794),
        BaseElement::new(14781700518249159275),
        BaseElement::new(2857749437648203959),
        BaseElement::new(8505429584078195973),
        BaseElement::new(18008150643764164736),
        BaseElement::new(720176627102578275),
        BaseElement::new(7038653538629322181),
        BaseElement::new(8849746187975356582),
    ],
    [
        BaseElement::new(17427790390280348710),
        BaseElement::new(1159544160012040055),
        BaseElement::new(17946663256456930598),
        BaseElement::new(6338793524502945410),
        BaseElement::new(17715539080731926288),
        BaseElement::new(4208940652334891422),
        BaseElement::new(12386490721239135719),
        BaseElement::new(10010817080957769535),
        BaseElement::new(5566101162185411405),
        BaseElement::new(12520146553271266365),
        BaseElement::new(4972547404153988943),
        BaseElement::new(5597076522138709717),
    ],
    [
        BaseElement::new(18338863478027005376),
        BaseElement::new(115128380230345639),
        BaseElement::new(4427489889653730058),
        BaseElement::new(10890727269603281956),
        BaseElement::new(7094492770210294530),
        BaseElement::new(7345573238864544283),
        BaseElement::new(6834103517673002336),
        BaseElement::new(14002814950696095900),
        BaseElement::new(15939230865809555943),
        BaseElement::new(12717309295554119359),
        BaseElement::new(4130723396860574906),
        BaseElement::new(7706153020203677238),
    ],
];
