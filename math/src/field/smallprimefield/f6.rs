// use super::{AsBytes, FieldElement, SmallPrimeFieldElement, StarkField, traits::SmallPrimeField};
// use crate::utils;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter},
    mem,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};

use utils::{
    collections::Vec,
    string::{String, ToString},
    AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable,
    Serializable,
};

use super::{
    super::{FieldElement, QuadExtensionA, StarkField},
    GenericPrimeFieldElement,
};

// CONSTANTS
// ================================================================================================

// Field modulus = 37
const M: u64 = 37;
// 36th root of unity
const G: GenericPrimeFieldElement = GenericPrimeFieldElement {
    value: 2u64,
    modulus: M,
};

// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = std::mem::size_of::<u64>();

// FIELD ELEMENT
// ================================================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SmallFieldElement37(GenericPrimeFieldElement);

impl SmallFieldElement37 {
    /// Creates a new field element from a u128 value. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed. This function can also be used
    /// to initialize constants.
    /// TODO: move into StarkField trait?
    pub const fn new(value: u64) -> Self {
        let val = if value < M { value } else { value - M };
        SmallFieldElement37(GenericPrimeFieldElement::new(val, M))
    }

    /// Returns field element converted to u64 representation.
    pub fn as_u64(&self) -> u64 {
        self.0.get_value()
    }

    // Returns a SmallFieldElement37 representation from a GenericPrimeFieldElement
    // Assumes that the modulus of elt is M!
    pub fn from_generic_prime_field_elt(elt: GenericPrimeFieldElement) -> Self {
        SmallFieldElement37::new(elt.get_value())
    }

    pub fn to_generic_prime_field_elt(elt: Self) -> GenericPrimeFieldElement {
        GenericPrimeFieldElement {
            value: elt.0.get_value(),
            modulus: M,
        }
    }

    #[allow(unused)]
    unsafe fn get_power_series(b: Self, n: usize) -> Vec<Self> {
        let mut result = utils::uninit_vector(n);
        result[0] = SmallFieldElement37::ONE;
        for i in 1..result.len() {
            result[i] = result[i - 1] * b;
        }
        result
    }
}

impl FieldElement for SmallFieldElement37 {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = Self(GenericPrimeFieldElement {
        value: 0u64,
        modulus: M,
    });
    const ONE: Self = Self(GenericPrimeFieldElement {
        value: 1u64,
        modulus: M,
    });

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    fn inv(self) -> Self {
        Self::from_generic_prime_field_elt(self.0.inv())
    }

    fn conjugate(&self) -> Self {
        Self::from_generic_prime_field_elt(self.0.conjugate())
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        let len = elements.len() * Self::ELEMENT_BYTES;
        let element_values: Vec<u64> = elements.iter().map(|x| x.0.get_value()).collect();
        let p = element_values.as_ptr();
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }

    unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError> {
        if bytes.len() % Self::ELEMENT_BYTES != 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "number of bytes ({}) does not divide into whole number of field elements",
                bytes.len(),
            )));
        }

        let p = bytes.as_ptr();
        let len = bytes.len() / Self::ELEMENT_BYTES;

        if (p as usize) % mem::align_of::<u128>() != 0 {
            return Err(DeserializationError::InvalidValue(
                "slice memory alignment is not valid for this field element type".to_string(),
            ));
        }

        Ok(slice::from_raw_parts(p as *const Self, len))
    }

    fn zeroed_vector(n: usize) -> Vec<Self> {
        // this uses a specialized vector initialization code which requests zero-filled memory
        // from the OS; unfortunately, this works only for built-in types and we can't use
        // Self::ZERO here as much less efficient initialization procedure will be invoked.
        // We also use u128 to make sure the memory is aligned correctly for our element size.
        debug_assert_eq!(Self::ELEMENT_BYTES, mem::size_of::<u128>());
        let result = vec![0u128; n];

        // translate a zero-filled vector of u128s into a vector of base field elements
        let mut v = core::mem::ManuallyDrop::new(result);
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    }

    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        elements
    }

    // fn rand() -> Self {
    //     let range = Uniform::from(RANGE);
    //     let mut g = thread_rng();
    //     SmallFieldElement37(g.sample(range))
    // }

    // fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
    //     Self::try_from(bytes).ok()
    // }

    // fn prng_vector(seed: [u8; 32], n: usize) -> Vec<Self> {
    //     let range = Uniform::from(RANGE);
    //     let g = StdRng::from_seed(seed);
    //     g.sample_iter(range).take(n).map(SmallFieldElement37::new).collect()
    // }
}

impl StarkField for SmallFieldElement37 {
    /// sage: MODULUS = 37
    /// sage: GF(MODULUS).is_prime_field()
    /// True
    /// sage: GF(MODULUS).order()
    /// 37
    type QuadExtension = QuadExtensionA<Self>;
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = 6;

    /// sage: GF(MODULUS).primitive_element()
    /// 3
    const GENERATOR: Self = SmallFieldElement37(GenericPrimeFieldElement {
        value: 2,
        modulus: M,
    });

    /// sage: is_odd((MODULUS - 1) / 2^40)
    /// True
    const TWO_ADICITY: u32 = 2;

    /// sage: k = (MODULUS - 1) / 2^40
    /// sage: GF(MODULUS).primitive_element()^k
    /// 23953097886125630542083529559205016746
    const TWO_ADIC_ROOT_OF_UNITY: Self = SmallFieldElement37(G);

    fn get_root_of_unity(n: u32) -> Self {
        super::traits::get_prime_field_root_of_unity(n, Self::MODULUS)
        // let small_field_size_64 = Self::MODULUS - 1;
        // let small_field_size: u32 = small_field_size_64.try_into().unwrap();
        // assert!(n != 0, "cannot get root of unity for n = 0");
        // assert!(
        //     n <= small_field_size,
        //     "order cannot exceed {}",
        //     small_field_size
        // );
        // assert!(
        //     small_field_size % n == 0,
        //     "Order invalid for field size {}",
        //     small_field_size
        // );
        // let power = small_field_size/n;
        // Self::exp(Self::GENERATOR, power.into())
    }

    fn get_modulus_le_bytes() -> Vec<u8> {
        Self::MODULUS.to_le_bytes().to_vec()
    }

    fn as_int(&self) -> Self::PositiveInteger {
        self.0.get_value()
    }

    // fn from_int(value: u64) -> Self {
    //     SmallFieldElement37::new(value)
    // }
}

impl Display for SmallFieldElement37 {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// OVERLOADED OPERATORS
// ================================================================================================

impl Add for SmallFieldElement37 {
    type Output = SmallFieldElement37;

    fn add(self, rhs: SmallFieldElement37) -> SmallFieldElement37 {
        Self::from_generic_prime_field_elt(self.0 + rhs.0)
    }
}

impl AddAssign for SmallFieldElement37 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for SmallFieldElement37 {
    type Output = SmallFieldElement37;

    fn sub(self, rhs: SmallFieldElement37) -> SmallFieldElement37 {
        Self::from_generic_prime_field_elt(self.0 - rhs.0)
    }
}

impl SubAssign for SmallFieldElement37 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for SmallFieldElement37 {
    type Output = SmallFieldElement37;

    fn mul(self, rhs: SmallFieldElement37) -> SmallFieldElement37 {
        Self::from_generic_prime_field_elt(self.0 * rhs.0)
    }
}

impl MulAssign for SmallFieldElement37 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for SmallFieldElement37 {
    type Output = SmallFieldElement37;

    fn div(self, rhs: SmallFieldElement37) -> SmallFieldElement37 {
        Self::from_generic_prime_field_elt(self.0 / rhs.0)
    }
}

impl DivAssign for SmallFieldElement37 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for SmallFieldElement37 {
    type Output = SmallFieldElement37;

    fn neg(self) -> SmallFieldElement37 {
        Self::from_generic_prime_field_elt(-self.0)
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for SmallFieldElement37 {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed.
    fn from(value: u128) -> Self {
        Self::new(value as u64)
    }
}

impl From<u64> for SmallFieldElement37 {
    /// Converts a 64-bit value into a field element.
    fn from(value: u64) -> Self {
        SmallFieldElement37::new(value as u64)
    }
}

impl From<u32> for SmallFieldElement37 {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        SmallFieldElement37::new(value as u64)
    }
}

impl From<u16> for SmallFieldElement37 {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        SmallFieldElement37::new(value as u64)
    }
}

impl From<u8> for SmallFieldElement37 {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        SmallFieldElement37::new(value as u64)
    }
}

impl From<[u8; 8]> for SmallFieldElement37 {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes
    /// are assumed to be in little-endian byte order. If the value is greater than or equal
    /// to the field modulus, modular reduction is silently preformed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        SmallFieldElement37::from(value)
    }
}

impl<'a> TryFrom<&'a [u8]> for SmallFieldElement37 {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value = bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| format!("{}", error))?;
        Ok(SmallFieldElement37::new(value))
    }
}

impl AsBytes for SmallFieldElement37 {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const u64 = &self.0.get_value();
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for SmallFieldElement37 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.0.get_value().to_le_bytes());
    }
}

impl Deserializable for SmallFieldElement37 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(SmallFieldElement37::new(value))
    }
}

impl Randomizable for SmallFieldElement37 {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

// impl AsBytes for [SmallFieldElement37] {
//     fn as_bytes(&self) -> &[u8] {
//         // TODO: take endianness into account
//         unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * ELEMENT_BYTES) }
//     }
// }

// impl AsBytes for [SmallFieldElement37; 4] {
//     fn as_bytes(&self) -> &[u8] {
//         // TODO: take endianness into account
//         unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * ELEMENT_BYTES) }
//     }
// }
