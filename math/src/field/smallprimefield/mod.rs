// use crate::utils;

use core::fmt::Debug;

pub mod traits;

pub mod f6;

pub mod generic_prime_field_elt;
use generic_prime_field_elt::GenericPrimeFieldElement;

#[cfg(test)]
mod tests;

// Number of bytes needed to represent field element
// const ELEMENT_BYTES: usize = 2*std::mem::size_of::<u64>();

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SmallPrimeFieldElement {
    value: u64,
    modulus: u64,
}

// impl SmallPrimeFieldElement {
//     fn get_power_series(b: Self, n: usize) -> Vec<Self> {
//         let mut result = utils::uninit_vector(n);
//         result[0] = Self::get_one(b.modulus);
//         for i in 1..result.len() {
//             result[i] = result[i - 1] * b;
//         }
//         result
//     }
// }

/*
impl FieldElement for SmallPrimeFieldElement {
    type PositiveInteger = u64;

    // These are dummies to satisfy the members for FieldElement
    const ZERO: Self = SmallPrimeFieldElement{value: 0u64, modulus: 0u64};
    const ONE: Self = SmallPrimeFieldElement{value: 1u64, modulus: 0u64};

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    fn inv(self) -> Self {
        SmallPrimeFieldElement{value: inv(self.value, self.modulus), modulus: self.modulus}
    }

    fn conjugate(&self) -> Self {
        Self::new(self.value, self.modulus)
    }

    // fn elements_as_bytes(elements: &[Self]) -> &[u8] {
    //     // TODO: take endianness into account
    //     let p = elements.as_ptr();
    //     let len = elements.len() * Self::ELEMENT_BYTES;
    //     unsafe { slice::from_raw_parts(p as *const u8, len) }
    // }

    // unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError> {
    //     if bytes.len() % Self::ELEMENT_BYTES != 0 {
    //         return Err(DeserializationError::InvalidValue(format!(
    //             "number of bytes ({}) does not divide into whole number of field elements",
    //             bytes.len(),
    //         )));
    //     }

    //     let p = bytes.as_ptr();
    //     let len = bytes.len() / Self::ELEMENT_BYTES;

    //     if (p as usize) % mem::align_of::<u128>() != 0 {
    //         return Err(DeserializationError::InvalidValue(
    //             "slice memory alignment is not valid for this field element type".to_string(),
    //         ));
    //     }

    //     Ok(slice::from_raw_parts(p as *const Self, len))
    // }

    // fn zeroed_vector(n: usize) -> Vec<Self> {
    //     // this uses a specialized vector initialization code which requests zero-filled memory
    //     // from the OS; unfortunately, this works only for built-in types and we can't use
    //     // Self::ZERO here as much less efficient initialization procedure will be invoked.
    //     // We also use u128 to make sure the memory is aligned correctly for our element size.
    //     debug_assert_eq!(Self::ELEMENT_BYTES, mem::size_of::<u128>());
    //     let result = vec![0u128; n];

    //     // translate a zero-filled vector of u128s into a vector of base field elements
    //     let mut v = core::mem::ManuallyDrop::new(result);
    //     let p = v.as_mut_ptr();
    //     let len = v.len();
    //     let cap = v.capacity();
    //     unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    // }

    fn as_base_elements(elements: &[Self]) -> &[Self] {
        elements
    }
    // // These are dummies to satisfy the members for FieldElement
    // fn rand() -> Self {
    //     let range = Uniform::from(0..10000);
    //     let mut g = thread_rng();
    //     Self::new(g.sample(range), 0)
    // }

    // fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
    //     Self::try_from(bytes).ok()
    // }

    // fn prng_vector(seed: [u8; 32], n: usize) -> Vec<Self> {
    //     let range = Uniform::from(RANGE);
    //     let g = StdRng::from_seed(seed);
    //     g.sample_iter(range).take(n).map(SmallPrimeFieldElement).collect()
    // }

    // fn to_bytes(&self) -> Vec<u8> {
    //     self.as_bytes().to_vec()
    // }

}

impl SmallPrimeFieldElement {
    pub const fn new(value: <Self as FieldElement>::PositiveInteger, modulus: <Self as FieldElement>::PositiveInteger) -> Self {
        if value < modulus {SmallPrimeFieldElement{ value, modulus }}
        else {SmallPrimeFieldElement{ value: value % modulus, modulus }}
    }

    pub const fn get_zero(modulus: u64) -> Self {
        SmallPrimeFieldElement { value: 0u64, modulus}
    }

    pub const fn get_one(modulus: u64) -> Self {
        SmallPrimeFieldElement { value: 1u64, modulus}
    }

    pub fn get_val(&self) -> u64 {
        self.value
    }
}

impl Randomizable for SmallPrimeFieldElement {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl Display for SmallPrimeFieldElement {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}


// OVERLOADED OPERATORS
// ================================================================================================

impl Add for SmallPrimeFieldElement {
    type Output = SmallPrimeFieldElement;
    fn add(self, rhs: SmallPrimeFieldElement) -> SmallPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        SmallPrimeFieldElement {
            modulus: self.modulus,
            value: add(self.value, rhs.value, self.modulus)
        }
    }
}

impl AddAssign for SmallPrimeFieldElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for SmallPrimeFieldElement {
    type Output = SmallPrimeFieldElement;
    fn sub(self, rhs: SmallPrimeFieldElement) -> SmallPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        SmallPrimeFieldElement::new(sub(self.value, rhs.value, self.modulus), self.modulus)
    }
}

impl SubAssign for SmallPrimeFieldElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for SmallPrimeFieldElement {
    type Output = SmallPrimeFieldElement;
    fn mul(self, rhs: SmallPrimeFieldElement) -> SmallPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        Self::new(mul(self.value, rhs.value, self.modulus), self.modulus)
    }
}

impl MulAssign for SmallPrimeFieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for SmallPrimeFieldElement {
    type Output = SmallPrimeFieldElement;
    fn div(self, rhs: SmallPrimeFieldElement) -> SmallPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        let inv_rhs = inv(rhs.value, self.modulus);
        Self::new(mul(self.value, inv_rhs, self.modulus), self.modulus)
    }
}

impl DivAssign for SmallPrimeFieldElement {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for SmallPrimeFieldElement {
    type Output = SmallPrimeFieldElement;
    fn neg(self) -> SmallPrimeFieldElement {
        Self::new(sub(0u64, self.value, self.modulus), self.modulus)
    }
}

impl Display for SmallPrimeFieldElement {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "value = {}, modulus = {}", self.value, self.modulus)
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for SmallPrimeFieldElement {
    /// Converts a 128-bit value into a filed element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed.
    fn from(value: u128) -> Self {
        SmallPrimeFieldElement::new(value as u64, 0)
    }
}

impl From<u64> for SmallPrimeFieldElement {
    /// Converts a 64-bit value into a filed element.
    fn from(value: u64) -> Self {
        Self::new(value as u64, 0)
    }
}

impl From<u32> for SmallPrimeFieldElement {
    /// Converts a 32-bit value into a filed element.
    fn from(value: u32) -> Self {
        Self::new(value as u64, 0)
    }
}

impl From<u16> for SmallPrimeFieldElement {
    /// Converts a 16-bit value into a filed element.
    fn from(value: u16) -> Self {
        Self::new(value as u64, 0)
    }
}

impl From<u8> for SmallPrimeFieldElement {
    /// Converts an 8-bit value into a filed element.
    fn from(value: u8) -> Self {
        Self::new(value as u64, 0)
    }
}

impl From<[u8; 16]> for SmallPrimeFieldElement {
    /// Converts the value encoded in an array of 16 bytes into a field element. The bytes
    /// are assumed to be in little-endian byte order. If the value is greater than or equal
    /// to the field modulus, modular reduction is silently preformed.
    fn from(bytes: [u8; 16]) -> Self {
        let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let modulus = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        SmallPrimeFieldElement::new(value, modulus)
    }
}

impl<'a> TryFrom<&'a [u8]> for SmallPrimeFieldElement {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value = bytes[0..8]
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| format!("{}", error))?;
        let modulus = bytes[8..16]
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| format!("{}", error))?;
        if modulus <= 0 {
            return Err(format!(
                "cannot convert bytes into a field element: \
                modulus {} is greater or equal to 0",
                modulus
            ));
        }
        Ok(Self::new(value, modulus))
    }
}

impl AsBytes for SmallPrimeFieldElement {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const SmallPrimeFieldElement = self;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// impl AsBytes for [SmallPrimeFieldElement] {
//     fn as_bytes(&self) -> &[u8] {
//         // TODO: take endianness into account
//         unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * ELEMENT_BYTES) }
//     }
// }

// impl AsBytes for [SmallPrimeFieldElement; 4] {
//     fn as_bytes(&self) -> &[u8] {
//         // TODO: take endianness into account
//         unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * ELEMENT_BYTES) }
//     }
// }


impl SmallPrimeField for SmallPrimeFieldElement {
    fn get_modulus(&self) -> u64 {
        self.modulus
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for SmallPrimeFieldElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.value.to_le_bytes());
    }
}

impl Deserializable for SmallPrimeFieldElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u128()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(SmallPrimeFieldElement(value))
    }
}

// FINITE FIELD ARITHMETIC
// ================================================================================================

/// Computes (a + b) % m; a and b are assumed to be valid field elements.
fn add(a: u64, b: u64, modulus: u64) -> u64 {
    let z = modulus - b;
    if a < z {
        modulus - z + a
    } else {
        a - z
    }
}

/// Computes (a - b) % m; a and b are assumed to be valid field elements.
fn sub(a: u64, b: u64, modulus: u64) -> u64 {
    if a < b {
        modulus - b + a
    } else {
        a - b
    }
}

/// Computes (a * b) % m; a and b are assumed to be valid field elements.
fn mul(a: u64, b: u64, modulus: u64) -> u64 {
    (a * b) % modulus
}



/// Computes y such that (x * y) % m = 1 except for when when x = 0; in such a case,
/// 0 is returned; x is assumed to be a valid field element.
fn inv(x: u64, modulus: u64) -> u64 {
    if x == 0 {
        return 0;
    };
    let (_, a) = extended_euclidean(modulus, x, modulus);
    a % modulus
}

// On input (x, y, modulus), computes (a, b), such that b * y % modulus = 1.
fn extended_euclidean(x: u64, y: u64, modulus: u64) -> (u64, u64) {
    if y == 0 {
        return (1, 0);
    }
    let (u1, v1) = extended_euclidean(y, x%y, modulus);
    let subtracting_term = (v1*(x/y)) % modulus;
    let second_term = (modulus + u1 - subtracting_term) % modulus;
    (v1, second_term)
}
*/
