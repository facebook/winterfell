use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};
use utils::{
    string::String, AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError,
    Randomizable, Serializable,
};

// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = 2 * std::mem::size_of::<u64>();

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GenericPrimeFieldElement {
    pub(crate) value: u64,
    pub(crate) modulus: u64,
}

impl GenericPrimeFieldElement {
    pub const fn new(value: u64, modulus: u64) -> Self {
        if value < modulus {
            Self { value, modulus }
        } else {
            Self {
                value: value % modulus,
                modulus,
            }
        }
    }

    pub const fn get_zero(modulus: u64) -> Self {
        Self {
            value: 0u64,
            modulus,
        }
    }

    pub const fn get_one(modulus: u64) -> Self {
        Self {
            value: 1u64,
            modulus,
        }
    }

    pub const fn get_value(&self) -> u64 {
        self.value
    }

    pub const fn get_modulus(&self) -> u64 {
        self.modulus
    }

    pub fn set_modulus(&mut self, modulus: u64) {
        self.modulus = modulus;
    }
}

impl GenericPrimeFieldElement {
    // type PositiveInteger = u64;
    // type BaseField = Self;

    // // These are dummies to satisfy the members for FieldElement
    // const ZERO: Self = Self {value: 0u64, modulus: Self::PositiveInteger};
    // const ONE: Self = Self {value: 1u64, modulus: Self::PositiveInteger};

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    pub(crate) fn inv(self) -> Self {
        GenericPrimeFieldElement::new(inv(self.value, self.modulus), self.modulus)
    }

    pub(crate) fn conjugate(&self) -> Self {
        GenericPrimeFieldElement::new(self.value, self.modulus)
    }

    #[allow(unused)]
    pub(crate) fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        // TODO: take endianness into account
        let p = elements.as_ptr();
        let len = elements.len() * Self::ELEMENT_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }

    // pub(crate) unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError> {
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

    // pub(crate) fn zeroed_vector(n: usize) -> Vec<Self> {
    //     // this uses a specialized vector initialization code which requests zero-filled memory
    //     // from the OS; unfortunately, this works only for built-in types and we can't use
    //     // Self::ZERO here as much less efficient initialization procedure will be invoked.
    //     // We also use u128 to make sure the memory is aligned correctly for our element size.
    //     debug_assert_eq!(Self::ELEMENT_BYTES, 2 * std::mem::size_of::<u64>());
    //     let result = vec![0u128; n];

    //     // translate a zero-filled vector of u128s into a vector of base field elements
    //     let mut v = core::mem::ManuallyDrop::new(result);
    //     let p = v.as_mut_ptr();
    //     let len = v.len();
    //     let cap = v.capacity();
    //     unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    // }

    // pub(crate) fn as_base_elements(elements: &[Self]) -> &[Self] {
    //     elements
    // }
}

// OVERLOADED OPERATORS
// ================================================================================================

impl Add for GenericPrimeFieldElement {
    type Output = GenericPrimeFieldElement;
    fn add(self, rhs: GenericPrimeFieldElement) -> GenericPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        GenericPrimeFieldElement {
            value: add(self.value, rhs.value, self.modulus),
            modulus: self.modulus,
        }
    }
}

impl AddAssign for GenericPrimeFieldElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for GenericPrimeFieldElement {
    type Output = GenericPrimeFieldElement;
    fn sub(self, rhs: GenericPrimeFieldElement) -> GenericPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        GenericPrimeFieldElement::new(sub(self.value, rhs.value, self.modulus), self.modulus)
    }
}

impl SubAssign for GenericPrimeFieldElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for GenericPrimeFieldElement {
    type Output = GenericPrimeFieldElement;
    fn mul(self, rhs: GenericPrimeFieldElement) -> GenericPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        Self::new(mul(self.value, rhs.value, self.modulus), self.modulus)
    }
}

impl MulAssign for GenericPrimeFieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for GenericPrimeFieldElement {
    type Output = GenericPrimeFieldElement;
    fn div(self, rhs: GenericPrimeFieldElement) -> GenericPrimeFieldElement {
        assert_eq!(self.modulus, rhs.modulus);
        let inv_rhs = inv(rhs.value, self.modulus);
        Self::new(mul(self.value, inv_rhs, self.modulus), self.modulus)
    }
}

impl DivAssign for GenericPrimeFieldElement {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for GenericPrimeFieldElement {
    type Output = GenericPrimeFieldElement;
    fn neg(self) -> GenericPrimeFieldElement {
        Self::new(sub(0u64, self.value, self.modulus), self.modulus)
    }
}

impl Randomizable for GenericPrimeFieldElement {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl Display for GenericPrimeFieldElement {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "value = {}, modulus = {}", self.value, self.modulus)
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for GenericPrimeFieldElement {
    /// Converts a 128-bit value into a filed element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed.
    fn from(value: u128) -> Self {
        GenericPrimeFieldElement {
            value: value as u64,
            modulus: 0u64,
        }
    }
}

impl From<u64> for GenericPrimeFieldElement {
    /// Converts a 64-bit value into a filed element.
    fn from(value: u64) -> Self {
        GenericPrimeFieldElement {
            value,
            modulus: 0u64,
        }
    }
}

impl From<u32> for GenericPrimeFieldElement {
    /// Converts a 32-bit value into a filed element.
    fn from(value: u32) -> Self {
        GenericPrimeFieldElement {
            value: value as u64,
            modulus: 0u64,
        }
    }
}

impl From<u16> for GenericPrimeFieldElement {
    /// Converts a 16-bit value into a filed element.
    fn from(value: u16) -> Self {
        GenericPrimeFieldElement {
            value: value as u64,
            modulus: 0u64,
        }
    }
}

impl From<u8> for GenericPrimeFieldElement {
    /// Converts an 8-bit value into a filed element.
    fn from(value: u8) -> Self {
        GenericPrimeFieldElement {
            value: value as u64,
            modulus: 0u64,
        }
    }
}

impl From<[u8; 16]> for GenericPrimeFieldElement {
    /// Converts the value encoded in an array of 16 bytes into a field element. The bytes
    /// are assumed to be in little-endian byte order. If the value is greater than or equal
    /// to the field modulus, modular reduction is silently preformed.
    fn from(bytes: [u8; 16]) -> Self {
        let value = u128::from_le_bytes(bytes);
        GenericPrimeFieldElement::from(value)
    }
}

impl<'a> TryFrom<&'a [u8]> for GenericPrimeFieldElement {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value = bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| format!("{}", error))?;
        Ok(GenericPrimeFieldElement {
            value,
            modulus: 0u64,
        })
    }
}

impl AsBytes for GenericPrimeFieldElement {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const GenericPrimeFieldElement = self;
        unsafe {
            slice::from_raw_parts(
                self_ptr as *const u8,
                GenericPrimeFieldElement::ELEMENT_BYTES,
            )
        }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for GenericPrimeFieldElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.value.to_le_bytes());
    }
}

impl Deserializable for GenericPrimeFieldElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        // if value >= Self::get_modulus() {
        //     return Err(DeserializationError::InvalidValue(format!(
        //         "invalid field element: value {} is greater than or equal to the field modulus",
        //         value
        //     )));
        // }
        Ok(Self {
            value,
            modulus: 0u64,
        })
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

fn extended_euclidean(x: u64, y: u64, modulus: u64) -> (u64, u64) {
    if y == 0 {
        return (1, 0);
    }
    let (u1, v1) = extended_euclidean(y, x % y, modulus);
    // let q: i128 = ({u1 as i128} - {({v1 as i128} * {(x/y) as i128}) as i128}) + {modulus as i128};
    let q: i128 = { (u1 + modulus - (v1 * (x / y))) as i128 };
    let q_modulo = q % { modulus as i128 };
    let second_term = q_modulo as u64;
    // let subtracting_term = v1 * (x / y);
    // let second_term = ((modulus + u1) - subtracting_term) % modulus;
    (v1, second_term)
    // (v1, (M + u1) - v1 * (x/y))
}
