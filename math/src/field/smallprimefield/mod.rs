use crate::fft;

use super::{
    traits::{FieldElement, StarkField},
    QuadExtensionA,
};
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

#[cfg(test)]
mod tests;

// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = mem::size_of::<u64>();

// SMALL PRIME FIELD ELEMENT
// ================================================================================================

/// Represents a base field element with a small modulus.
/// Primarily for testing, so we can hand calculate expected outputs.
/// Note that all the operations here are naive field operations without optimizations.
/// We also don't end up needing to use the twoadic roots anymore,
/// since we can factor MODULUS - 1 easily. Meaning, any factor root of MODULUS - 1 can be found.
/// Internal values are stored in their canonical form in the range [0, MODULUS). The backing type is
/// `u64`.

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct BaseElement<const M: u64, const G: u64, const T: u32> {
    pub(crate) value: u64,
}

impl<const M: u64, const G: u64, const T: u32> BaseElement<M, G, T> {
    const fn get_twoadic_root() -> Self {
        let g_pow = div_by_power_of_two(M, Self::TWO_ADICITY);
        let pow_val = G ^ g_pow;
        Self::new(pow_val)
    }

    const fn get_modulus_bits() -> u32 {
        64u32 - M.leading_zeros()
    }

    /// Creates a new field element from a u64 value. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed. This function can also be used
    /// to initialize constants.
    pub const fn new(value: u64) -> Self {
        let val = value % M;
        Self { value: val }
    }

    #[allow(unused)]
    pub unsafe fn get_power_series(b: Self, n: usize) -> Vec<Self> {
        let mut result = utils::uninit_vector(n);
        result[0] = Self::ONE;
        for i in 1..result.len() {
            result[i] = result[i - 1] * b;
        }
        result
    }

    pub unsafe fn get_twiddles(domain_size: usize) -> Vec<Self> {
        debug_assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of 2"
        );
        let root = Self::get_root_of_unity(domain_size.try_into().unwrap());
        let mut twiddles = Self::get_power_series(root, domain_size / 2);
        fft::permute(&mut twiddles);
        twiddles
    }

    pub unsafe fn get_inv_twiddles(domain_size: usize) -> Vec<Self> {
        debug_assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of 2"
        );
        let root = Self::get_root_of_unity(domain_size.try_into().unwrap());
        let inv_root = root.exp((domain_size as u32 - 1).into());
        let mut inv_twiddles = Self::get_power_series(inv_root, domain_size / 2);
        fft::permute(&mut inv_twiddles);
        inv_twiddles
    }
}

impl<const M: u64, const G: u64, const T: u32> FieldElement for BaseElement<M, G, T> {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = Self::new(0);
    const ONE: Self = Self::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    fn inv(self) -> Self {
        Self::new(inv(self.value, M))
    }

    fn conjugate(&self) -> Self {
        Self::new(self.value)
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        let len = elements.len() * Self::ELEMENT_BYTES;
        let p = elements.as_ptr();
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
        // from the OS; here to fulfil trait bounds
        // We also use u64 to make sure the memory is aligned correctly for our element size.
        debug_assert_eq!(Self::ELEMENT_BYTES, mem::size_of::<u64>());
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

    fn double(self) -> Self {
        Self::new(self.value + self.value)
    }

    fn square(self) -> Self {
        Self::new(self.value * self.value)
    }

    fn cube(self) -> Self {
        Self::new(self.value * self.value * self.value)
    }

    fn exp(self, power: Self::PositiveInteger) -> Self {
        let mut r = Self::ONE;
        let mut b = self;
        let mut p = power;

        let int_zero = Self::PositiveInteger::from(0u32);
        let int_one = Self::PositiveInteger::from(1u32);

        if p == int_zero {
            return Self::ONE;
        } else if b == Self::ZERO {
            return Self::ZERO;
        }

        while p > int_zero {
            if p & int_one == int_one {
                r *= b;
            }
            p >>= int_one;
            b = b.square();
        }

        r
    }
}

impl<const M: u64, const G: u64, const T: u32> StarkField for BaseElement<M, G, T> {
    type QuadExtension = QuadExtensionA<Self>;
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = Self::get_modulus_bits();

    const GENERATOR: Self = Self::new(G);

    const TWO_ADICITY: u32 = T;

    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::get_twoadic_root();

    /// Gets the n-th root of unity.
    /// Here, n needs to be a factor of the modulus.
    /// Note that this is actually the nth root, not the
    /// 2^n-th root, unlike the generic function under Starkfield.
    fn get_root_of_unity(n: u32) -> Self {
        get_prime_field_root_of_unity(n, Self::MODULUS)
    }

    fn get_modulus_le_bytes() -> Vec<u8> {
        Self::MODULUS.to_le_bytes().to_vec()
    }

    fn as_int(&self) -> Self::PositiveInteger {
        self.value
    }
}

impl<const M: u64, const G: u64, const T: u32> Display for BaseElement<M, G, T> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.value)
    }
}

// OVERLOADED OPERATORS
// ================================================================================================

impl<const M: u64, const G: u64, const T: u32> Add for BaseElement<M, G, T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.value + rhs.value)
    }
}

impl<const M: u64, const G: u64, const T: u32> AddAssign for BaseElement<M, G, T> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<const M: u64, const G: u64, const T: u32> Sub for BaseElement<M, G, T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(checked_mod_sub(self.value, rhs.value, M))
    }
}

impl<const M: u64, const G: u64, const T: u32> SubAssign for BaseElement<M, G, T> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const M: u64, const G: u64, const T: u32> Mul for BaseElement<M, G, T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::new(self.value * rhs.value)
    }
}

impl<const M: u64, const G: u64, const T: u32> MulAssign for BaseElement<M, G, T> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl<const M: u64, const G: u64, const T: u32> Div for BaseElement<M, G, T> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Self::new(self.value / rhs.value)
    }
}

impl<const M: u64, const G: u64, const T: u32> DivAssign for BaseElement<M, G, T> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl<const M: u64, const G: u64, const T: u32> Neg for BaseElement<M, G, T> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(M - self.value)
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl<const M: u64, const G: u64, const T: u32> From<u128> for BaseElement<M, G, T> {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed.
    fn from(value: u128) -> Self {
        Self::new(value as u64)
    }
}

impl<const M: u64, const G: u64, const T: u32> From<u64> for BaseElement<M, G, T> {
    /// Converts a 64-bit value into a field element.
    fn from(value: u64) -> Self {
        BaseElement::new(value as u64)
    }
}

impl<const M: u64, const G: u64, const T: u32> From<u32> for BaseElement<M, G, T> {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        BaseElement::new(value as u64)
    }
}

impl<const M: u64, const G: u64, const T: u32> From<u16> for BaseElement<M, G, T> {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        BaseElement::new(value as u64)
    }
}

impl<const M: u64, const G: u64, const T: u32> From<u8> for BaseElement<M, G, T> {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        BaseElement::new(value as u64)
    }
}

impl<const M: u64, const G: u64, const T: u32> From<[u8; 8]> for BaseElement<M, G, T> {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes
    /// are assumed to be in little-endian byte order. If the value is greater than or equal
    /// to the field modulus, modular reduction is silently preformed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        BaseElement::from(value)
    }
}

impl<'a, const M: u64, const G: u64, const T: u32> TryFrom<&'a [u8]> for BaseElement<M, G, T> {
    type Error = String;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to be in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value = bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| format!("{}", error))?;
        Ok(Self::new(value))
    }
}

impl<const M: u64, const G: u64, const T: u32> AsBytes for BaseElement<M, G, T> {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const u64 = &self.value;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl<const M: u64, const G: u64, const T: u32> Serializable for BaseElement<M, G, T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.value.to_le_bytes());
    }
}

impl<const M: u64, const G: u64, const T: u32> Deserializable for BaseElement<M, G, T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(BaseElement::new(value))
    }
}

impl<const M: u64, const G: u64, const T: u32> Randomizable for BaseElement<M, G, T> {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

// Helper functions ******

// Got the skeleton of this algorithm from https://docs.rs/unknown_order/0.2.3/src/unknown_order/rust_backend.rs.html#143-184
pub fn inv(x: u64, modulus: u64) -> u64 {
    if x == 0 || modulus == 0 || modulus == 1 {
        return 0;
    }

    // Euclid's extended algorithm, Bèzout coefficient of `n` is not needed
    //n is either prime or coprime
    //
    //function inverse(a, n)
    //    t := 0;     newt := 1;
    //    r := n;     newr := a;
    //    while newr ≠ 0
    //        quotient := r div newr
    //        (t, newt) := (newt, t - quotient * newt)
    //        (r, newr) := (newr, r - quotient * newr)
    //    if r > 1 then return "a is not invertible"
    //    if t < 0 then t := t + n
    //    return t
    //
    let (mut t, mut new_t) = (0u64, 1u64);
    let (mut r, mut new_r) = (modulus, x);

    while new_r != 0 {
        let quotient = r / new_r;

        let temp_t = t;
        let temp_new_t = new_t;

        t = temp_new_t;
        new_t = checked_mod_sub(temp_t, quotient * temp_new_t, modulus);

        let temp_r = r;
        let temp_new_r = new_r;

        r = temp_new_r;
        new_r = checked_mod_sub(temp_r, quotient * temp_new_r, modulus);
    }
    if r > 1u64 {
        // Not invertible
        return 0;
    }
    t
}

fn checked_mod_sub(a: u64, b: u64, modulus: u64) -> u64 {
    let mut new_a = a;
    loop {
        match new_a.checked_sub(b) {
            Some(val) => {
                new_a = val;
                break;
            }
            None => {
                new_a += modulus;
            }
        }
    }
    new_a
}

pub fn get_prime_field_root_of_unity<E: StarkField>(n: u32, modulus: u64) -> E {
    let small_field_size_64 = modulus - 1;
    let small_field_size: u32 = small_field_size_64.try_into().unwrap();
    assert!(n != 0, "cannot get root of unity for n = 0");
    assert!(
        n <= small_field_size,
        "order cannot exceed {}",
        small_field_size
    );
    assert!(
        small_field_size % n == 0,
        "Order invalid for field size {}",
        small_field_size
    );
    let power = small_field_size / n;
    E::exp(E::GENERATOR, power.into())
}

const fn get_two_adicity(n: u64) -> u32 {
    let mut two_adicity = 0;
    let mut quotient = n - 1;
    while quotient % 2 == 0 {
        two_adicity = two_adicity + 1;
        quotient = quotient + 2;
    }
    two_adicity
}

const fn div_by_power_of_two(dividend: u64, pow: u32) -> u64 {
    dividend / (1u64 << pow)
}
