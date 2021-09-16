use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};
use std::{mem, u64};
use utils::{
    string::String, AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError,
    Randomizable, Serializable,
};

use crate::{field::QuadExtensionA, FieldElement, StarkField};

// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = std::mem::size_of::<u64>();

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SmallPrimeFieldElt<const M: u64, const G: u64> {
    pub(crate) value: u64,
}

impl<const M: u64, const G: u64> SmallPrimeFieldElt<M, G> {
    const fn get_modulus_as_u64() -> u64 {
        M
    }

    const fn get_generator() -> Self {
        Self::new(G)
    }

    // TODO: this may need to be something else, i.e. its own type param
    const fn get_twoadic_root() -> Self {
        Self::new(G)
    }

    const fn get_modulus_bits() -> u32 {
        64u32 - M.leading_zeros()
    }

    fn get_value(&self) -> u64 {
        self.as_u64()
    }
    /// Creates a new field element from a u128 value. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed. This function can also be used
    /// to initialize constants.
    pub const fn new(value: u64) -> Self {
        let val = value % M; //if  == Ordering::Less { value } else { };
        Self { value: val }
    }

    /// Returns field element converted to u64 representation.
    pub fn as_u64(&self) -> u64 {
        self.value
    }

    #[allow(unused)]
    unsafe fn get_power_series(b: Self, n: usize) -> Vec<Self> {
        let mut result = utils::uninit_vector(n);
        result[0] = Self::ONE;
        for i in 1..result.len() {
            result[i] = result[i - 1] * b;
        }
        result
    }
}

impl<const M: u64, const G: u64> FieldElement for SmallPrimeFieldElt<M, G> {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = Self::new(0);
    const ONE: Self = Self::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    fn inv(self) -> Self {
        Self::new(inv(self.get_value(), Self::get_modulus_as_u64()))
    }

    fn conjugate(&self) -> Self {
        Self::new(self.value)
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        let len = elements.len() * Self::ELEMENT_BYTES;
        let element_values: Vec<u64> = elements.iter().map(|x| x.get_value()).collect();
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

impl<const M: u64, const G: u64> StarkField for SmallPrimeFieldElt<M, G> {
    /// sage: MODULUS = 37
    /// sage: GF(MODULUS).is_prime_field()
    /// True
    /// sage: GF(MODULUS).order()
    /// 37
    type QuadExtension = QuadExtensionA<Self>;
    const MODULUS: Self::PositiveInteger = Self::get_modulus_as_u64();
    const MODULUS_BITS: u32 = Self::get_modulus_bits();

    /// sage: GF(MODULUS).primitive_element()
    /// 3
    const GENERATOR: Self = Self::get_generator();

    /// sage: is_odd((MODULUS - 1) / 2^40)
    /// True
    const TWO_ADICITY: u32 = 2;

    /// sage: k = (MODULUS - 1) / 2^40
    /// sage: GF(MODULUS).primitive_element()^k
    /// 23953097886125630542083529559205016746
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::get_twoadic_root();

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
        self.get_value()
    }

    // fn from_int(value: u64) -> Self {
    //     SmallFieldElement37::new(value)
    // }
}

impl<const M: u64, const G: u64> Display for SmallPrimeFieldElt<M, G> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.get_value())
    }
}

// OVERLOADED OPERATORS
// ================================================================================================

impl<const M: u64, const G: u64> Add for SmallPrimeFieldElt<M, G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.get_value() + rhs.get_value())
    }
}

impl<const M: u64, const G: u64> AddAssign for SmallPrimeFieldElt<M, G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<const M: u64, const G: u64> Sub for SmallPrimeFieldElt<M, G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(checked_mod_sub(self.value, rhs.value, M))
    }
}

impl<const M: u64, const G: u64> SubAssign for SmallPrimeFieldElt<M, G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const M: u64, const G: u64> Mul for SmallPrimeFieldElt<M, G> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::new(self.get_value() * rhs.get_value())
    }
}

impl<const M: u64, const G: u64> MulAssign for SmallPrimeFieldElt<M, G> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl<const M: u64, const G: u64> Div for SmallPrimeFieldElt<M, G> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Self::new(self.get_value() / rhs.get_value())
    }
}

impl<const M: u64, const G: u64> DivAssign for SmallPrimeFieldElt<M, G> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl<const M: u64, const G: u64> Neg for SmallPrimeFieldElt<M, G> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(Self::get_modulus_as_u64() - self.get_value())
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl<const M: u64, const G: u64> From<u128> for SmallPrimeFieldElt<M, G> {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently preformed.
    fn from(value: u128) -> Self {
        Self::new(value as u64)
    }
}

impl<const M: u64, const G: u64> From<u64> for SmallPrimeFieldElt<M, G> {
    /// Converts a 64-bit value into a field element.
    fn from(value: u64) -> Self {
        SmallPrimeFieldElt::new(value as u64)
    }
}

impl<const M: u64, const G: u64> From<u32> for SmallPrimeFieldElt<M, G> {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        SmallPrimeFieldElt::new(value as u64)
    }
}

impl<const M: u64, const G: u64> From<u16> for SmallPrimeFieldElt<M, G> {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        SmallPrimeFieldElt::new(value as u64)
    }
}

impl<const M: u64, const G: u64> From<u8> for SmallPrimeFieldElt<M, G> {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        SmallPrimeFieldElt::new(value as u64)
    }
}

impl<const M: u64, const G: u64> From<[u8; 8]> for SmallPrimeFieldElt<M, G> {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes
    /// are assumed to be in little-endian byte order. If the value is greater than or equal
    /// to the field modulus, modular reduction is silently preformed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        SmallPrimeFieldElt::from(value)
    }
}

impl<'a, const M: u64, const G: u64> TryFrom<&'a [u8]> for SmallPrimeFieldElt<M, G> {
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

impl<const M: u64, const G: u64> AsBytes for SmallPrimeFieldElt<M, G> {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const u64 = &self.get_value();
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl<const M: u64, const G: u64> Serializable for SmallPrimeFieldElt<M, G> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.get_value().to_le_bytes());
    }
}

impl<const M: u64, const G: u64> Deserializable for SmallPrimeFieldElt<M, G> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= Self::get_modulus_as_u64() {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(SmallPrimeFieldElt::new(value))
    }
}

impl<const M: u64, const G: u64> Randomizable for SmallPrimeFieldElt<M, G> {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

// Helper functions ******

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