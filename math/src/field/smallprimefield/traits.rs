use super::super::traits::StarkField;
use core::convert::TryInto;

// pub trait SmallPrimeFieldElement: FieldElement {
//     const MODULUS: Self::PositiveInteger;
//     const MODULUS_BITS: u32;
//     type GenericValue: Debug
//         + Copy
//         + PartialEq
//         + PartialOrd
//         + Add<Self::GenericValue, Output = Self::GenericValue>
//         + Sub<Self::GenericValue, Output = Self::GenericValue>
//         + Mul<Self::GenericValue, Output = Self::GenericValue>
//         + Div<Self::GenericValue, Output = Self::GenericValue>
//         + AddAssign<Self::GenericValue>
//         + SubAssign<Self::GenericValue>
//         + MulAssign<Self::GenericValue>
//         + DivAssign<Self::GenericValue>
//         + Neg<Output = Self::GenericValue>
//         + From<u32>
//         + From<u64>
//         + Add
//         + AddAssign;
//     fn new(value: u64) -> Self;
//     fn get_modulus(&self) -> Self::PositiveInteger;
//     fn get_zero(&self) -> Self::GenericValue;
//     fn get_one(&self) -> Self::GenericValue;
// }

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

// pub trait SmallPrimeFieldInstance: FieldElement + StarkField {
//     fn get_modulus(&self) -> u64;
//     fn get_val(&self) -> u64;
//     fn from_smallprimefield(SmallPrimeFieldElement { value, modulus }: SmallPrimeFieldElement) -> Self {

//     }
//     fn get_smallprimefield(&self) -> SmallPrimeFieldElement {
//         SmallPrimeFieldElement::new(self.get_val(), self.get_modulus())
//     }
// }

/*
impl FieldElement for SmallPrimeFieldElement {
    type PositiveInteger = u64;
    type BaseField = Self;

    // These are dummies to satisfy the members for FieldElement
    const ZERO: Self = GenericPrimeFieldElement{value: 0u64, modulus: Self::MODULUS};
    const ONE: Self = GenericPrimeFieldElement{value: 1u64, modulus: Self::MODULUS};

    const ELEMENT_BYTES: usize = GenericPrimeFieldElement::ELEMENT_BYTES;

    const IS_CANONICAL: bool = true;

    fn inv(self) -> Self {
        Self::new(inv(self.value, self.MODULUS))
    }

    fn conjugate(&self) -> Self {
        GenericPrimeFieldElement::new(self.value, self.modulus)
    }

    // /// This implementation is about 5% faster than the one in the trait.
    // fn get_power_series(b: Self, n: usize) -> Vec<Self> {
    //     let mut result = utils::uninit_vector(n);
    //     result[0] = Self::ONE;
    //     for i in 1..result.len() {
    //         result[i] = result[i - 1] * b;
    //     }
    //     result
    // }

    // fn rand() -> Self {
    //     let range = Uniform::from(Self::RANGE);
    //     let mut g = thread_rng();
    //     Self::new(g.sample(range))
    // }

    // fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
    //     Self::try_from(bytes).ok()
    // }

    // fn to_bytes(&self) -> Vec<u8> {
    //     self.as_bytes().to_vec()
    // }

    // fn from_int(value: u128) -> Self {
    //     Self::new(value)
    // }

    // fn prng_vector(seed: [u8; 32], n: usize) -> Vec<Self> {
    //     let range = Uniform::from(Self::RANGE);
    //     let g = StdRng::from_seed(seed);
    //     g.sample_iter(range).take(n).map(Self::new).collect()
    // }

}

*/

// // FINITE FIELD ARITHMETIC
// // ================================================================================================

// /// Computes (a + b) % m; a and b are assumed to be valid field elements.
// fn add(a: u64, b: u64, modulus: u64) -> u64 {
//     let z = modulus - b;
//     if a < z {
//         modulus - z + a
//     } else {
//         a - z
//     }
// }

// /// Computes (a - b) % m; a and b are assumed to be valid field elements.
// fn sub(a: u64, b: u64, modulus: u64) -> u64 {
//     if a < b {
//         modulus - b + a
//     } else {
//         a - b
//     }
// }

// /// Computes (a * b) % m; a and b are assumed to be valid field elements.
// fn mul(a: u64, b: u64, modulus: u64) -> u64 {
//     (a * b) % modulus
// }

// /// Computes y such that (x * y) % m = 1 except for when when x = 0; in such a case,
// /// 0 is returned; x is assumed to be a valid field element.
// fn inv(x: u64, modulus: u64) -> u64 {
//     if x == 0 {
//         return 0;
//     };
//     let (_, a) = extended_euclidean(modulus, x, modulus);
//     a % modulus
// }

// fn extended_euclidean(x: u64, y: u64, modulus: u64) -> (u64, u64) {
//     if y == 0 {
//         return (1, 0);
//     }
//     let (u1, v1) = extended_euclidean(y, x % y, modulus);
//     // let q: i128 = {(u1 - v1 * (x/y)) as i128} + {M as i128};
//     // let q_mod_M = q % {M as i128};
//     let subtracting_term = v1 * (x / y);
//     let second_term = (modulus + u1 - subtracting_term) % modulus;
//     (v1, second_term)
//     // (v1, (M + u1) - v1 * (x/y))
// }
