use std::convert::TryInto;

use crate::StarkField;

pub mod generic_prime_field_elt;

#[cfg(test)]
mod tests;

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
