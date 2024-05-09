// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{collections::BTreeMap, vec::Vec};

use air::Air;
use math::{fft, StarkField};
use utils::uninit_vector;

pub struct PeriodicValueTable<B: StarkField> {
    values: Vec<B>,
    length: usize,
    width: usize,
}

impl<B: StarkField> PeriodicValueTable<B> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Builds a table of periodic column values for the specified AIR. The table contains expanded
    /// values of all periodic columns normalized to the same length. This enables simple lookup
    /// into the able using step index of the constraint evaluation domain.
    pub fn new<A: Air<BaseField = B>>(air: &A) -> PeriodicValueTable<B> {
        // get a list of polynomials describing periodic columns from AIR. if there are no
        // periodic columns return an empty table
        let polys = air.get_periodic_column_polys();
        if polys.is_empty() {
            return PeriodicValueTable { values: Vec::new(), length: 0, width: 0 };
        }

        // determine the size of the biggest polynomial in the set. unwrap is OK here
        // because if we get here, there must be at least one polynomial in the set.
        let max_poly_size = polys.iter().max_by_key(|p| p.len()).unwrap().len();

        // cache twiddles used for polynomial evaluation here so that we don't have to re-build
        // them for polynomials of the same size
        let mut twiddle_map = BTreeMap::new();

        let evaluations = polys
            .iter()
            .map(|poly| {
                let poly_size = poly.len();
                let num_cycles = (air.trace_length() / poly_size) as u64;
                let offset = air.domain_offset().exp(num_cycles.into());
                let twiddles =
                    twiddle_map.entry(poly_size).or_insert_with(|| fft::get_twiddles(poly_size));

                fft::evaluate_poly_with_offset(poly, twiddles, offset, air.ce_blowup_factor())
            })
            .collect::<Vec<_>>();

        // allocate memory to hold all expanded values and copy polynomial evaluations into the
        // table in such a way that values for the same row are adjacent to each other.
        let row_width = polys.len();
        let column_length = max_poly_size * air.ce_blowup_factor();
        let mut values = unsafe { uninit_vector(row_width * column_length) };
        for i in 0..column_length {
            for (j, column) in evaluations.iter().enumerate() {
                values[i * row_width + j] = column[i % column.len()];
            }
        }

        PeriodicValueTable {
            values,
            length: column_length,
            width: row_width,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn is_empty(&self) -> bool {
        self.width == 0
    }

    pub fn get_row(&self, ce_step: usize) -> &[B] {
        if self.is_empty() {
            &[]
        } else {
            let start = (ce_step % self.length) * self.width;
            &self.values[start..start + self.width]
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use air::Air;
    use math::{
        fields::f128::BaseElement, get_power_series_with_offset, polynom, FieldElement, StarkField,
    };

    use crate::tests::MockAir;

    #[test]
    fn periodic_value_table() {
        let trace_length = 32;

        // instantiate AIR with 2 periodic columns
        let col1 = vec![1u128, 2].into_iter().map(BaseElement::new).collect::<Vec<_>>();
        let col2 = vec![3u128, 4, 5, 6].into_iter().map(BaseElement::new).collect::<Vec<_>>();
        let air = MockAir::with_periodic_columns(vec![col1, col2], trace_length);

        // build a table of periodic values
        let table = super::PeriodicValueTable::new(&air);

        assert_eq!(2, table.width);
        assert_eq!(4 * air.ce_blowup_factor(), table.length);

        let polys = air.get_periodic_column_polys();
        let domain = build_ce_domain(air.ce_domain_size(), air.domain_offset());

        // build expected values by evaluating polynomials over shifted ce_domain
        let expected = polys
            .iter()
            .map(|poly| {
                let num_cycles = trace_length / poly.len();
                domain
                    .iter()
                    .map(|&x| {
                        let x = x.exp((num_cycles as u32).into());
                        polynom::eval(poly, x)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // build actual values by recording rows of the table at each step of ce_domain
        let mut actual = vec![Vec::new(), Vec::new()];
        for i in 0..air.ce_domain_size() {
            let row = table.get_row(i);
            actual[0].push(row[0]);
            actual[1].push(row[1]);
        }

        assert_eq!(expected, actual);
    }

    fn build_ce_domain(domain_size: usize, domain_offset: BaseElement) -> Vec<BaseElement> {
        let g = BaseElement::get_root_of_unity(domain_size.ilog2());
        get_power_series_with_offset(g, domain_offset, domain_size)
    }
}
