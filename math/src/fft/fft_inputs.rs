use super::StarkField;
use crate::FieldElement;

// FFTINPUTS TRAIT
// ================================================================================================

/// Defines the interface that must be implemented by the input to fft_in_place method.
pub trait FftInputs<B: StarkField> {
    /// Returns the number of elements in this input.
    fn len(&self) -> usize;

    /// Combines the result of smaller number theoretic transform into a larger NTT.
    fn butterfly(&mut self, offset: usize, stride: usize);

    /// Combines the result of smaller number theoretic transform multiplied with a
    /// twiddle factor into a larger NTT.
    fn butterfly_twiddle(&mut self, twiddle: B, offset: usize, stride: usize);

    /// Swaps the element at index i with the element at index j.
    fn swap(&mut self, i: usize, j: usize);

    /// Multiplies every element in this input by a series of increment. Specifically:
    ///
    /// elem_i = elem_i * offset * increment^i
    fn shift_by_series(&mut self, offset: B, increment: B);

    /// Multiplies every element in this input by `offset`. Specifically:
    ///
    /// elem_i = elem_i * offset
    fn shift_by(&mut self, offset: B);
}

/// Implements FftInputs for a slice of field elements.
impl<B, E> FftInputs<B> for [E]
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fn len(&self) -> usize {
        self.len()
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;
        let temp = self[i];
        self[i] = temp + self[j];
        self[j] = temp - self[j];
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: B, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;
        let temp = self[i];
        self[j] = self[j].mul_base(twiddle);
        self[i] = temp + self[j];
        self[j] = temp - self[j];
    }

    fn swap(&mut self, i: usize, j: usize) {
        self.swap(i, j)
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let mut offset = E::from(offset);
        let increment = E::from(increment);
        for d in self.iter_mut() {
            *d *= offset;
            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);
        for d in self.iter_mut() {
            *d *= offset;
        }
    }
}
