use alloc::vec::Vec;

use super::lagrange::LagrangeRandElements;

/// TODOP: document
#[derive(Debug, Clone)]
pub struct AuxRandElements<E> {
    rand_elements: Vec<E>,
    lagrange: Option<LagrangeRandElements<E>>,
}

impl<E> AuxRandElements<E> {
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self {
            rand_elements,
            lagrange: None,
        }
    }

    pub fn new_with_lagrange(
        rand_elements: Vec<E>,
        lagrange: Option<LagrangeRandElements<E>>,
    ) -> Self {
        Self {
            rand_elements,
            lagrange,
        }
    }

    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    pub fn lagrange(&self) -> Option<&LagrangeRandElements<E>> {
        self.lagrange.as_ref()
    }
}
