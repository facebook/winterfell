// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod high_degree;
use core::{fmt::Formatter, ops::Add};

use alloc::{fmt, vec::Vec};
pub use high_degree::sum_check_prove_higher_degree;

mod plain;
use math::FieldElement;
pub use plain::sumcheck_prove_plain_batched_serial;
pub use plain::sumcheck_prove_plain_batched;

mod error;
pub use error::SumCheckProverError;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::MultiLinearPoly;

// CIRCUIT LAYER POLYS
// ===============================================================================================

/// Holds a layer of an [`EvaluatedCircuit`] in a representation amenable to proving circuit
/// evaluation using GKR.
#[derive(Clone, Debug)]
pub struct CircuitLayerPolys<E: FieldElement> {
    pub numerators: MultiLinearPoly<E>,
    pub denominators: MultiLinearPoly<E>,
}


impl<E> Serializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { numerators, denominators } = self;
        numerators.write_into(target);
        denominators.write_into(target);
    }
}

impl<E> Deserializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            numerators: MultiLinearPoly::read_from(source)?,
            denominators: MultiLinearPoly::read_from(source)?,
        })
    }
}


// CIRCUIT LAYER POLYS
// ===============================================================================================


impl<E> CircuitLayerPolys<E>
where
    E: FieldElement,
{
    pub fn from_circuit_layer(layers: &[CircuitLayer<E>]) -> Vec<Self> {
        let mut result = vec![];
        for layer in layers {
            result.push(Self::from_wires(layer.wires.clone()))
        }
        result
    }

    pub fn from_wires(wires: Vec<CircuitWire<E>>) -> Self {
        let mut numerators = Vec::new();
        let mut denominators = Vec::new();

        for wire in wires {
            numerators.push(wire.numerator);
            denominators.push(wire.denominator);
        }

        Self {
            numerators: MultiLinearPoly::from_evaluations(numerators),
            denominators: MultiLinearPoly::from_evaluations(denominators),
        }
    }
}

// CIRCUIT LAYER
// ===============================================================================================

/// Represents a layer in a [`EvaluatedCircuit`].
///
/// A layer is made up of a set of `n` wires, where `n` is a power of two. This is the natural
/// circuit representation of a layer, where each consecutive pair of wires are summed to yield a
/// wire in the subsequent layer of an [`EvaluatedCircuit`].
///
/// Note that a [`Layer`] needs to be first converted to a [`LayerPolys`] before the evaluation of
/// the layer can be proved using GKR.
#[derive(Debug)]
pub struct CircuitLayer<E: FieldElement> {
    wires: Vec<CircuitWire<E>>,
}

impl<E: FieldElement> CircuitLayer<E> {
    /// Creates a new [`Layer`] from a set of projective coordinates.
    ///
    /// Panics if the number of projective coordinates is not a power of two.
    pub fn new(wires: Vec<CircuitWire<E>>) -> Self {
        assert!(wires.len().is_power_of_two());

        Self { wires }
    }

    /// Returns the wires that make up this circuit layer.
    pub fn wires(&self) -> &[CircuitWire<E>] {
        &self.wires
    }

    /// Returns the number of wires in the layer.
    pub fn num_wires(&self) -> usize {
        self.wires.len()
    }
}

// CIRCUIT WIRE
// ===============================================================================================

/// Represents a fraction `numerator / denominator` as a pair `(numerator, denominator)`. This is
/// the type for the gates' inputs in [`prover::EvaluatedCircuit`].
///
/// Hence, addition is defined in the natural way fractions are added together: `a/b + c/d = (ad +
/// bc) / bd`.
#[derive(Clone, Copy)]
pub struct CircuitWire<E: FieldElement> {
    numerator: E,
    denominator: E,
}

impl<E> CircuitWire<E>
where
    E: FieldElement,
{
    /// Creates new projective coordinates from a numerator and a denominator.
    pub fn new(numerator: E, denominator: E) -> Self {
        assert_ne!(denominator, E::ZERO);

        Self { numerator, denominator }
    }
}

impl<E> Add for CircuitWire<E>
where
    E: FieldElement,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let numerator = self.numerator * other.denominator + other.numerator * self.denominator;
        let denominator = self.denominator * other.denominator;

        Self::new(numerator, denominator)
    }
}

impl<E: FieldElement> fmt::Debug for CircuitWire<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} / {}", self.numerator, self.denominator)
    }
}
