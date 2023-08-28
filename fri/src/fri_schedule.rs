// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Enumerates the possible schedules for the FRI folding process.
///
/// The FRI folding process can operate under a constant factor or
/// can follow a dynamic sequence of factors. This enum provides a
/// way to specify which approach to use.
///
/// # Variants
///
/// - `Constant`: Represents a constant folding factor. This means that
///   the prover will use the same folding factor iteratively throughout
///   the FRI folding process. The prover will also specify the maximum
///   degree of the remainder polynomial at the last FRI layer.
///
/// - `Dynamic`: Represents a dynamic schedule of folding factors. This means
///   that the prover can use different folding factors across different rounds.
///
/// # Examples
///
/// Using a constant factor:
///
/// ```
/// let constant_schedule = FoldingSchedule::constant(4, 2);
/// ```
///
/// Using a dynamic schedule:
///
/// ```
/// let dynamic_schedule = FoldingSchedule::dynamic(vec![4, 2, 2]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FoldingSchedule {
    Constant {
        fri_folding_factor: u8,
        fri_remainder_max_degree: u8,
    },
    Dynamic {
        schedule: Vec<u8>,
    },
}

impl FoldingSchedule {
    // Constructors
    // -------------------------------------------------------------------------------------------

    pub fn new_constant(fri_folding_factor: u8, fri_remainder_max_degree: u8) -> Self {
        FoldingSchedule::Constant {
            fri_folding_factor,
            fri_remainder_max_degree,
        }
    }

    pub fn new_dynamic(schedule: Vec<u8>) -> Self {
        FoldingSchedule::Dynamic { schedule }
    }

    // Accessors
    // -------------------------------------------------------------------------------------------

    pub fn get_factor(&self) -> Option<u8> {
        match self {
            FoldingSchedule::Constant {
                fri_folding_factor, ..
            } => Some(*fri_folding_factor),
            FoldingSchedule::Dynamic { schedule: _ } => None,
        }
    }

    pub fn get_schedule(&self) -> Option<&[u8]> {
        match self {
            FoldingSchedule::Constant { .. } => None,
            FoldingSchedule::Dynamic { schedule } => Some(schedule),
        }
    }

    pub fn get_max_remainder_degree(&self) -> Option<u8> {
        match self {
            FoldingSchedule::Constant {
                fri_remainder_max_degree,
                ..
            } => Some(*fri_remainder_max_degree),
            FoldingSchedule::Dynamic { schedule: _ } => None,
        }
    }

    // Utility methods
    // -------------------------------------------------------------------------------------------

    /// Returns true if the schedule is constant, false otherwise.
    pub fn is_constant(&self) -> bool {
        matches!(self, FoldingSchedule::Constant { .. })
    }

    /// Returns true if the schedule is dynamic, false otherwise.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, FoldingSchedule::Dynamic { .. })
    }

    /// Returns the number of layers in the schedule if the schedule is dynamic, None otherwise.
    pub fn len_schedule(&self) -> Option<usize> {
        match self {
            FoldingSchedule::Dynamic { schedule, .. } => Some(schedule.len()),
            _ => None,
        }
    }
}

// FRI SCHEDULE IMPLEMENTATION
// ================================================================================================

impl Serializable for FoldingSchedule {
    // Serializes `FoldingSchedule` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            FoldingSchedule::Constant {
                fri_folding_factor,
                fri_remainder_max_degree,
            } => {
                target.write_u8(1);
                target.write_u8(*fri_folding_factor);
                target.write_u8(*fri_remainder_max_degree);
            }
            FoldingSchedule::Dynamic { schedule } => {
                target.write_u8(2);
                target.write_u8(schedule.len() as u8);
                for factor in schedule {
                    target.write_u8(*factor);
                }
            }
        }
    }
}

impl Deserializable for FoldingSchedule {
    // Reads a `FoldingSchedule` from the specified `source`.
    fn read_from<W: ByteReader>(source: &mut W) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => Ok(FoldingSchedule::Constant {
                fri_folding_factor: source.read_u8()?,
                fri_remainder_max_degree: source.read_u8()?,
            }),
            2 => {
                let len = source.read_u8()?;
                let mut schedule = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    schedule.push(source.read_u8()?);
                }
                Ok(FoldingSchedule::Dynamic { schedule })
            }
            value => Err(DeserializationError::InvalidValue(format!(
                "value {value} cannot be deserialized as FoldingSchedule enum"
            ))),
        }
    }
}
