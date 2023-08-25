// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldingSchedule {
    Constant {
        factor: u8,
        remainder_max_degree: u8,
    },
    Dynamic {
        schedule: Vec<u8>,
    },
}

impl FoldingSchedule {
    // Constructors
    // -------------------------------------------------------------------------------------------

    pub fn new_constant(factor: u8, remainder_max_degree: u8) -> Self {
        FoldingSchedule::Constant {
            factor,
            remainder_max_degree,
        }
    }

    pub fn new_dynamic(schedule: Vec<u8>) -> Self {
        FoldingSchedule::Dynamic { schedule }
    }

    // Accessors
    // -------------------------------------------------------------------------------------------

    pub fn get_factor(&self) -> Option<u8> {
        match self {
            FoldingSchedule::Constant { factor, .. } => Some(*factor),
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
                remainder_max_degree,
                ..
            } => Some(*remainder_max_degree),
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
