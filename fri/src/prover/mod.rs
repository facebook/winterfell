// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod monolith;
pub use monolith::FriProver;

mod channel;
pub use channel::{DefaultProverChannel, ProverChannel};

#[cfg(test)]
mod tests;
