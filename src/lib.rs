// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A library supplying paddable sparse Merkle tree.

pub mod error;
pub mod index;
pub mod node_template;
pub mod pad_secret;
pub mod proof;
pub mod traits;
pub mod tree;
pub mod utils;

#[cfg(test)]
mod tests;
