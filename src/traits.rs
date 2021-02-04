// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This module provides a generic set of traits
//! for customizing nodes in the sparse Merkle tree.
//!
//! For examples on how to use these traits,
//! see the implementations of the [example](../example/index.html) module.

use crate::{error::DecodingError, index::TreeIndex};
use digest::{BlockInput, FixedOutput, Reset, Update};

// A convenience trait for digest bounds used throughout the library
pub trait Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone {}

impl<T: Update + BlockInput + FixedOutput + Reset + Default + Clone> Hash for T {}

/// Trait for merging two child nodes to extract the parent node in the SMT.
pub trait Mergeable {
    /// A function to merge two child nodes as the parent node in the SMT.
    fn merge(lch: &Self, rch: &Self) -> Self;
}

/// Trait for generating a padding node in the SMT.
pub trait Paddable {
    /// When the tree node of the input index doesn't exist,
    /// we need to construct a padding node at that position.
    fn padding(idx: &TreeIndex) -> Self;
}

/// Trait for getting the type name of tree nodes in the SMT.
pub trait TypeName {
    /// A function returning the type name of tree nodes in the SMT for logging purpose.
    fn get_name() -> String {
        "Name".to_owned()
    }
}

/// Trait for generating a random value.
pub trait Rand {
    /// A function returning a random value of the corresponding type.
    fn randomize(&mut self) {}
}

/// Trait for extracting a node with necessary information in Merkle proofs from a tree node.
pub trait ProofExtractable {
    /// The type of a node with necessary information in Merkle proofs.
    type ProofNode;

    /// Extracting a proof node from a tree node.
    fn get_proof_node(&self) -> Self::ProofNode;
}

/// Trait for prove and verify padding nodes at random sampling.
pub trait PaddingProvable {
    /// The data type of the proof for a padding node.
    type PaddingProof;

    /// Generate the proof for padding node at given tree index.
    fn prove_padding_node(&self, idx: &TreeIndex) -> Self::PaddingProof;

    /// Verify the proof for a padding node at given tree index with associated node data in the Merkle proof.
    ///
    /// Note that ```node``` is the node data in the Merkle proof,
    /// ```proof``` is the proof of the padding node,
    /// ```idx``` is the tree index.
    fn verify_padding_node(
        node: &<Self as ProofExtractable>::ProofNode,
        proof: &Self::PaddingProof,
        idx: &TreeIndex,
    ) -> bool
    where
        Self: ProofExtractable;
}

/// Trait for encoding.
pub trait Serializable {
    /// Encode the input object.
    fn serialize(&self) -> Vec<u8>
    where
        Self: std::marker::Sized;

    /// Decode some of the input bytes starting from the ```begin``` position as a ```Self``` object,
    /// possibly with some bytes at the end left.
    ///
    /// Note that ```bytes``` is the input bytes to be decoded,
    /// and ```begin``` is the beginning position of ```bytes```.
    /// At the end of the execution,
    /// ```begin``` should point to the first byte not decoded.
    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError>
    where
        Self: std::marker::Sized;

    /// Decode the input bytes as a ```Self``` object, using up all bytes.
    ///
    /// The default implementation of this method is to first call ```deserialize_as_a_unit``` with ```begin = 0```.
    /// If any error message is returned, return the error message directly.
    /// If ```begin != bytes.len()```, which means there are bytes not used for decoding,
    /// return [DecodingError::TooManyEncodedBytes](../error/enum.DecodingError.html#variant.TooManyEncodedBytes).
    /// Otherwise, return the object of decoding result.
    fn deserialize(bytes: &[u8]) -> Result<Self, DecodingError>
    where
        Self: std::marker::Sized,
    {
        let mut begin = 0usize;
        let res = Self::deserialize_as_a_unit(bytes, &mut begin);
        if let Err(e) = res {
            return Err(e);
        }
        // Check if all input bytes are used for decoding.
        if begin != bytes.len() {
            println!("{}, {}", begin, bytes.len());
            return Err(DecodingError::TooManyEncodedBytes);
        }
        res
    }
}

/// Trait for generating and verifying inclusion proofs.
pub trait InclusionProvable {
    /// The data type of a node with necessary information in Merkle proofs.
    type ProofNodeType;
    /// The data type of the Merkle tree.
    type TreeStruct;

    /// Generate an inclusion proof for the input list of indexes.
    fn generate_inclusion_proof(tree: &Self::TreeStruct, list: &[TreeIndex]) -> Option<Self>
    where
        Self: std::marker::Sized;

    /// Verify the inclusion proof according to the leave nodes and the root.
    fn verify_inclusion_proof(
        &self,
        leaves: &[Self::ProofNodeType],
        root: &Self::ProofNodeType,
    ) -> bool;
}

/// Trait for random sampling and verifying sampling proofs.
pub trait RandomSampleable {
    /// The data type of a node with necessary information in Merkle proofs.
    type ProofNodeType;
    /// The data type of the Merkle tree.
    type TreeStruct;

    /// Random sampling.
    /// Returns the random sampling proof of the input index.
    ///
    /// If the input index is a real leaf node in the Merkle tree, return the inclusion proof of the leaf node.
    ///
    /// Otherwise, find the closest real leaf nodes left to and right to the input index respectively.
    /// Return the inclusion proof of the closest nodes if exist,
    /// together with proofs of necessary padding nodes showing that the leaf nodes are the closest.
    fn random_sampling(tree: &Self::TreeStruct, idx: &TreeIndex) -> Self;

    /// Verify the random sampling proof.
    fn verify_random_sampling_proof(&self, root: &Self::ProofNodeType) -> bool;
}
