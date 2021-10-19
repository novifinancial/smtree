// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Various utility functions.

use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt::Debug;
use std::mem;

use crate::pad_secret::Secret;
use crate::{
    error::DecodingError,
    index::{TreeIndex, MAX_HEIGHT},
    traits::{Mergeable, Paddable, ProofExtractable, Rand, Serializable},
    tree::{NodeType, SparseMerkleTree},
};

const BYTE_SIZE: usize = 8;
const BYTE_NUM: usize = MAX_HEIGHT / BYTE_SIZE;

// NIL NODE STRUCT
// ================================================================================================
/// A Nil SMT node.
#[derive(Default, Clone, Debug)]
pub struct Nil;

impl PartialEq for Nil {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for Nil {}

impl Mergeable for Nil {
    fn merge(_lch: &Nil, _rch: &Nil) -> Nil {
        Nil
    }
}

impl Paddable for Nil {
    fn padding(_idx: &TreeIndex, _secret: &Secret) -> Nil {
        Nil
    }
}

impl Serializable for Nil {
    fn serialize(&self) -> Vec<u8> {
        Vec::new()
    }
    fn deserialize_as_a_unit(_bytes: &[u8], _begin: &mut usize) -> Result<Nil, DecodingError> {
        Ok(Nil::default())
    }
}

impl ProofExtractable for Nil {
    type ProofNode = Nil;
    fn get_proof_node(&self) -> Self::ProofNode {
        Nil
    }
}

// PUBLIC UTILITY FUNCTIONS
// ================================================================================================

/// Converts the provided `num` into the specified number of bytes in little-endian byte order.
///
/// Panics if the specified number of bytes is not sufficient to encode `num`.
pub fn usize_to_bytes(num: usize, byte_num: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    let mut tmp = num;
    while tmp > 0 {
        vec.push((tmp & u8::MAX as usize) as u8);
        tmp >>= BYTE_SIZE;
    }
    if vec.len() > byte_num {
        panic!("Error when encoding usize to bytes: number of bytes exceeds the input limit.");
    } else {
        vec.resize(byte_num, 0u8)
    }
    vec
}

/// Reads `byte_num` bytes from `bytes` slice starting at `begin` index and interprets them
/// as a usize in little-ending byte order.
pub fn bytes_to_usize(
    bytes: &[u8],
    byte_num: usize,
    begin: &mut usize,
) -> Result<usize, DecodingError> {
    if byte_num > mem::size_of::<usize>() {
        return Err(DecodingError::TooManyEncodedBytes);
    }

    if bytes.len() - *begin < byte_num {
        return Err(DecodingError::BytesNotEnough);
    }

    let mut num = 0usize;
    for i in (*begin..*begin + byte_num).rev() {
        num <<= BYTE_SIZE;
        num += bytes[i] as usize;
    }
    *begin += byte_num;
    Ok(num)
}

/// Generates a set of random pairs of tree indexes and values. The function intended for use
/// in testing and benchmarking code.
pub fn generate_sorted_index_value_pairs<V: Default + Clone + Rand>(
    height: usize,
    leaf_num: usize,
) -> Vec<(TreeIndex, V)> {
    // TODO: check that leaf_num <= 2^height

    let mut list: Vec<(TreeIndex, V)> = Vec::new();
    let mut set: BTreeSet<TreeIndex> = BTreeSet::new();
    for _i in 0..leaf_num {
        loop {
            let mut idx = TreeIndex::zero(height);
            idx.randomize();
            if !set.contains(&idx) {
                set.insert(idx);
                break;
            }
        }
    }
    let mut value = V::default();
    for idx in set {
        value.randomize();
        list.push((idx, value.clone()));
    }
    list
}

/// Convert a u64 to TreeIndex.
pub fn tree_index_from_u64(height: usize, idx: u64) -> TreeIndex {
    let mut new_pos = [0u8; BYTE_NUM];
    let mut idx = idx;
    for i in (0..height).rev() {
        new_pos[i / BYTE_SIZE] += ((idx & 1) << (i % BYTE_SIZE)) as u8;
        idx >>= 1;
    }
    TreeIndex::new(height, new_pos)
}

#[deprecated(
    since = "0.1.1",
    note = "Please use the tree_index_from_u64 function instead"
)]
pub fn set_pos_best(height: usize, idx: u32) -> TreeIndex {
    tree_index_from_u64(height, idx as u64)
}

#[deprecated(since = "0.1.1")]
pub fn set_pos_worst(height: usize, mut idx: u32, depth: usize) -> TreeIndex {
    let mut new_pos = [0u8; BYTE_NUM];
    for i in (0..depth).rev() {
        new_pos[i / BYTE_SIZE] += ((idx & 1) << (i % BYTE_SIZE)) as u8;
        idx >>= 1;
    }
    TreeIndex::new(height, new_pos)
}

type Set = HashSet<TreeIndex>;

/// Prints out the structure of the provided `tree`, which makes it visually easy to see the
/// placement of leaf, padding, and internal nodes.
pub fn print_output<P: Clone + Default + Mergeable + Paddable + ProofExtractable>(
    tree: &SparseMerkleTree<P>,
) where
    <P as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    // TODO: check the size of the tree
    let mut leaves = Set::new();
    let mut paddings = Set::new();
    let mut internals = Set::new();
    let nodes = tree.get_index_node_pairs();
    for (key, node) in nodes.iter() {
        match node.get_node_type() {
            NodeType::Leaf => {
                leaves.insert(*key);
            }
            NodeType::Padding => {
                paddings.insert(*key);
            }
            NodeType::Internal => {
                internals.insert(*key);
            }
        }
    }

    println!("Tree height: {}", tree.get_height());
    print_node(
        1 << tree.get_height(),
        &TreeIndex::zero(0),
        &leaves,
        &paddings,
        &internals,
    );
    println!();
    for i in 1..=tree.get_height() {
        print!("{:>1$}", "/", 1 << tree.get_height() >> i);
        for j in 1..1 << i {
            if (j & 1) == 1 {
                print!("{:>1$}", "\\", 1 << tree.get_height() >> (i - 1));
            } else {
                print!("{:>1$}", "/", 1 << tree.get_height() >> (i - 1));
            }
        }
        println!();

        print_node(
            1 << tree.get_height() >> i,
            &TreeIndex::zero(i),
            &leaves,
            &paddings,
            &internals,
        );
        for j in 1..1 << i {
            let pos = tree_index_from_u64(i, j as u64);
            print_node(
                1 << tree.get_height() >> (i - 1),
                &pos,
                &leaves,
                &paddings,
                &internals,
            );
        }
        println!();
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn print_node(spaces: usize, idx: &TreeIndex, leaves: &Set, paddings: &Set, internals: &Set) {
    if leaves.contains(idx) {
        print!("{:>1$}", "*", spaces);
    } else if paddings.contains(idx) {
        print!("{:>1$}", "o", spaces);
    } else if internals.contains(idx) {
        print!("{:>1$}", "^", spaces);
    } else {
        print!("{:>1$}", ".", spaces);
    }
}

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub(crate) fn log_2(x: u32) -> u32 {
    let offset = if x.is_power_of_two() { 1 } else { 0 };
    assert!(x > 0);
    num_bits::<u32>() as u32 - x.leading_zeros() - offset
}
