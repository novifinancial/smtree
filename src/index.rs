// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This module provides definitions of tree index in an SMT,
//! and operations to get the index of the parent/sibling/child/etc. of a given tree node.

use std::cmp::Ordering;

use rand::Rng;

use crate::{
    error::DecodingError,
    tree::ChildDir,
    utils::{bytes_to_usize, tree_index_from_u32, usize_to_bytes},
};

// We store the position of each tree node in a byte array of size 32,
// thus the maximum height could be 8  * 32 = 256.
const BYTE_SIZE: usize = 8;
const BYTE_NUM: usize = 32;

/// The maximum height of a SMT is 256 (not including the root node),
/// so the maximum number of leaves is ```2^256```.
pub const MAX_HEIGHT: usize = BYTE_SIZE * BYTE_NUM;

// The number of bytes for encoding the height field.
const HEIGHT_BYTE_NUM: usize = 2;

/// The index of a tree node includes the height (the root with height 0),
/// and the path from the root to the node.
///
/// The path is a bit array, and each bit indicates which direction the child node goes.
///
/// The i-th bit being 0 indicates that the node at height i+1 in the path
/// is the left child of the node at height i, and 1 indicates the right child.
#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TreeIndex {
    // The height of the node.
    height: usize,

    // The position of the node, the least significant bit indicates
    // the direction from the root node, 0 for left, 1 for right.
    path: [u8; BYTE_NUM],
}

/// If two indexes have the same height, the right-side one is greater.
///
/// If two indexes have different heights, the one with smaller height is greater,
/// i.o.w., the higher the node in the SMT, the greater its index is.
impl Ord for TreeIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.height.cmp(&other.get_height()) {
            Ordering::Greater => Ordering::Less,
            Ordering::Less => Ordering::Greater,
            Ordering::Equal => {
                for i in 0..self.height {
                    match self.get_bit(i).cmp(&other.get_bit(i)) {
                        Ordering::Greater => {
                            return Ordering::Greater;
                        }
                        Ordering::Less => {
                            return Ordering::Less;
                        }
                        Ordering::Equal => {
                            continue;
                        }
                    }
                }
                Ordering::Equal
            }
        }
    }
}

/// If two indexes have the same height, the right-side one is greater.
///
/// If two indexes have different heights, the one with smaller height is greater,
/// i.o.w., the higher the node in the SMT, the greater its index is.
impl PartialOrd for TreeIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TreeIndex {
    /// The constructor.
    ///
    /// Panics if the input height exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html),
    pub fn new(height: usize, pos: [u8; BYTE_NUM]) -> TreeIndex {
        if height > MAX_HEIGHT {
            panic!("{}", DecodingError::ExceedMaxHeight);
        }
        TreeIndex { height, path: pos }
    }

    /// Construct TreeIndex from a u32 leaf position.
    pub fn from_u32(height: usize, pos: u32) -> TreeIndex {
        if height > MAX_HEIGHT {
            panic!("{}", DecodingError::ExceedMaxHeight);
        }
        // Check if index fits to the tree.
        if 32 - pos.leading_zeros() > height as u32 {
            panic!("{}", DecodingError::IndexOverflow);
        }
        tree_index_from_u32(height, pos)
    }

    /// Returns a tree index of the left-most node (all bits in the path being 0) at the given height.
    ///
    /// Panics if the input height exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn zero(height: usize) -> TreeIndex {
        TreeIndex::new(height, [0u8; BYTE_NUM])
    }

    /// Returns the height of a tree index.
    pub fn get_height(&self) -> usize {
        self.height
    }

    /// Set the height of a tree index.
    ///
    /// Panics if the input height exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn set_height(&mut self, height: usize) {
        if height > MAX_HEIGHT {
            panic!("{}", DecodingError::ExceedMaxHeight);
        }
        self.height = height;
    }

    /// Returns the path of a tree index.
    pub fn get_path(&self) -> [u8; BYTE_NUM] {
        self.path
    }

    /// Get the i-th bit in the path.
    ///
    /// Panics if queried bit index is out of the range ```[0, height-1]```.
    pub fn get_bit(&self, i: usize) -> u8 {
        if i >= self.height {
            panic!("The input index is out of range, thus the queried bit doesn't exist.");
        }
        (self.path[i / BYTE_SIZE] >> (i % BYTE_SIZE)) & 1
    }

    /// Returns the last bit in the path of the tree index.
    ///
    /// Panics if the tree index has height 0 thus the bit doesn't exist.
    pub fn get_last_bit(self) -> u8 {
        if self.height == 0 {
            panic!("The height is 0, thus the queried bit doesn't exist.");
        }
        self.get_bit(self.height - 1)
    }

    /// Returns a tree index with the input height and the path being a prefix of the self path.
    ///
    /// Panics if the input height exceeds the height of the index.
    pub fn get_prefix(&self, height: usize) -> TreeIndex {
        if height > self.height {
            panic!("The input height exceeds the height of the tree index.");
        }
        let mut index = TreeIndex::new(height, self.path);
        let mut len = height;
        let mut flag: u32 = (1 << 8) - 1;
        for i in 0..BYTE_NUM {
            if len < BYTE_SIZE {
                flag = (1 << len) - 1;
                len = 0;
            } else {
                len -= 8;
            }
            index.path[i] &= flag as u8;
        }
        index
    }

    /// Randomly samples a path.
    pub fn randomize(&mut self) {
        let mut rng = rand::thread_rng();
        for i in 0..BYTE_NUM {
            self.path[i] = rng.gen();
        }
        *self = self.get_prefix(self.height);
    }

    /// Returns the tree index of the left child of a node.
    ///
    /// Panics if the height of the child node exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn get_lch_index(&self) -> TreeIndex {
        if self.height == MAX_HEIGHT {
            panic!("The index already has the maximum height.");
        }
        let mut pos = self.path;
        // Change the new bit for the left child as 0.
        pos[self.height / BYTE_SIZE] &= u8::MAX - (1 << (self.height % BYTE_SIZE));
        TreeIndex::new(self.height + 1, self.path)
    }

    /// Returns the tree index of the right child of a node.
    ///
    /// Panics if the height of the child node exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn get_rch_index(&self) -> TreeIndex {
        if self.height == MAX_HEIGHT {
            panic!("The index already has the maximum height.");
        }
        let mut pos = self.path;
        // Change the new bit for the right child as 1.
        pos[self.height / BYTE_SIZE] |= 1 << (self.height % BYTE_SIZE);
        TreeIndex::new(self.height + 1, pos)
    }

    /// Returns the tree index of the child in the input direction of a node.
    ///
    /// Panics if the height of the child node exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn get_child_index_by_dir(&self, dir: ChildDir) -> TreeIndex {
        if dir == ChildDir::Left {
            self.get_lch_index()
        } else {
            self.get_rch_index()
        }
    }

    /// Returns the tree index of the sibling of a node.
    ///
    /// Panics if the queried node is the root, which means that the sibling doesn't exist.
    pub fn get_sibling_index(&self) -> TreeIndex {
        if self.height == 0 {
            panic!("The root doesn't have a sibling.");
        }
        let mut pos = self.path;
        // Change the last bit as the opposite.
        pos[(self.height - 1) / BYTE_SIZE] ^= 1 << ((self.height - 1) % BYTE_SIZE);
        TreeIndex::new(self.height, pos)
    }

    /// Returns the tree index of the parent of a node.
    ///
    /// Panics if the queried node is the root, which means that the parent doesn't exist.
    pub fn get_parent_index(&self) -> TreeIndex {
        if self.height == 0 {
            panic!("The root doesn't have a parent.");
        }
        self.get_prefix(self.height - 1)
    }

    // Returns the number of bytes for encoding the bit array by the number of bits.
    fn get_byte_num_by_bit(bit_num: usize) -> usize {
        let mut byte_num = bit_num / BYTE_SIZE;
        if bit_num % BYTE_SIZE > 0 {
            byte_num += 1;
        }
        byte_num
    }

    // Returns the left/right index to the input index, direction depending on the input.
    fn get_dir_index(&self, dir: ChildDir) -> Option<TreeIndex> {
        let mut opp_dir = ChildDir::Left;
        let mut dir_bit = 1;
        if dir == ChildDir::Left {
            opp_dir = ChildDir::Right;
            dir_bit = 0;
        }

        // Gets the closest ancestor that has a dir child not on the path from the root to the input index.
        // Retrieve the dir child, which is the root of the subtree that contains the dir index.
        let mut index = *self;
        for i in (0..self.height).rev() {
            if self.get_bit(i) == 1 - dir_bit {
                index = index.get_prefix(i).get_child_index_by_dir(dir);
                break;
            }
        }
        // Gets the opp_dir-most child, which is the desired index.
        while index.get_height() < self.height {
            index = index.get_child_index_by_dir(opp_dir);
        }

        if index == *self {
            // If the result index is the same as the input, the input is the dir-most leaf.
            // So the dir node to the input doesn't exist, return None.
            None
        } else {
            Some(index)
        }
    }

    /// Returns the index on the left of self.
    pub fn get_left_index(&self) -> Option<TreeIndex> {
        self.get_dir_index(ChildDir::Left)
    }

    /// Returns the index on the right of self.
    pub fn get_right_index(&self) -> Option<TreeIndex> {
        self.get_dir_index(ChildDir::Right)
    }

    /// Encode a list of tree indexes in the format: ```height || path || ... || path```.
    ///
    /// If the input list is empty, return empty vector.
    pub fn serialize(list: &[TreeIndex]) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        // Returns empty vector if the input list is empty.
        if list.is_empty() {
            return vec;
        }

        // Encode the height.
        let height = list[0].get_height();
        let mut height_bytes = usize_to_bytes(height, HEIGHT_BYTE_NUM);
        vec.append(&mut height_bytes);

        // Encode all the paths, each takes ceiling(height/8) bytes.
        let byte_num = Self::get_byte_num_by_bit(height);
        for item in list {
            vec.extend_from_slice(&item.get_path()[0..byte_num]);
        }
        vec
    }

    /// Decode input bytes (```height || path || ... || path```) as a list of tree indexes.
    ///
    /// Note that ```bytes``` is the input bytes,
    /// ```num``` is the target number of tree indexes,
    /// ```begin``` is the beginning position of ```bytes```.
    ///
    /// If the decoded height exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html),
    /// return [DecodingError::ExceedMaxHeight](../error/enum.DecodingError.html#variant.ExceedMaxHeight).
    ///
    /// If the bytes are not enough for decoding,
    /// return [DecodingError::BytesNotEnough](../error/enum.DecodingError.html#variant.BytesNotEnough).
    pub fn deserialize_as_a_unit(
        bytes: &[u8],
        num: usize,
        begin: &mut usize,
    ) -> Result<Vec<TreeIndex>, DecodingError> {
        // Return empty list if the input byte is empty.
        if bytes.len() - *begin == 0 && num == 0 {
            return Ok(Vec::new());
        }

        // Decode the height.
        let height = bytes_to_usize(bytes, HEIGHT_BYTE_NUM, begin);
        if let Err(e) = height {
            return Err(e);
        }
        let height = height.unwrap();
        if height > MAX_HEIGHT {
            return Err(DecodingError::ExceedMaxHeight);
        }

        // Check if the bytes are enough for the target number of indexes.
        let index_byte_num = Self::get_byte_num_by_bit(height);
        if (bytes.len() - *begin) < index_byte_num * num {
            return Err(DecodingError::BytesNotEnough);
        }

        // Decode each path in the indexes.
        let mut vec: Vec<TreeIndex> = Vec::new();
        for _i in 0..num {
            let mut path = [0u8; BYTE_NUM];
            for item in path.iter_mut().take(index_byte_num) {
                *item = bytes[*begin];
                *begin += 1;
            }
            vec.push(TreeIndex::new(height, path));
        }

        Ok(vec)
    }
}
