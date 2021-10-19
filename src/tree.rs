// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This module provides definitions of the tree node and the paddable sparse Merkle tree,
//! together with methods of tree generation/update, Merkle proof generation, and random sampling.

use std::fmt::Debug;

use crate::pad_secret::{Secret, ALL_ZEROS_SECRET};
use crate::utils::tree_index_from_u64;
use crate::{
    error::{DecodingError, TreeError},
    index::{TreeIndex, MAX_HEIGHT},
    traits::{Mergeable, Paddable, ProofExtractable, Serializable},
    utils::{log_2, Nil},
};

/// The direction of a child node, either left or right.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum ChildDir {
    Left,
    Right,
}

/// The type of a tree node:
/// an internal node has child nodes;
/// a padding node has padding value and no child node;
/// a leaf node has real value and no child node.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    /// An internal node has child nodes.
    Internal,
    /// A padding node has padding value and no child node.
    Padding,
    /// A leaf node has real value and no child node.
    Leaf,
}

impl Default for NodeType {
    /// The default NodeType is [NodeType::Internal](../tree/enum.NodeType.html#variant.Internal)
    fn default() -> NodeType {
        NodeType::Internal
    }
}

/// A node in the SMT, consisting of the links to its parent, child nodes, value and node type.
#[derive(Debug, Clone, Default)]
pub struct TreeNode<V> {
    // The reference to its parent/left child/right child.
    // Being ```None``` for non-existing node.
    parent: Option<usize>,
    lch: Option<usize>,
    rch: Option<usize>,

    value: V,
    // The value of the tree node.
    node_type: NodeType, // The type of the node.
}

impl<V: Clone + Default + Mergeable + Paddable> TreeNode<V> {
    /// The constructor.
    pub fn new(node_type: NodeType) -> TreeNode<V> {
        TreeNode {
            parent: None,
            lch: None,
            rch: None,
            value: V::default(),
            node_type,
        }
    }

    /// Returns the reference to the left child of the tree node.
    ///
    /// If the child node doesn't exist, return ```None```.
    pub fn get_lch(&self) -> Option<usize> {
        self.lch
    }

    /// Returns the reference to the right child of the tree node.
    ///
    /// If the child node doesn't exist, return ```None```.
    pub fn get_rch(&self) -> Option<usize> {
        self.rch
    }

    /// Returns the reference to the child in the input direction of the tree node.
    ///
    /// If the child node doesn't exist, return ```None```.
    pub fn get_child_by_dir(&self, dir: ChildDir) -> Option<usize> {
        match dir {
            ChildDir::Left => self.lch,
            ChildDir::Right => self.rch,
        }
    }

    /// Returns the reference to the parent of the tree node.
    ///
    /// If the parent node doesn't exist, return ```None```.
    pub fn get_parent(&self) -> Option<usize> {
        self.parent
    }

    /// Returns the node type.
    pub fn get_node_type(&self) -> &NodeType {
        &self.node_type
    }

    /// Returns the value of the tree node.
    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Set the reference to the parent node as the input.
    pub fn set_parent(&mut self, idx: usize) {
        self.parent = Some(idx);
    }

    /// Set the reference to the left child as the input.
    pub fn set_lch(&mut self, idx: usize) {
        self.lch = Some(idx);
    }

    /// Set the reference to the right child as the input.
    pub fn set_rch(&mut self, idx: usize) {
        self.rch = Some(idx);
    }

    /// Set the value of the tree node as the input.
    pub fn set_value(&mut self, val: V) {
        self.value = val;
    }

    /// Set the tree node type as the input.
    pub fn set_node_type(&mut self, x: NodeType) {
        self.node_type = x;
    }
}

/// Paddable sparse Merkle tree.
#[derive(Default, Debug)]
pub struct SparseMerkleTree<P> {
    height: usize,
    // The height of the SMT.
    root: usize,
    // The reference to the root of the SMT.
    nodes: Vec<TreeNode<P>>, // The values of tree nodes.
}

impl<P: Clone + Default + Mergeable + Paddable + ProofExtractable> SparseMerkleTree<P>
where
    <P as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    /// The constructor.
    ///
    /// Panics if the input height exceeds [MAX_HEIGHT](../index/constant.MAX_HEIGHT.html).
    pub fn new(height: usize) -> SparseMerkleTree<P> {
        if height > MAX_HEIGHT {
            panic!("{}", DecodingError::ExceedMaxHeight);
        }
        let mut root_node = TreeNode::<P>::new(NodeType::Padding);
        root_node.set_value(P::padding(&TreeIndex::zero(0), &ALL_ZEROS_SECRET));
        SparseMerkleTree {
            height,
            root: 0,
            nodes: vec![root_node],
        }
    }

    /// A simple Merkle tree constructor, where all items are added next to each other from left to
    /// right. Note that zero padding secret is used and the height depends on the input list size.
    /// Use this helper constructor only when simulating a plain Merkle tree.
    pub fn new_merkle_tree(list: &[P]) -> SparseMerkleTree<P> {
        let height = log_2(list.len() as u32) as usize;
        let mut smtree = Self::new(height);
        smtree.build_merkle_tree_zero_padding(list);
        smtree
    }

    /// Returns the height of the SMT.
    pub fn get_height(&self) -> usize {
        self.height
    }

    /// Returns the number of nodes in the SMT.
    pub fn get_nodes_num(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the tree node by reference.
    ///
    /// Panics if the reference is out of range.
    pub fn get_node_by_ref(&self, link: usize) -> &TreeNode<P> {
        if link > self.nodes.len() {
            panic!("Input reference out of range");
        }
        &self.nodes[link]
    }

    /// Returns the tree node by references.
    ///
    /// Panics if the reference is out of range.
    pub fn get_node_raw_by_refs(&self, list: &[usize]) -> Vec<&P> {
        let mut vec = Vec::new();
        for link in list {
            vec.push(self.get_node_by_ref(*link).get_value());
        }
        vec
    }

    /// Returns the tree node by references.
    ///
    /// Panics if the reference is out of range.
    pub fn get_node_proof_by_refs(&self, list: &[usize]) -> Vec<P::ProofNode> {
        let mut vec = Vec::new();
        for link in list {
            vec.push(self.get_node_by_ref(*link).get_value().get_proof_node());
        }
        vec
    }

    /// Returns the reference to the root ndoe.
    pub fn get_root_ref(&self) -> usize {
        self.root
    }

    /// Returns the raw data of the root.
    pub fn get_root_raw(&self) -> &P {
        self.get_node_by_ref(self.root).get_value()
    }

    /// Returns the data of the root that is visible in the Merkle proof.
    pub fn get_root(&self) -> <P as ProofExtractable>::ProofNode {
        self.get_root_raw().get_proof_node()
    }

    // Returns the ref and tree index of the ancestor that is closest to the input index in the tree.
    // Panics if the height of the input index doesn't match with that of the tree.
    pub fn get_closest_ancestor_ref_index(&self, idx: &TreeIndex) -> (usize, TreeIndex) {
        // Panics if the the height of the input index doesn't match with the tree height.
        if idx.get_height() != self.height {
            panic!("{}", TreeError::HeightNotMatch);
        }

        let mut ancestor = self.root;
        let mut ancestor_idx = *idx;
        // Navigate by the tree index from the root node to the queried node.
        for i in 0..self.height {
            if idx.get_bit(i) == 0 {
                // The queried index is in the left sub-tree.
                if self.nodes[ancestor].get_lch().is_none() {
                    // Terminates at current bit if there is no child node to follow along.
                    ancestor_idx = ancestor_idx.get_prefix(i);
                    break;
                }
                ancestor = self.nodes[ancestor].get_lch().unwrap();
            } else {
                // The queried index is in the right sub-tree.
                if self.nodes[ancestor].get_rch().is_none() {
                    // Terminates at current bit if there is no child node to follow along.
                    ancestor_idx = ancestor_idx.get_prefix(i);
                    break;
                }
                ancestor = self.nodes[ancestor].get_rch().unwrap();
            }
        }
        (ancestor, ancestor_idx)
    }

    /// Returns the tree node of a queried tree index.
    ///
    /// Panics if the the height of the input index doesn't match with the tree height.
    ///
    /// If the node doesn't exist, return ```None```.
    pub fn get_leaf_by_index(&self, idx: &TreeIndex) -> Option<&TreeNode<P>> {
        let (node, node_idx) = self.get_closest_ancestor_ref_index(idx);
        if node_idx.get_height() < self.height {
            None
        } else {
            Some(&self.nodes[node])
        }
    }

    /// Returns the index-reference pairs of all tree nodes in a BFS order.
    pub fn get_index_ref_pairs(&self) -> Vec<(TreeIndex, usize)> {
        // Run a BFS to go through all tree nodes and
        // generate the tree index for each node in the meanwhile.
        // The first node in the vector is the root.
        let mut vec: Vec<(TreeIndex, usize)> = vec![(TreeIndex::zero(0), self.root)];
        let mut head: usize = 0;
        while head < vec.len() {
            // If there is a left child, add it to the vector.
            if let Some(x) = self.nodes[vec[head].1].get_lch() {
                vec.push((vec[head].0.get_lch_index(), x));
            }
            // If there is a right child, add it to the vector.
            if let Some(x) = self.nodes[vec[head].1].get_rch() {
                vec.push((vec[head].0.get_rch_index(), x));
            }
            // Move on to the next node in the vector.
            head += 1;
        }
        vec
    }

    /// Returns the index-node pairs of all tree nodes.
    pub fn get_index_node_pairs(&self) -> Vec<(TreeIndex, &TreeNode<P>)> {
        let mut vec: Vec<(TreeIndex, &TreeNode<P>)> = Vec::new();
        let index_ref = self.get_index_ref_pairs();
        for (index, refer) in index_ref {
            vec.push((index, &self.nodes[refer]));
        }
        vec
    }

    // Returns the index-node pairs of the input node type.
    fn get_nodes_of_type(&self, _node_type: NodeType) -> Vec<(TreeIndex, &TreeNode<P>)> {
        let mut vec: Vec<(TreeIndex, &TreeNode<P>)> = Vec::new();
        let nodes = self.get_index_node_pairs();
        for (key, value) in nodes.iter() {
            if _node_type == *value.get_node_type() {
                vec.push((*key, value));
            }
        }
        vec
    }

    /// Returns the index-node pairs of all leaf nodes.
    pub fn get_leaves(&self) -> Vec<(TreeIndex, &TreeNode<P>)> {
        self.get_nodes_of_type(NodeType::Leaf)
    }

    /// Returns the index-node pairs of all padding nodes.
    pub fn get_paddings(&self) -> Vec<(TreeIndex, &TreeNode<P>)> {
        self.get_nodes_of_type(NodeType::Padding)
    }

    /// Returns the index-node pairs of all internal nodes.
    pub fn get_internals(&self) -> Vec<(TreeIndex, &TreeNode<P>)> {
        self.get_nodes_of_type(NodeType::Internal)
    }

    /// Add a new child to the input parent node.
    fn add_child(&mut self, parent: usize, dir: ChildDir) {
        let mut node: TreeNode<P> = TreeNode::new(NodeType::Internal);
        node.set_parent(parent); // Link the parent to the child node.
        self.nodes.push(node);
        let len = self.nodes.len();

        // Link the child to the parent node.
        match dir {
            ChildDir::Left => {
                self.nodes[parent].set_lch(len - 1);
            }
            ChildDir::Right => {
                self.nodes[parent].set_rch(len - 1);
            }
        }
    }

    /// Add a left child to the input parent node.
    fn add_lch(&mut self, parent: usize) {
        self.add_child(parent, ChildDir::Left);
    }

    /// Add a right child to the input parent node.
    fn add_rch(&mut self, parent: usize) {
        self.add_child(parent, ChildDir::Right);
    }

    /// Add a new node in the node list with the input node type and value,
    /// and return the reference to the new node.
    fn add_node(&mut self, node_type: NodeType) -> usize {
        let node = TreeNode::new(node_type);
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    /// Set references to child nodes and the value as the merging result of two child nodes.
    fn set_children(&mut self, parent: &mut TreeNode<P>, lref: usize, rref: usize) {
        parent.set_lch(lref);
        parent.set_rch(rref);

        let lch = self.nodes[lref].get_value();
        let rch = self.nodes[rref].get_value();
        let value = Mergeable::merge(lch, rch);
        parent.set_value(value);
    }

    /// Check if the tree indexes in the list are all valid and sorted.
    ///
    /// If the height of some index doesn't match with the height of the tree,
    /// return [TreeError::HeightNotMatch](../error/enum.TreeError.html#variant.HeightNotMatch).
    ///
    /// If the indexes are not in order,
    /// return [TreeError::IndexNotSorted](../error/enum.TreeError.html#variant.IndexNotSorted).
    ///
    /// If there are duplicated indexes in the list,
    /// return [TreeError::IndexDuplicated](../error/enum.TreeError.html#variant.IndexDuplicated).
    pub fn check_index_list_validity(&self, list: &[(TreeIndex, P)]) -> Option<TreeError> {
        // Check validity of the input list.
        for (i, item) in list.iter().enumerate() {
            // Panic if any index in the list doesn't match with the height of the SMT.
            if item.0.get_height() != self.height {
                return Some(TreeError::HeightNotMatch);
            }
            // Panic if two consecutive indexes after sorting are the same.
            if i > 0 {
                if item.0 < list[i - 1].0 {
                    return Some(TreeError::IndexNotSorted);
                }
                if item.0 == list[i - 1].0 {
                    return Some(TreeError::IndexDuplicated);
                }
            }
        }
        None
    }

    /// Construct SMT from the input list of sorted index-value pairs, index being the sorting key.
    ///
    /// If the height of some index in the input list doesn't match with the height of the tree,
    /// return [TreeError::HeightNotMatch](../error/enum.TreeError.html#variant.HeightNotMatch).
    ///
    /// If the indexes in the input list are not in order,
    /// return [TreeError::IndexNotSorted](../error/enum.TreeError.html#variant.IndexNotSorted).
    ///
    /// If there are duplicated indexes in the list,
    /// return [TreeError::IndexDuplicated](../error/enum.TreeError.html#variant.IndexDuplicated).
    pub fn construct_smt_nodes(
        &mut self,
        list: &[(TreeIndex, P)],
        secret: &Secret,
    ) -> Option<TreeError> {
        // Check the validity of the input list.
        if let Some(x) = self.check_index_list_validity(list) {
            return Some(x);
        }

        // If the input list is empty, no change to the tree.
        if list.is_empty() {
            return None;
        }
        // If the input list is not empty, pop out the original padding root node.
        self.nodes.pop();

        let mut layer: Vec<(TreeIndex, usize)> = Vec::new();
        for (i, item) in list.iter().enumerate() {
            layer.push((item.0, i));
        }

        // Clear the node list.
        self.nodes.clear();

        // Build the tree layer by layer.
        for i in (0..self.height).rev() {
            let mut upper: Vec<(TreeIndex, usize)> = Vec::new(); // The upper layer to be constructed.

            // Build the upper layer starting from the left-most tree index of the current highest existing layer.
            let mut head = 0;
            let length = layer.len();
            while head < length {
                // Get the index and instance of the current child node.
                let node_idx = &layer[head].0;
                let node_link: usize; // Reference to the current node.
                if i == self.height - 1 {
                    // If the current layer is the leaf layer, the node hasn't been added to the tree.
                    // Add the node and refer to it, the last node in the node vector.
                    node_link = self.add_node(NodeType::Leaf);
                    self.nodes[node_link].set_value(list[layer[head].1].1.clone());
                } else {
                    // If the current layer is above the leaf layer, the node is already in the list,
                    // and the reference is the second element of the ```(TreeIndex, usize)``` pair.
                    node_link = layer[head].1;
                }

                // Get the index and instance of the parent node,
                // which is to be added to the upper layer.
                let parent_idx = node_idx.get_parent_index();
                let mut parent = TreeNode::new(NodeType::Internal);

                // Get the index and instance of the sibling node,
                // which is to be merged with the current node to get the value of the current node.
                let sibling_idx = node_idx.get_sibling_index();
                let sibling_link: usize; // Reference to the sibling node.
                if node_idx.get_last_bit() == 0 {
                    // When the current node is the left child of its parent,
                    // its sibling either is the next node in the sorted list,
                    // or doesn't exist yet.
                    if head < length - 1 && layer[head + 1].0 == sibling_idx {
                        // When the sibling is the next node in the list,
                        // retrieve the node reference, and move the pointer to the next node.
                        if i == self.height - 1 {
                            // If the current layer is the leaf layer, the node hasn't been added to the tree.
                            // Add the node and refer to it, the last node in the node vector.
                            sibling_link = self.add_node(NodeType::Leaf);
                            self.nodes[sibling_link].set_value(list[layer[head + 1].1].1.clone());
                        } else {
                            // If the current layer is above the leaf layer, the node is already in the list,
                            // and the reference is the second element of the (TreeIndex, usize) pair.
                            sibling_link = layer[head + 1].1;
                        }
                        head += 1; // Move the pointer to the next node.
                    } else {
                        // When the sibling doesn't exist, generate a new padding node.
                        sibling_link = self.add_node(NodeType::Padding);
                        self.nodes[sibling_link].set_value(Paddable::padding(&sibling_idx, secret));
                    }
                    self.set_children(&mut parent, node_link, sibling_link);
                } else {
                    // When the current node is the right node of its parent,
                    // its sibling doesn't exist yet, so need to generate a new padding node.
                    sibling_link = self.add_node(NodeType::Padding);
                    self.nodes[sibling_link].set_value(Paddable::padding(&sibling_idx, secret));
                    self.set_children(&mut parent, sibling_link, node_link);
                }

                self.nodes.push(parent); // Add the parent node to the node list.
                                         // Link the child nodes to the parent.
                let len = self.nodes.len();
                self.nodes[node_link].set_parent(len - 1);
                self.nodes[sibling_link].set_parent(len - 1);
                upper.push((parent_idx, len - 1)); // Add the new parent node to the upper layer for generating the next layer.

                head += 1; // Done with the current node, move the pointer to the next node.
            }
            layer.clear();
            layer = upper; // Continue to generate the upper layer.
        }
        self.root = self.nodes.len() - 1; // The root is the last node added to the tree.
        None
    }

    /// Build SMT from the input list of sorted index-value pairs, index being the sorting key.
    ///
    /// Panics if the input list is not valid.
    pub fn build(&mut self, list: &[(TreeIndex, P)], secret: &Secret) {
        if let Some(x) = self.construct_smt_nodes(list, secret) {
            panic!("{}", x);
        }
    }

    /// Build simple Merkle tree from the input list with zero padding secret.
    ///
    /// Panics if the input list is not valid.
    fn build_merkle_tree_zero_padding(&mut self, list: &[P]) {
        let tree_list: Vec<(TreeIndex, P)> = list
            .iter()
            .enumerate()
            .map(|(index, p)| (tree_index_from_u64(self.height, index as u64), p.clone()))
            .collect();
        if let Some(x) = self.construct_smt_nodes(&tree_list, &ALL_ZEROS_SECRET) {
            panic!("{}", x);
        }
    }

    /// Retrieve the path from the root to the input leaf node.
    /// If there is any node on the path or its sibling not existing yet, add it to the tree.
    fn retrieve_path(&mut self, key: &TreeIndex) -> Vec<usize> {
        let mut vec: Vec<usize> = Vec::new();

        // Start from the index of the root.
        let mut node_idx = TreeIndex::zero(0);
        let mut node: usize = self.root;
        vec.push(node); // Add the root to the path.

        for i in 0..self.height {
            // Add the left child if not exist.
            if self.nodes[node].get_lch().is_none() {
                self.add_lch(node);
            }
            // Add the right child if not exist.
            if self.nodes[node].get_rch().is_none() {
                self.add_rch(node);
            }

            // Move on to the next node in the path.
            if key.get_bit(i) == 0 {
                // Go to the left child.
                node = self.nodes[node].get_lch().unwrap();
                node_idx = node_idx.get_lch_index();
            } else {
                // Go to the right child.
                node = self.nodes[node].get_rch().unwrap();
                node_idx = node_idx.get_rch_index();
            }
            vec.push(node);
        }
        vec
    }

    /// Update the tree by modifying the leaf node of a certain tree index.
    ///
    /// Panics if the height of the input index doesn't match with that of the tree.
    pub fn update(&mut self, key: &TreeIndex, value: P, secret: &Secret) {
        // Panic if the height of the input tree index doesn't match with that of the tree.
        if key.get_height() != self.height {
            panic!("{}", TreeError::HeightNotMatch)
        }

        let vec = self.retrieve_path(key); // Retrieve the path from the root to the input leaf node.

        // Update the leaf node.
        let len = vec.len();
        self.nodes[vec[len - 1]].set_node_type(NodeType::Leaf);
        self.nodes[vec[len - 1]].set_value(value);

        assert_eq!(len - 1, self.height); // Make sure the length of the path matches with the tree height.

        // Merge nodes to update parent nodes along the path from the leaf to the root.
        let mut idx = *key; // The node index starting from the leaf node.
        for i in (0..len - 1).rev() {
            let parent = vec[i]; // The link to the parent node.
            self.nodes[parent].set_node_type(NodeType::Internal);

            let sibling: usize;
            let sibling_idx: TreeIndex;

            // Get the link to and the index of the sibling node.
            if idx.get_last_bit() == 0 {
                sibling = self.nodes[parent].get_rch().unwrap();
            } else {
                sibling = self.nodes[parent].get_lch().unwrap();
            }
            sibling_idx = idx.get_sibling_index();

            // Adjust the node type of the sibling node.
            match *self.nodes[sibling].get_node_type() {
                NodeType::Leaf => (),
                _ => {
                    // If the sibling node has no child, it is a padding node.
                    if self.nodes[sibling].get_lch().is_none()
                        && self.nodes[sibling].get_rch().is_none()
                    {
                        self.nodes[sibling].set_node_type(NodeType::Padding);
                        self.nodes[sibling].set_value(Paddable::padding(&sibling_idx, secret));
                    }
                }
            }

            // Merge the two child nodes and set the value of the parent node.
            let new_value = Mergeable::merge(
                self.nodes[self.nodes[parent].get_lch().unwrap()].get_value(),
                self.nodes[self.nodes[parent].get_rch().unwrap()].get_value(),
            );
            self.nodes[parent].set_value(new_value);

            idx = idx.get_parent_index(); // Move on to the node at the upper layer.
        }
    }

    /// Returns the references to the input leaf node and siblings of nodes long the Merkle path from the root to the leaf.
    /// The result is a list of references ```[leaf, sibling, ..., sibling]```.
    ///
    /// If the input leaf node doesn't exist, return ```None```.
    ///
    /// Panics if the height of the input index is different from the height of the tree.
    pub fn get_merkle_path_ref(&self, idx: &TreeIndex) -> Option<Vec<usize>> {
        // Panics if the height of the input index is different from the height of the tree.
        if idx.get_height() != self.height {
            panic!("{}", TreeError::HeightNotMatch);
        }

        let mut siblings = Vec::new();
        let mut node = self.root;
        // Add references to sibling nodes along the path from the root to the input node.
        for i in 0..self.height {
            if idx.get_bit(i) == 0 {
                // Add the reference to the right child to the sibling list and move on to the left child.
                self.nodes[node].get_lch()?;
                siblings.push(self.nodes[node].get_rch().unwrap());
                node = self.nodes[node].get_lch().unwrap();
            } else {
                // Add the reference to the left child to the sibling list and move on to the right child.
                self.nodes[node].get_rch()?;
                siblings.push(self.nodes[node].get_lch().unwrap());
                node = self.nodes[node].get_rch().unwrap();
            }
        }
        let mut path = vec![node];
        path.append(&mut siblings);
        Some(path) // Some([leaf, sibling, ..., sibling])
    }

    /// Returns the references to the input leaves and siblings of nodes long the batched Merkle paths from the root to the leaves.
    /// The result is a list of references ```[leaf, ..., leaf, sibling, ..., sibling]```.
    ///
    /// If the root or some input leaf node doesn't exist, return ```None```.
    ///
    /// If the input list is empty, return an empty vector.
    ///
    /// Panics if the input list is not valid.
    pub fn get_merkle_path_ref_batch(&self, list: &[TreeIndex]) -> Option<Vec<usize>> {
        // If the input list is empty, return an empty vector.
        if list.is_empty() {
            return Some(Vec::new());
        }

        // Construct an SMT from the input list of indexes with void value.
        // Panics if the input list is invalid for constructing an SMT.
        let mut proof_tree: SparseMerkleTree<Nil> = SparseMerkleTree::new(self.height);
        let mut list_for_building: Vec<(TreeIndex, Nil)> = Vec::new();
        for index in list {
            list_for_building.push((*index, Nil));
        }
        if let Some(x) = proof_tree.construct_smt_nodes(&list_for_building, &ALL_ZEROS_SECRET) {
            panic!("{}", x);
        }

        // Extract values of leaves and siblings in the batched Merkle proof from the original SMT
        // in the BFS order of all nodes in proof_tree.
        let mut leaves: Vec<usize> = Vec::new();
        let mut siblings: Vec<usize> = Vec::new();
        let vec = proof_tree.get_index_ref_pairs(); // Get the index-ref pair in BFS order.
        let mut smt_refs = vec![0usize; vec.len()]; // Map from nodes in proof_tree to nodes in self.
        smt_refs[vec[0].1] = self.root;
        for (_idx, proof_ref) in vec {
            let smt_ref = smt_refs[proof_ref];
            match &proof_tree.nodes[proof_ref].node_type {
                // The padding node in proof_tree is a sibling node in the batched proof.
                NodeType::Padding => {
                    siblings.push(smt_ref);
                }
                // The leaf node in proof_tree in also a leaf node in the batched proof.
                NodeType::Leaf => {
                    leaves.push(smt_ref);
                }
                NodeType::Internal => {}
            }
            // Map the left child of current node in proof_tree to that of the referenced node in the original SMT.
            if let Some(x) = proof_tree.nodes[proof_ref].get_lch() {
                self.nodes[smt_ref].get_lch()?;
                smt_refs[x] = self.nodes[smt_ref].get_lch().unwrap();
            }
            // Map the right child of current node in proof_tree to that of the referenced node in the original SMT.
            if let Some(x) = proof_tree.nodes[proof_ref].get_rch() {
                self.nodes[smt_ref].get_rch()?;
                smt_refs[x] = self.nodes[smt_ref].get_rch().unwrap();
            }
        }
        leaves.append(&mut siblings);
        Some(leaves) // Some([leaf, ..., leaf, sibling, ..., sibling])
    }

    /// Returns the tree index of closest left/right (depending on input direction) node in the tree.
    pub fn get_closest_index_by_dir(
        &self,
        ancestor_ref: usize,
        ancestor_idx: TreeIndex,
        dir: ChildDir,
    ) -> Option<TreeIndex> {
        let mut closest_ref = ancestor_ref;
        let mut closest_idx = ancestor_idx;

        // Find the node of which the subtree contains the closest node.
        while closest_ref != self.root {
            let parent_ref = self.nodes[closest_ref].get_parent().unwrap();
            if self.nodes[parent_ref].get_child_by_dir(dir).is_none()
                || closest_ref == self.nodes[parent_ref].get_child_by_dir(dir).unwrap()
                || *self.nodes[self.nodes[parent_ref].get_child_by_dir(dir).unwrap()]
                    .get_node_type()
                    == NodeType::Padding
            {
                // When the parent node doesn't have a non-padding dir child or the current node itself is the left child,
                // go up to the upper level.
                closest_ref = parent_ref;
                closest_idx = closest_idx.get_prefix(closest_idx.get_height() - 1);
            } else {
                // The sibling of the current node is a dir-child of its parent, thus its subtree contains the target node.
                closest_ref = self.nodes[parent_ref].get_child_by_dir(dir).unwrap();
                closest_idx = closest_idx.get_sibling_index();
                break;
            }
        }
        if closest_idx.get_height() == 0 {
            // The closest left/right node doesn't exist in the tree.
            return None;
        }

        let mut opp_dir = ChildDir::Left;
        if dir == ChildDir::Left {
            opp_dir = ChildDir::Right;
        }

        // Retrieve the opp_dir most node in the subtree, which is our target.
        while *self.nodes[closest_ref].get_node_type() == NodeType::Internal {
            if *self.nodes[self.nodes[closest_ref].get_child_by_dir(opp_dir).unwrap()]
                .get_node_type()
                == NodeType::Padding
            {
                closest_ref = self.nodes[closest_ref].get_child_by_dir(dir).unwrap();
                closest_idx = closest_idx.get_child_index_by_dir(dir);
            } else {
                closest_ref = self.nodes[closest_ref].get_child_by_dir(opp_dir).unwrap();
                closest_idx = closest_idx.get_child_index_by_dir(opp_dir);
            }
        }
        Some(closest_idx)
    }

    /// Returns the index-reference pairs to necessary padding nodes to prove that
    /// the input index is the left/right (depending on the input direction) most real leaf in the tree.
    /// Note that the reference is the offset from the end of the sibling list.
    pub fn get_padding_proof_by_dir_index_ref_pairs(
        idx: &TreeIndex,
        dir: ChildDir,
    ) -> Vec<(TreeIndex, usize)> {
        let mut opp_dir = ChildDir::Right;
        let mut dir_bit = 0;
        if dir == ChildDir::Right {
            opp_dir = ChildDir::Left;
            dir_bit = 1;
        }

        // Along the path from the leaf node to the root,
        // any sibling that is an opp_dir child of its parent,
        // it must be a padding node and should be part of proof.
        let mut refs: Vec<(TreeIndex, usize)> = Vec::new();
        for i in (0..idx.get_height()).rev() {
            if idx.get_bit(i) == dir_bit {
                refs.push((
                    idx.get_prefix(i).get_child_index_by_dir(opp_dir),
                    idx.get_height() - 1 - i,
                ));
            }
        }
        refs
    }

    /// Returns the index-reference pairs to necessary padding nodes to prove that
    /// there are no other real leaf nodes between the input indexes in the tree.
    /// Note that the reference is the offset from the end of the sibling list.
    ///
    /// Panics if the input indexes don't have the same height or not in the right order.
    pub fn get_padding_proof_batch_index_ref_pairs(
        left_idx: &TreeIndex,
        right_idx: &TreeIndex,
    ) -> Vec<(TreeIndex, usize)> {
        // Panics if the heights of two indexes don't match.
        if left_idx.get_height() != right_idx.get_height() {
            panic!("{}", TreeError::HeightNotMatch);
        }
        // Panics if the two indexes are not in the right order.
        if left_idx >= right_idx {
            panic!("{}", TreeError::IndexNotSorted);
        }

        // Check all siblings in the batched Merkle proof of the two input indexes.
        // If any sibling or the subtree of the sibling is between the two input indexes,
        // they must be padding nodes and should be included in the padding node proof.
        let mut refs: Vec<(TreeIndex, usize)> = Vec::new();
        let mut cur_ref = 0usize;
        let mut index: [TreeIndex; 2] = [*left_idx, *right_idx];
        let mut parent: [TreeIndex; 2] =
            [left_idx.get_parent_index(), right_idx.get_parent_index()];
        while parent[0] != parent[1] {
            // There won't be such padding nodes in above the common ancestor of two input indexes.
            for dir_bit in (0..2).rev() {
                if index[dir_bit].get_last_bit() == dir_bit as u8 {
                    // If the current index or the subtree of the index is between the two input indexes,
                    // add it to the reference of padding node proof.
                    // Not that the reference is the offset from the end of the sibling list in the Merkle proof.
                    refs.push((index[dir_bit].get_sibling_index(), cur_ref));
                }
                index[dir_bit] = parent[dir_bit];
                parent[dir_bit] = parent[dir_bit].get_parent_index();
                cur_ref += 1;
            }
        }
        refs
    }
}
