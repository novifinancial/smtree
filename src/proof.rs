//! This module provides definitions of the inclusion proof (Merkle proof) of a tree node in an SMT,
//! and proof verification.

use std::fmt::Debug;

use crate::{
    error::DecodingError,
    index::TreeIndex,
    traits::{
        InclusionProvable, Mergeable, Paddable, PaddingProvable, ProofExtractable,
        RandomSampleable, Serializable,
    },
    tree::{ChildDir, NodeType, SparseMerkleTree},
    utils::{bytes_to_usize, usize_to_bytes, Nil},
};

// The number of bytes for encoding the batch num in a Merkle proof.
const BATCH_NUM_BYTE_NUM: usize = 8;
// The number of bytes for encoding the sibling num in a Merkle proof.
const SIBLING_NUM_BYTE_NUM: usize = 8;
// The number of bytes for encoding the padding num in a padding node proof.
const PADDING_NUM_BYTE_NUM: usize = 2;

/// A proof depicts a Merkle path.
///
/// It consists of the tree index of the proved node, which indicates the path from the root to it,
/// and the siblings of nodes along the path, excluding the root which doesn't have a sibling.
#[derive(Debug, Clone, Default)]
pub struct MerkleProof<V: Clone + Default + Mergeable + ProofExtractable>
where
    <V as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    // The tree indexes of the proved leaves.
    indexes: Vec<TreeIndex>,
    // The siblings of nodes along the path, from the sibling of the root to that of the leaf when there is only one leaf.
    // When there are multiple leaves to be proved in a batched Merkle proof, the order of siblings follows the BFS order.
    siblings: Vec<V::ProofNode>,
}

impl<V: Default + Clone + Mergeable + ProofExtractable> MerkleProof<V>
where
    <V as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    /// The constructor for proof of a single node.
    pub fn new(_idx: TreeIndex) -> MerkleProof<V> {
        let idx: Vec<TreeIndex> = vec![_idx];
        MerkleProof {
            indexes: idx,
            siblings: Vec::new(),
        }
    }

    /// The constructor for a batched proof.
    pub fn new_batch(idx: &[TreeIndex]) -> MerkleProof<V> {
        MerkleProof {
            indexes: idx.to_vec(),
            siblings: Vec::new(),
        }
    }

    pub fn get_batch_num(&self) -> usize {
        self.indexes.len()
    }

    /// Returns the indexes of the proof.
    pub fn get_indexes(&self) -> &[TreeIndex] {
        &self.indexes
    }

    /// Returns the siblings of nodes along the path.
    pub fn get_path_siblings(&self) -> &[V::ProofNode] {
        &self.siblings
    }

    /// Returns the number of siblings along the proof path.
    pub fn get_siblings_num(&self) -> usize {
        self.siblings.len()
    }

    /// Returns the sibling of the node at input index.
    ///
    /// For the single node proof, the sibling which is the child of the root has index 0,
    /// and the sibling of the proved node has the greatest index.
    ///
    /// For a batched proof, the order of siblings follows the BFS order.
    ///
    /// Panics if the input index is out of the range ```[0, siblings_num-1]```.
    pub fn get_sibling_at_idx(&self, idx: usize) -> &V::ProofNode {
        if idx >= self.siblings.len() {
            panic!("The input index is out of range.");
        }
        &self.siblings[idx]
    }

    /// Add a sibling node at the end of the proof path.
    pub fn add_sibling(&mut self, value: V::ProofNode) {
        self.siblings.push(value);
    }

    /// Set the sibling nodes.
    pub fn set_siblings(&mut self, value: Vec<V::ProofNode>) {
        self.siblings = value;
    }

    /// Verify a Merkle proof of a single node.
    pub fn verify(&self, leaf: &V::ProofNode, root: &V::ProofNode) -> bool {
        // Check if there is only one index.
        if self.indexes.len() != 1 {
            return false;
        }

        // If the number of siblings doesn't match with the height of the proved node,
        // the proof is invalid.
        if self.siblings.len() != self.indexes[0].get_height() {
            return false;
        }

        // Compute the hash along the Merkle path.
        let mut value = leaf.clone();
        for i in (0..self.siblings.len()).rev() {
            // H[node] = hash(H[lch] | H[rch])
            if self.indexes[0].get_bit(i) == 0 {
                value = Mergeable::merge(&value, &self.siblings[i]);
            } else {
                value = Mergeable::merge(&self.siblings[i], &value);
            }
        }

        // Compare the computed hash with the tree root.
        value == *root
    }

    /// Verify a batched Merkle proof.
    pub fn verify_batch(&self, leaves: &[V::ProofNode], root: &V::ProofNode) -> bool {
        // Check if the number of leaves is the same as the number of the indexes.
        if leaves.len() != self.indexes.len() {
            println!("leaf and index len don't match");
            return false;
        }

        // If there isn't any leaf node, the siblings list must also be empty.
        if leaves.is_empty() {
            return if self.siblings.is_empty() {
                true
            } else {
                println!("sibling not empty");
                false
            };
        }

        // Construct an SMT from the indexes in the proof, from which we can extract the positions of sibling nodes.
        let mut proof_tree: SparseMerkleTree<Nil> =
            SparseMerkleTree::new(self.indexes[0].get_height());
        let mut list_for_building: Vec<(TreeIndex, Nil)> = Vec::new();
        for index in &self.indexes {
            list_for_building.push((*index, Nil));
        }
        if let Some(_x) = proof_tree.construct_smt_nodes(&list_for_building) {
            return false;
        }

        // Retrieve the BFS order of nodes in the proof_tree.
        let vec = proof_tree.get_index_ref_pairs();
        let mut value = vec![V::ProofNode::default(); vec.len()];
        let mut ref_sibling = self.siblings.len();
        let mut ref_leaf = leaves.len();
        // Compute hashes in the reverse order of the BFS list.
        for i in (0..vec.len()).rev() {
            let ref_tree = vec[i].1;
            match &proof_tree.get_node_by_ref(ref_tree).get_node_type() {
                // If the current node is a padding node in the proof_tree,
                // it is a sibing node is the Merkle proof.
                NodeType::Padding => {
                    if ref_sibling == 0 {
                        // The siblings are not enough for padding nodes in the proof_tree.
                        return false;
                    }
                    ref_sibling -= 1;
                    value[ref_tree] = self.siblings[ref_sibling].clone();
                }
                // If the current node is a leaf node in the proof_tree,
                // it is also a leaf node in the Merkle proof.
                NodeType::Leaf => {
                    if ref_leaf == 0 {
                        // The leaves are not enough for leaf node in the proof_tree.
                        println!("leaf not enough");
                        return false;
                    }
                    ref_leaf -= 1;
                    value[ref_tree] = leaves[ref_leaf].clone();
                }
                // If the current node is an internal node in the proof_tree,
                // the value can be computed by merging two child nodes, whose values are available.
                NodeType::Internal => {
                    value[ref_tree] = Mergeable::merge(
                        &value[proof_tree.get_node_by_ref(ref_tree).get_lch().unwrap()],
                        &value[proof_tree.get_node_by_ref(ref_tree).get_rch().unwrap()],
                    );
                }
            }
        }

        // If there are left leaf nodes or sibling nodes not used in the proof_tree, the Merkle proof is invalid.
        if ref_leaf > 0 || ref_sibling > 0 {
            return false;
        }
        // Checks the root value.
        value[vec[0].1] == *root
    }
}

impl<V: Default + Clone + Mergeable + ProofExtractable> Serializable for MerkleProof<V>
where
    <V as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    /// Encode a proof in the format: ```batch_num || tree_indexes || sibling_num || siblings```.
    ///
    /// If the index list is empty, return empty vector.
    fn serialize(&self) -> Vec<u8> {
        // If the index list is empty, return empty vector.
        if self.indexes.is_empty() {
            return Vec::<u8>::new();
        }

        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut usize_to_bytes(self.indexes.len(), BATCH_NUM_BYTE_NUM)); // Encode the batch_num.
        bytes.append(&mut TreeIndex::serialize(&self.indexes)); // Encode the tree indexes.
        bytes.append(&mut usize_to_bytes(
            self.siblings.len(),
            SIBLING_NUM_BYTE_NUM,
        )); // Encode the sibling_num.
        for item in &self.siblings {
            bytes.append(&mut V::ProofNode::serialize(&item)); // Encode the siblings.
        }
        bytes
    }

    /// Decode input bytes (```batch_num || tree_indexes ||  sibling_num || siblings```) as a Merkle proof.
    ///
    /// If there are bytes left, not used for decoding, or ```*begin != bytes.len()``` at the end of the execution,
    /// return [DecodingError::TooManyEncodedBytes](../error/enum.DecodingError.html#variant.TooManyEncodedBytes).
    fn deserialize_as_a_unit(
        bytes: &[u8],
        begin: &mut usize,
    ) -> Result<MerkleProof<V>, DecodingError> {
        // Return empty proof if the input byte is empty.
        if bytes.len() - *begin == 0 {
            return Ok(MerkleProof::new_batch(&[] as &[TreeIndex]));
        }
        // Decode the batch_num.
        let num = bytes_to_usize(bytes, BATCH_NUM_BYTE_NUM, begin);
        if let Err(e) = num {
            return Err(e);
        }
        let num = num.unwrap();

        // Decode the tree indexes.
        let index = TreeIndex::deserialize_as_a_unit(bytes, num, begin);
        if let Err(e) = index {
            return Err(e);
        }
        let index = index.unwrap();
        let mut proof: MerkleProof<V> = MerkleProof::new_batch(&index);

        // Decode the sibling_num.
        let sibling_num = bytes_to_usize(bytes, SIBLING_NUM_BYTE_NUM, begin);
        if let Err(e) = sibling_num {
            return Err(e);
        }
        let sibling_num = sibling_num.unwrap();

        // Decode the siblings.
        let mut siblings: Vec<V::ProofNode> = Vec::new();
        for _i in 0..sibling_num {
            let sibling = V::ProofNode::deserialize_as_a_unit(bytes, begin);
            if let Err(e) = sibling {
                return Err(e);
            }
            siblings.push(sibling.unwrap());
        }

        proof.set_siblings(siblings);
        Ok(proof)
    }
}

impl<P: Clone + Default + Mergeable + Paddable + ProofExtractable> InclusionProvable
    for MerkleProof<P>
where
    <P as ProofExtractable>::ProofNode: Clone + Default + Eq + Mergeable + Serializable,
{
    type ProofNodeType = <P as ProofExtractable>::ProofNode;
    type TreeStruct = SparseMerkleTree<P>;

    /// Generate Merkle proof for a given list of nodes.
    ///
    /// Return ```None``` if any of the input node doesn't exist in the tree.
    fn generate_inclusion_proof(tree: &Self::TreeStruct, list: &[TreeIndex]) -> Option<Self> {
        if list.len() == 1 {
            // Get the references to the input leaf and siblings of nodes long the Merkle path from the root to the leaves.
            let refs = tree.get_merkle_path_ref(&list[0]);
            refs.as_ref()?;
            let refs = refs.unwrap();
            // Construct the Merkle proof given the references to all sibling nodes in the proof.
            let mut proof = MerkleProof::<P>::new(list[0]);
            proof.set_siblings(tree.get_node_proof_by_refs(&refs[1..]));
            Some(proof)
        } else {
            // Get the references to the input leaves and siblings of nodes long the batched Merkle paths from the root to the leaves.
            let refs = tree.get_merkle_path_ref_batch(list);
            refs.as_ref()?;
            let refs = refs.unwrap();
            // Construct the batched Merkle proof given the references to all sibling nodes in the proof.
            let mut proof = MerkleProof::<P>::new_batch(list);
            proof.set_siblings(tree.get_node_proof_by_refs(&refs[list.len()..]));
            Some(proof)
        }
    }

    fn verify_inclusion_proof(
        &self,
        leaves: &[Self::ProofNodeType],
        root: &Self::ProofNodeType,
    ) -> bool {
        if leaves.len() == 1 {
            self.verify(&leaves[0], root)
        } else {
            self.verify_batch(leaves, root)
        }
    }
}

/// A random sampling proof proves that the result of random sampling is valid.
///
/// It consists of the tree index of the proved node, and the proofs of certain padding nodes, and a standard Merkle proof.
///
/// If the sampled index exists as a real leaf node (non-padding) in the tree,
/// no padding nodes will be proved but just a standard Merkle proof for the sampled index.
///
/// If the sampled index doesn't exist as a real leaf node (non-padding) in the tree,
/// proofs of necessary padding nodes between the two closest neighbours of the sampled index are included in the proof,
/// and the Merkle proof proves inclusion of the closest neighbours.
#[derive(Default)]
pub struct RandomSamplingProof<
    V: Clone + Default + Mergeable + ProofExtractable + Paddable + PaddingProvable,
> where
    V::ProofNode: Default + Eq + Clone + Mergeable + Serializable,
    V::PaddingProof: Default + Eq + Clone + Serializable,
{
    index: TreeIndex, // The tree index of teh proved node.
    padding_proofs: Vec<<V as PaddingProvable>::PaddingProof>, // The proofs of necessary padding nodes.
    merkle_proof: MerkleProof<V>,                              // The Merkle proof.
    leaves: Vec<V::ProofNode>,                                 // The leaf nodes in the proof.
}

impl<V: Clone + Default + Mergeable + Paddable + PaddingProvable + ProofExtractable>
    RandomSamplingProof<V>
where
    V::ProofNode: Default + Eq + Clone + Mergeable + Serializable,
    V::PaddingProof: Default + Eq + Clone + Serializable,
{
    /// The constructor.
    pub fn new(
        index: TreeIndex,
        padding_proofs: Vec<V::PaddingProof>,
        merkle_proof: MerkleProof<V>,
        leaves: Vec<V::ProofNode>,
    ) -> RandomSamplingProof<V> {
        RandomSamplingProof {
            index,
            padding_proofs,
            merkle_proof,
            leaves,
        }
    }

    /// Returns the Merkle proof.
    pub fn get_merkle_proof(&self) -> &MerkleProof<V> {
        &self.merkle_proof
    }

    /// Returns the index of the proof.
    pub fn get_index(&self) -> &TreeIndex {
        &self.index
    }

    /// Returns the leaf nodes.
    pub fn get_leaves(&self) -> &[V::ProofNode] {
        &self.leaves
    }

    /// Set the leaf node in the proof of a single node.
    pub fn set_leaf(&mut self, value: V::ProofNode) {
        self.leaves = vec![value];
    }

    /// Set the leaf nodes in a batched proof.
    pub fn set_leaves(&mut self, value: &[V::ProofNode]) {
        self.leaves = value.to_vec();
    }

    /// Add a leaf node in a batched proof.
    pub fn add_leaf(&mut self, value: V::ProofNode) {
        self.leaves.push(value);
    }

    /// Adds the proof of a new padding node.
    pub fn add_padding_proof(&mut self, proof: V::PaddingProof) {
        self.padding_proofs.push(proof);
    }

    /// Set the padding proofs as the input.
    pub fn set_padding_proofs(&mut self, proofs: Vec<V::PaddingProof>) {
        self.padding_proofs = proofs;
    }
}

impl<V: Clone + Default + Mergeable + Paddable + PaddingProvable + ProofExtractable> Serializable
    for RandomSamplingProof<V>
where
    V::ProofNode: Default + Eq + Clone + Mergeable + Serializable,
    V::PaddingProof: Default + Eq + Clone + Serializable,
{
    /// Encode a proof in the format: ```tree_index || padding_num || padding_proofs || merkle_proof || leaves```.
    fn serialize(&self) -> Vec<u8> {
        // Check if the number of leaves is the same as the number of indexes.
        if self.merkle_proof.indexes.len() != self.leaves.len() {
            panic!("The number of indexes doesn't match with the number of leaves");
        }

        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut TreeIndex::serialize(&[self.index])); // Encode the tree indexes.
        bytes.append(&mut usize_to_bytes(
            self.padding_proofs.len(),
            PADDING_NUM_BYTE_NUM,
        )); // Encode the padding_num.
        for item in &self.padding_proofs {
            bytes.append(&mut V::PaddingProof::serialize(&item)); // Encode the padding proofs.
        }
        bytes.append(&mut self.merkle_proof.serialize()); // Encode the Merkle proof.
        for item in &self.leaves {
            bytes.append(&mut V::ProofNode::serialize(&item)); // Encode the leaves.
        }
        bytes
    }

    /// Decode input bytes (```tree_index || padding_num || padding_proofs || merkle_proof || leaves```) as a Padding proof.
    fn deserialize_as_a_unit(
        bytes: &[u8],
        begin: &mut usize,
    ) -> Result<RandomSamplingProof<V>, DecodingError> {
        // Decode the tree index.
        let index = TreeIndex::deserialize_as_a_unit(bytes, 1, begin);
        if let Err(e) = index {
            return Err(e);
        }
        let index = index.unwrap();

        // Decode the padding_num.
        let num = bytes_to_usize(bytes, PADDING_NUM_BYTE_NUM, begin);
        if let Err(e) = num {
            return Err(e);
        }
        let num = num.unwrap();

        // Decode the padding proofs.
        let mut padding_proofs: Vec<V::PaddingProof> = Vec::new();
        for _i in 0..num {
            let padding_proof = V::PaddingProof::deserialize_as_a_unit(bytes, begin);
            if let Err(e) = padding_proof {
                return Err(e);
            }
            padding_proofs.push(padding_proof.unwrap());
        }

        // Decode the Merkle proof.
        let merkle_proof = MerkleProof::<V>::deserialize_as_a_unit(bytes, begin);
        if let Err(e) = merkle_proof {
            return Err(e);
        }
        let merkle_proof = merkle_proof.unwrap();
        // Decode the leaves.
        let mut leaves: Vec<V::ProofNode> = Vec::new();
        for _i in 0..merkle_proof.get_batch_num() {
            let leaf = V::ProofNode::deserialize_as_a_unit(bytes, begin);
            if let Err(e) = leaf {
                return Err(e);
            }
            leaves.push(leaf.unwrap());
        }

        Ok(RandomSamplingProof::<V>::new(
            index[0],
            padding_proofs,
            merkle_proof,
            leaves,
        ))
    }
}

impl<V: Clone + Default + Mergeable + Paddable + PaddingProvable + ProofExtractable>
    RandomSampleable for RandomSamplingProof<V>
where
    V::ProofNode: Default + Eq + Clone + Mergeable + Serializable,
    V::PaddingProof: Default + Eq + Clone + Serializable,
{
    type ProofNodeType = V::ProofNode;
    type TreeStruct = SparseMerkleTree<V>;

    fn random_sampling(tree: &Self::TreeStruct, idx: &TreeIndex) -> Self {
        // Fetch the lowest ancestor of the sampled index in the tree.
        let (ancestor, ancestor_idx) = tree.get_closest_ancestor_ref_index(idx);

        // If the sampled index is a real leaf node in the tree,
        // return a padding node proof containing no padding node, and the Merkle proof of that node.
        if ancestor_idx.get_height() == tree.get_height()
            && *tree.get_node_by_ref(ancestor).get_node_type() == NodeType::Leaf
        {
            // Get the references to the input leaf and siblings of nodes long the Merkle path from the root to the leaves.
            let refs = tree.get_merkle_path_ref(idx).unwrap();
            // Construct the Merkle proof given the references to all sibling nodes in the proof.
            let mut proof = MerkleProof::<V>::new(*idx);
            proof.set_siblings(tree.get_node_proof_by_refs(&refs[1..]));
            return RandomSamplingProof::new(
                *idx,
                Vec::new(),
                proof,
                tree.get_node_proof_by_refs(&refs[0..1]),
            );
        }

        let mut list: Vec<TreeIndex> = Vec::new();
        // Fetch the index of the closest node on the left.
        let res = tree.get_closest_index_by_dir(ancestor, ancestor_idx, ChildDir::Left);
        if let Some(x) = res {
            list.push(x);
        }
        // Fetch the index of the closest node on the right.
        let res = tree.get_closest_index_by_dir(ancestor, ancestor_idx, ChildDir::Right);
        if let Some(x) = res {
            list.push(x);
        }

        let mut padding_proofs: Vec<V::PaddingProof> = Vec::new();
        // Generate the Merkle proof of closest nodes.
        let mut merkle_proof: MerkleProof<V> = MerkleProof::new_batch(&list);
        let mut leaves = Vec::<V::ProofNode>::new();
        // Add proofs of necessary padding nodes in the proof.
        match list.len() {
            0 => {
                // When the tree is empty, prove that the root is a padding node.
                padding_proofs.push(
                    tree.get_node_by_ref(tree.get_root_ref())
                        .get_value()
                        .prove_padding_node(&TreeIndex::zero(0)),
                );
            }
            1 => {
                // When there is only a left/right neighbour.
                // Get the references to the input leaf and siblings of nodes long the Merkle path from the root to the leaves.
                let refs = tree.get_merkle_path_ref(&list[0]).unwrap();
                // Construct the Merkle proof given the references to all sibling nodes in the proof.
                merkle_proof.set_siblings(tree.get_node_proof_by_refs(&refs[1..]));
                leaves = tree.get_node_proof_by_refs(&refs[0..1]);
                let padding_refs;
                // Fetch the reference (offset to the end of the sibling list) to the necessary padding nodes by neighbour direction.
                if list[0] < *idx {
                    padding_refs = SparseMerkleTree::<V>::get_padding_proof_by_dir_index_ref_pairs(
                        &list[0],
                        ChildDir::Left,
                    );
                } else {
                    padding_refs = SparseMerkleTree::<V>::get_padding_proof_by_dir_index_ref_pairs(
                        &list[0],
                        ChildDir::Right,
                    );
                }
                // Add the proofs of the necessary padding nodes.
                <RandomSamplingProof<V>>::add_padding_proofs(
                    tree,
                    &mut padding_proofs,
                    refs,
                    padding_refs,
                )
            }
            _ => {
                // When neighbours on both sides exist.
                // Get the references to the input leaves and siblings of nodes long the batched Merkle paths from the root to the leaves.
                let refs = tree.get_merkle_path_ref_batch(&list).unwrap();
                // Construct the Merkle proof given the references to all sibling nodes in the proof.
                merkle_proof.set_siblings(tree.get_node_proof_by_refs(&refs[2..]));
                leaves = tree.get_node_proof_by_refs(&refs[0..2]);
                // Fetch the reference (offset to the end of the sibling list) to the necessary padding nodes.
                let padding_refs = SparseMerkleTree::<V>::get_padding_proof_batch_index_ref_pairs(
                    &list[0], &list[1],
                );
                // Add the proofs of the necessary padding nodes.
                <RandomSamplingProof<V>>::add_padding_proofs(
                    tree,
                    &mut padding_proofs,
                    refs,
                    padding_refs,
                )
            }
        }
        RandomSamplingProof::new(*idx, padding_proofs, merkle_proof, leaves)
    }

    /// Verify the padding node proofs with the supporting Merkle proof for random sampling.
    /// For usage, before calling this method, the input Merkle proof needs to be verified.
    fn verify_random_sampling_proof(&self, root: &Self::ProofNodeType) -> bool {
        // Verify the Merkle proof first.
        if !self.merkle_proof.verify_inclusion_proof(&self.leaves, root) {
            return false;
        }

        let list = self.merkle_proof.get_indexes();
        let siblings = self.merkle_proof.get_path_siblings();
        match list.len() {
            0 => {
                // When the tree is empty, only a padding root exists.
                if self.padding_proofs.len() != 1 {
                    return false;
                }
                // Verify that the root is a padding node.
                <V as PaddingProvable>::verify_padding_node(
                    root,
                    &self.padding_proofs[0],
                    &TreeIndex::zero(0),
                )
            }
            1 => {
                if list[0] == self.index {
                    // When the sampled index exists as a real leaf node in the tree,
                    // there isn't a padding node to be proved.
                    self.padding_proofs.is_empty()
                } else {
                    // When the sampled index doesn't exist as a real leaf node in the tree,
                    // and the neighbour on one side doesn't exist,
                    // there is only one neighbour proved in the Merkle proof.
                    let padding_refs;
                    if list[0] < self.index {
                        // Only the left neighbour exists.
                        // Get references to padding nodes that prove the left neighbour is the right-most node in the tree.
                        padding_refs =
                            SparseMerkleTree::<V>::get_padding_proof_by_dir_index_ref_pairs(
                                &list[0],
                                ChildDir::Left,
                            );
                    } else {
                        // Only the right neighbour exists.
                        // Get references to padding nodes that prove the right neighbour is the left-most node in the tree.
                        padding_refs =
                            SparseMerkleTree::<V>::get_padding_proof_by_dir_index_ref_pairs(
                                &list[0],
                                ChildDir::Right,
                            );
                    }

                    // If the number of necessary padding nodes doesn't match, the proof is invalid.
                    if padding_refs.len() != self.padding_proofs.len() {
                        return false;
                    }

                    // Verify each necessary padding node is indeed a padding node
                    // according to the Merkle proof data and the padding node proof.
                    self.verify_padding_nodes(&siblings, &padding_refs)
                }
            }
            2 => {
                // When the sampled index doesn't exist as a real leaf node in the tree,
                // but neighbours on both sides exist,
                // the two closest neighbours are proved nodes in the Merkle proof.

                // Get references to padding nodes that prove the indexes between the two neighbours
                // don't exist as real leaf nodes in the tree.
                let padding_refs = SparseMerkleTree::<V>::get_padding_proof_batch_index_ref_pairs(
                    &list[0], &list[1],
                );

                // If the number of necessary padding nodes doesn't match, the proof is invalid.
                if padding_refs.len() != self.padding_proofs.len() {
                    return false;
                }

                // Verify each necessary padding node is indeed a padding node
                // according to the Merkle proof data and the padding node proof.
                self.verify_padding_nodes(&siblings, &padding_refs)
            }
            _ => {
                // The Merkle proof shouldn't prove more than 2 nodes.
                false
            }
        }
    }
}

impl<V: Clone + Default + Mergeable + Paddable + PaddingProvable + ProofExtractable>
    RandomSamplingProof<V>
where
    V::ProofNode: Default + Eq + Clone + Mergeable + Serializable,
    V::PaddingProof: Default + Eq + Clone + Serializable,
{
    fn verify_padding_nodes(
        &self,
        siblings: &&[<V as ProofExtractable>::ProofNode],
        padding_refs: &[(TreeIndex, usize)],
    ) -> bool {
        for i in 0..padding_refs.len() {
            if padding_refs[i].1 >= siblings.len()
                || !<V as PaddingProvable>::verify_padding_node(
                    &siblings[siblings.len() - 1 - padding_refs[i].1],
                    &self.padding_proofs[i],
                    &padding_refs[i].0,
                )
            {
                return false;
            }
        }
        true
    }

    fn add_padding_proofs(
        tree: &SparseMerkleTree<V>,
        padding_proofs: &mut Vec<<V as PaddingProvable>::PaddingProof>,
        refs: Vec<usize>,
        padding_refs: Vec<(TreeIndex, usize)>,
    ) {
        for (index, item) in padding_refs {
            padding_proofs.push(
                tree.get_node_by_ref(refs[refs.len() - 1 - item])
                    .get_value()
                    .prove_padding_node(&index),
            );
        }
    }
}
