# Paddable Sparse Merkle Tree

To construct a ```SparseMerkleTree``` object, 
you need to first define the value type for the tree nodes, 
and implement ```Clone```, ```Default```, ```Mergeable```, ```Paddable```, 
```ProofExtractable``` traits for it.
You also need to implement ```Debug```, ```Clone```,  ```Default```, ```Eq```,
```Mergeable```, ```Serializable``` traits for your proof node type 
```ProofExtractable::ProofNode```.

Assuming your node value is simply a hash, and the merge function is classic, to hash
the concatenated hashes of two child nodes. 
Therefore the proof node type is the same as the tree node type.
Here is a reference implementation:
```
use digest::Digest;
use std::marker::PhantomData;

use smt::{
    index::{TreeIndex},
    traits::{Mergeable, Paddable, Serializable, ProofExtractable},
    error::DecodingError,
};

const SECRET: &str = "secret";
pub const PADDING_STRING: &str = "padding_node";

/// The value type of a tree node, the result of a hash function D.
#[derive(Clone, Debug)]
pub struct Hash<D> {
    hash: Vec<u8>,
    phantom: PhantomData<D>,
}
impl<D> Hash<D> {
    pub fn new(hash: Vec<u8>) -> Hash<D> {
        Hash {
            hash,
            phantom: PhantomData,
        }
    }
}
impl<D: Digest> Default for Hash<D> {
    fn default() -> Self {
        Hash{
            hash: vec![0u8; D::output_size()],
            phantom: PhantomData
        }
    }
}
impl<D> PartialEq for Hash<D> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}
impl<D> Eq for Hash<D> {}

impl<D: Digest> Mergeable for Hash<D> {
    /// Hash the concatenated hashes of two child nodes.
    fn merge(lch: &Hash<D>, rch: &Hash<D>) -> Hash<D> {
        let mut hasher = D::new();
        hasher.update(&lch.hash);
        hasher.update(&rch.hash);
        Hash::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Paddable for Hash<D> {
    /// The value of a padding node is H("padding_node"||Hash(secret||tree_index)).
    /// This construction enables verification of a padding node,
    /// and is for random sampling purpose.
    fn padding(idx: &TreeIndex) -> Hash<D> {
        let mut pre_image = D::new();
        pre_image.update(SECRET.as_bytes());
        pre_image.update(&TreeIndex::serialize(&[*idx]));

        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&pre_image.finalize().to_vec());
        Hash::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Serializable for Hash<D> {
    /// Serialize a hash object.
    fn serialize(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&self.hash);
        vec
    }

    /// Deserialize the input bytes as a hash object.
    /// possibly with some bytes at the end left.
    ///
    /// Note that ```begin``` is the beginning position of ```bytes```.
    /// At the end of the execution,
    /// ```begin``` should point to the first byte not decoded.
    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        if bytes.len() - *begin < D::output_size() {
            return Err(DecodingError::BytesNotEnough);
        }
        let item = Self::new(bytes[*begin..*begin + D::output_size()].to_vec());
        *begin += D::output_size();
        Ok(item)
    }
}

impl<D: Clone> ProofExtractable for Hash<D> {
    /// The proof node type.
    /// In the case of hash, the proof node type is the same.
    type ProofNode = Hash<D>;

    /// Retrieve from a tree node value the proof node in Merkle proofs.
    fn get_proof_node(&self) -> Self::ProofNode {
        self.clone()
    }
}
```
If you want to enable random sampling for your sparse Merkle tree, you need to further
implement the ```PaddingProvable``` trait. Here is an example:
```
use smt::traits::PaddingProvable;

impl<D: Clone + Digest> PaddingProvable for Hash<D> {
    type PaddingProof = Hash<D>;

    /// Generate the proof for a padding node, which is H(secret||tree_index).
    fn prove_padding_node(&self, idx: &TreeIndex) -> Hash<D> {
        let data = TreeIndex::serialize(&[*idx]);
        let mut pre_image = D::new();
        pre_image.update(SECRET.as_bytes());
        pre_image.update(&data);
        Hash::new(pre_image.finalize().to_vec())
    }

    /// Verify if the node is a padding node by checking if node = H("padding_node"||proof).
    fn verify_padding_node(node: &<Self as ProofExtractable>::ProofNode,
                           proof: &Self::PaddingProof, _idx: &TreeIndex) -> bool {
        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&proof.hash);
        *node == Hash::<D>::new(hasher.finalize().to_vec())
    }
}
```

Now you are all prepared to build your sparse Merkle tree!
```
use std::collections::BTreeSet;

/// Generate a random list of leaf nodes sorted by index.
pub fn generate_sorted_index_value_pairs<V: Default + Clone> (height: usize, leaf_num: usize) -> Vec<(TreeIndex, V)> {
    let mut list: Vec<(TreeIndex, V)> = Vec::new();
    let mut set: BTreeSet<TreeIndex> = BTreeSet::new();
    for _i in 0..leaf_num {
        loop {
            let mut idx = TreeIndex::zero(height);
            idx.randomize();
            if !set.contains(&idx) { // Prevent duplication of tree index.
                set.insert(idx);
                break;
            }
        }
    }
    let value = V::default();
    for idx in set {
        list.push((idx, value.clone()));
    }
    list
}

use smt::{
    tree::SparseMerkleTree,
    proof::{MerkleProof, RandomSamplingProof},
    traits::{InclusionProvable, RandomSampleable},
};

type SMT<P> = SparseMerkleTree<P>;

const LEAF_NUM: usize = 10000;
const TREE_HEIGHT: usize = 256;

fn main() {
    let list: Vec<(TreeIndex, Hash<blake3::Hasher>)> = generate_sorted_index_value_pairs(TREE_HEIGHT, LEAF_NUM);
    // Build the sparse Merkle tree.
    let mut tree = SMT::new(TREE_HEIGHT);
    tree.build(&list);

    // Generate the inclusion proof for first two nodes in the list.
    let inclusion_list = [list[0].0, list[1].0];
    let proof = MerkleProof::<Hash<blake3::Hasher>>::generate_inclusion_proof(&tree, &inclusion_list);

    // Verify the inclusion proof.
    assert!(proof.is_some()); // Both indexes exist, so shouldn't return None.
    let proof = proof.unwrap();
    assert!(proof.verify_inclusion_proof(
                &[list[0].1.get_proof_node(), list[1].1.get_proof_node()],
                &tree.get_root()));

    // Encode the Merkle proof.
    let serialized_proof = proof.serialize();
    // Decode the Merkle proof.
    let _deserialized_proof = MerkleProof::<Hash<blake3::Hasher>>::deserialize(&serialized_proof).unwrap();

    // Random sampling the first index in the list.
    let proof = RandomSamplingProof::<Hash<blake3::Hasher>>::random_sampling(&tree, &list[0].0);
    // Encode the random sampling proof.
    let serialized = proof.serialize();
    // Decode the random sampling proof.
    let deserialized = RandomSamplingProof::<Hash<blake3::Hasher>>::deserialize(&serialized).unwrap();
    // Verify the random sampling proof.
    assert!(deserialized.verify_random_sampling_proof(&tree.get_root()));
}
```

License
-------

This project is [MIT licensed](./LICENSE).
