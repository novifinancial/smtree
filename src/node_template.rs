// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::marker::PhantomData;

use digest::Digest;
use rand::Rng;

use crate::{
    error::DecodingError,
    index::TreeIndex,
    traits::{
        Mergeable, Paddable, PaddingProvable, ProofExtractable, Rand, Serializable, TypeName,
    },
    utils::{bytes_to_usize, usize_to_bytes},
};

const SECRET: &str = "secret";
pub const PADDING_STRING: &str = "padding_node";

/// An SMT node that carries just a hash value
#[derive(Default, Clone, Debug)]
pub struct HashNodeSMT<D> {
    hash: Vec<u8>,
    phantom: PhantomData<D>,
}

impl<D> HashNodeSMT<D> {
    pub fn new(hash: Vec<u8>) -> HashNodeSMT<D> {
        HashNodeSMT {
            hash,
            phantom: PhantomData,
        }
    }
}

impl<D> PartialEq for HashNodeSMT<D> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<D> Eq for HashNodeSMT<D> {}

impl<D: Digest> Mergeable for HashNodeSMT<D> {
    fn merge(lch: &HashNodeSMT<D>, rch: &HashNodeSMT<D>) -> HashNodeSMT<D> {
        let mut hasher = D::new();
        hasher.update(&lch.hash);
        hasher.update(&rch.hash);
        HashNodeSMT::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Paddable for HashNodeSMT<D> {
    fn padding(idx: &TreeIndex) -> HashNodeSMT<D> {
        let mut pre_image = D::new();
        pre_image.update(SECRET.as_bytes());
        pre_image.update(&TreeIndex::serialize(&[*idx]));

        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&pre_image.finalize().to_vec());
        HashNodeSMT::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Serializable for HashNodeSMT<D> {
    fn serialize(&self) -> Vec<u8> {
        (&self.hash).clone()
    }

    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        if bytes.len() - *begin < D::output_size() {
            return Err(DecodingError::BytesNotEnough);
        }
        let item = Self::new(bytes[*begin..*begin + D::output_size()].to_vec());
        *begin += D::output_size();
        Ok(item)
    }
}

impl<D: Clone> ProofExtractable for HashNodeSMT<D> {
    type ProofNode = HashNodeSMT<D>;
    fn get_proof_node(&self) -> Self::ProofNode {
        self.clone()
    }
}

impl<D: Clone + Digest> PaddingProvable for HashNodeSMT<D> {
    type PaddingProof = HashNodeSMT<D>;

    fn prove_padding_node(&self, idx: &TreeIndex) -> HashNodeSMT<D> {
        let data = TreeIndex::serialize(&[*idx]);
        let mut pre_image = D::new();
        pre_image.update(SECRET.as_bytes());
        pre_image.update(&data);
        HashNodeSMT::new(pre_image.finalize().to_vec())
    }

    fn verify_padding_node(
        node: &<Self as ProofExtractable>::ProofNode,
        proof: &Self::PaddingProof,
        _idx: &TreeIndex,
    ) -> bool {
        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&proof.hash);
        *node == HashNodeSMT::<D>::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Rand for HashNodeSMT<D> {
    fn randomize(&mut self) {
        *self = HashNodeSMT::new(vec![0u8; D::output_size()]);
        let mut rng = rand::thread_rng();
        for item in &mut self.hash {
            *item = rng.gen();
        }
    }
}

impl<D: TypeName> TypeName for HashNodeSMT<D> {
    fn get_name() -> String {
        format!("Hash ({})", D::get_name())
    }
}

impl TypeName for blake3::Hasher {
    fn get_name() -> String {
        "Blake3".to_owned()
    }
}

impl TypeName for blake2::Blake2b {
    fn get_name() -> String {
        "Blake2b".to_owned()
    }
}

impl TypeName for sha2::Sha256 {
    fn get_name() -> String {
        "Sha2".to_owned()
    }
}

impl TypeName for sha3::Sha3_256 {
    fn get_name() -> String {
        "Sha3".to_owned()
    }
}

/// An SMT node that carries a u64 value, and merging is computed as the sum of two nodes.
#[derive(Default, Clone, Debug)]
pub struct SumNodeSMT(u64);

impl SumNodeSMT {
    pub fn new(value: u64) -> SumNodeSMT {
        SumNodeSMT(value)
    }
}

impl PartialEq for SumNodeSMT {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SumNodeSMT {}

impl Mergeable for SumNodeSMT {
    fn merge(lch: &SumNodeSMT, rch: &SumNodeSMT) -> SumNodeSMT {
        SumNodeSMT(lch.0 + rch.0)
    }
}

impl Paddable for SumNodeSMT {
    fn padding(_idx: &TreeIndex) -> SumNodeSMT {
        SumNodeSMT(0u64)
    }
}

impl Serializable for SumNodeSMT {
    fn serialize(&self) -> Vec<u8> {
        usize_to_bytes(self.0 as usize, 8)
    }

    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        if bytes.len() - *begin < 8 {
            return Err(DecodingError::BytesNotEnough);
        }
        Ok(SumNodeSMT(bytes_to_usize(bytes, 8, begin).unwrap() as u64))
    }
}

impl ProofExtractable for SumNodeSMT {
    type ProofNode = SumNodeSMT;
    fn get_proof_node(&self) -> Self::ProofNode {
        SumNodeSMT(self.0)
    }
}

impl PaddingProvable for SumNodeSMT {
    type PaddingProof = SumNodeSMT;
    fn prove_padding_node(&self, _idx: &TreeIndex) -> SumNodeSMT {
        SumNodeSMT(0)
    }
    fn verify_padding_node(node: &SumNodeSMT, proof: &SumNodeSMT, _idx: &TreeIndex) -> bool {
        node.0 == 0 && proof.0 == 0
    }
}

impl Rand for SumNodeSMT {
    fn randomize(&mut self) {
        let mut rng = rand::thread_rng();
        let x: u32 = rng.gen();
        self.0 = x as u64;
    }
}

impl TypeName for SumNodeSMT {
    fn get_name() -> String {
        "Sum".to_owned()
    }
}
