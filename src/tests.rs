// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::fmt::Debug;
use std::marker::PhantomData;

use crate::node_template::{HashNodeSmt, SumNodeSmt};
use crate::pad_secret::ALL_ZEROS_SECRET;
use crate::{
    index::{TreeIndex, MAX_HEIGHT},
    node_template,
    proof::{MerkleProof, RandomSamplingProof},
    traits::{
        InclusionProvable, Mergeable, Paddable, PaddingProvable, ProofExtractable, Rand,
        RandomSampleable, Serializable, TypeName,
    },
    tree::SparseMerkleTree,
    utils::{generate_sorted_index_value_pairs, print_output},
};

type SMT<P> = SparseMerkleTree<P>;

pub struct Tester<P> {
    _phantom: PhantomData<P>,
}

const LEAF_NUM: usize = 100;
const TREE_HEIGHT: usize = 8;

#[test]
#[should_panic]
fn test_index_exceed_max_height() {
    let _index = TreeIndex::zero(MAX_HEIGHT + 1);
}

#[test]
#[should_panic]
fn test_tree_exceed_max_height() {
    let _tree: SMT<SumNodeSmt> = SMT::new(MAX_HEIGHT + 1);
}

#[test]
fn test_padding_provable() {
    let mut idx = TreeIndex::zero(256);
    let secret = &ALL_ZEROS_SECRET;
    for _i in 0..1000 {
        idx.randomize();
        let sum = SumNodeSmt::padding(&idx, secret);
        assert!(SumNodeSmt::verify_padding_node(
            &sum.get_proof_node(),
            &sum.prove_padding_node(&idx, secret),
            &idx
        ));

        let node = HashNodeSmt::<blake3::Hasher>::padding(&idx, secret);
        assert!(
            node_template::HashNodeSmt::<blake3::Hasher>::verify_padding_node(
                &node.get_proof_node(),
                &node.prove_padding_node(&idx, &secret),
                &idx,
            )
        );
    }
}

impl<
        P: Default
            + Clone
            + Mergeable
            + Paddable
            + ProofExtractable
            + Rand
            + TypeName
            + PaddingProvable,
    > Tester<P>
where
    <P as ProofExtractable>::ProofNode:
        Debug + Clone + Default + Eq + Debug + Mergeable + Serializable,
    <P as PaddingProvable>::PaddingProof: Clone + Default + Eq + Serializable,
{
    fn test_building_smt(list: &[(TreeIndex, P)]) -> SMT<P> {
        let secret = &ALL_ZEROS_SECRET;
        // Build the SMT from a list.
        let mut build_tree = SMT::new(TREE_HEIGHT);
        build_tree.build(&list, secret);

        // Build the SMT by updating elements in the list one by one.
        let mut update_tree = SMT::new(TREE_HEIGHT);
        for item in list.iter() {
            update_tree.update(&item.0, item.1.clone(), secret);
        }

        // The roots of two SMT should be the same.
        assert_eq!(build_tree.get_root(), update_tree.get_root());

        // Compare the types of nodes in the two differently constructed SMTs.
        assert_eq!(
            build_tree.get_leaves().len(),
            update_tree.get_leaves().len()
        );
        assert_eq!(
            build_tree.get_paddings().len(),
            update_tree.get_paddings().len()
        );
        assert_eq!(
            build_tree.get_internals().len(),
            update_tree.get_internals().len()
        );

        build_tree
    }

    fn merkle_proof_existing(tree: &SMT<P>, leaves: &[P::ProofNode], list: &[TreeIndex]) -> bool {
        let proof = MerkleProof::<P>::generate_inclusion_proof(&tree, list);
        match proof {
            None => unreachable!(),
            Some(proof) => {
                // Test encoding of Merkle proof.
                let serialized_proof = proof.serialize();
                let deserialized_proof = MerkleProof::<P>::deserialize(&serialized_proof).unwrap();
                deserialized_proof.verify_inclusion_proof(leaves, &tree.get_root())
            }
        }
    }

    fn test_merkle_proof(list: &[(TreeIndex, P)], tree: &SMT<P>) {
        // Test single node Merkle proof generation and verification.
        for item in list.iter() {
            assert!(Tester::<P>::merkle_proof_existing(
                tree,
                &[item.1.get_proof_node()],
                &[item.0]
            ));
        }
    }

    fn test_merkle_proof_batch(list: &[(TreeIndex, P)], tree: &SMT<P>) {
        // Test batched Merkle proof generation and verification.

        // Test batched proof of an empty list of tree indexes.
        assert!(Tester::<P>::merkle_proof_existing(tree, &[], &[]));

        // Test batched proof of lists of various lengths.
        for batch_size in &[1, 100, list.len()] {
            for i in 0..LEAF_NUM / batch_size {
                let mut proof_list = Vec::new();
                let mut leaves = Vec::new();
                for j in 0..*batch_size {
                    proof_list.push(list[i * batch_size + j].0);
                    leaves.push(list[i * batch_size + j].1.get_proof_node());
                }
                assert!(Tester::<P>::merkle_proof_existing(
                    tree,
                    &leaves,
                    &proof_list
                ));
            }
        }
    }

    fn random_sampling(tree: &SMT<P>, idx: &TreeIndex) -> bool {
        let secret = &ALL_ZEROS_SECRET;

        let proof = RandomSamplingProof::<P>::random_sampling(tree, idx, secret);
        let serialized = proof.serialize();
        let deserialized = RandomSamplingProof::<P>::deserialize(&serialized).unwrap();
        deserialized.verify_random_sampling_proof(&tree.get_root())
    }

    fn test_random_sampling(list: &[(TreeIndex, P)], tree: &SMT<P>) {
        let secret = &ALL_ZEROS_SECRET;
        // Test random sampling.

        // When the index looked up exists.
        for item in list.iter() {
            assert!(Tester::<P>::random_sampling(tree, &item.0));
        }

        // When no node exists.
        let empty_tree: SMT<P> = SMT::new(TREE_HEIGHT);
        assert!(Tester::<P>::random_sampling(&empty_tree, &list[0].0));

        // When the index looked up doesn't exist and left neighbour doesn't exist.
        let index = list[0].0.get_left_index();
        if let Some(index) = index {
            assert!(Tester::<P>::random_sampling(tree, &index));
            let proof = RandomSamplingProof::<P>::random_sampling(tree, &index, secret);
            assert_eq!(proof.get_merkle_proof().get_indexes().len(), 1);
            assert_eq!(proof.get_merkle_proof().get_indexes()[0], list[0].0);
        }

        // When the index looked up doesn't exist and right neighbour doesn't exist.
        let index = list[list.len() - 1].0.get_right_index();
        if let Some(index) = index {
            assert!(Tester::<P>::random_sampling(tree, &index));
            let proof = RandomSamplingProof::<P>::random_sampling(tree, &index, secret);
            assert_eq!(proof.get_merkle_proof().get_indexes().len(), 1);
            assert_eq!(
                proof.get_merkle_proof().get_indexes()[0],
                list[list.len() - 1].0
            );
        }

        // When the index looked up doesn't exist but both neighbours exist.
        for i in 1..list.len() {
            let index = list[i].0.get_left_index().unwrap();
            if index > list[i - 1].0 {
                assert!(Tester::<P>::random_sampling(tree, &index));
                let proof = RandomSamplingProof::<P>::random_sampling(tree, &index, secret);
                assert_eq!(proof.get_merkle_proof().get_indexes().len(), 2);
                assert_eq!(proof.get_merkle_proof().get_indexes()[0], list[i - 1].0);
                assert_eq!(proof.get_merkle_proof().get_indexes()[1], list[i].0);
            }

            let index = list[i - 1].0.get_right_index().unwrap();
            if index < list[i].0 {
                assert!(Tester::<P>::random_sampling(tree, &index));
                let proof = RandomSamplingProof::<P>::random_sampling(tree, &index, secret);
                assert_eq!(proof.get_merkle_proof().get_indexes().len(), 2);
                assert_eq!(proof.get_merkle_proof().get_indexes()[0], list[i - 1].0);
                assert_eq!(proof.get_merkle_proof().get_indexes()[1], list[i].0);
            }
        }
    }

    pub fn test() {
        for _iter in 0..10 {
            println!(
                "Test #{} for SMT({}) with {} leaves of {} starts!",
                _iter,
                TREE_HEIGHT,
                LEAF_NUM,
                P::get_name()
            );

            let list: Vec<(TreeIndex, P)> =
                generate_sorted_index_value_pairs(TREE_HEIGHT, LEAF_NUM);
            let tree = Tester::<P>::test_building_smt(&list);
            Tester::<P>::test_merkle_proof(&list, &tree);
            Tester::<P>::test_merkle_proof_batch(&list, &tree);
            Tester::<P>::test_random_sampling(&list, &tree);
            println!("Succeed!");
        }
    }
}

#[test]
fn test_smt() {
    Tester::<node_template::SumNodeSmt>::test();
    Tester::<node_template::HashNodeSmt<blake3::Hasher>>::test();
    Tester::<node_template::HashNodeSmt<blake2::Blake2b>>::test();
    Tester::<node_template::HashNodeSmt<sha2::Sha256>>::test();
    Tester::<node_template::HashNodeSmt<sha3::Sha3_256>>::test();
}

#[test]
fn test_merkle_tree() {
    let list: Vec<HashNodeSmt<blake3::Hasher>> = vec![HashNodeSmt::default(); 5];
    let tree = SMT::<HashNodeSmt<blake3::Hasher>>::new_merkle_tree(&list);
    print_output(&tree);
}
