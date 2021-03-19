// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::cmp::Eq;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};

use smtree::pad_secret::ALL_ZEROS_SECRET;
use smtree::{
    index::TreeIndex,
    node_template::{HashNodeSmt, SumNodeSmt},
    traits::{Mergeable, Paddable, ProofExtractable, Rand, Serializable, TypeName},
    tree::SparseMerkleTree,
};

type SMT<P> = SparseMerkleTree<P>;

type List<P> = Vec<(TreeIndex, P)>;

pub fn bench_build<
    P: 'static + Mergeable + Paddable + ProofExtractable + Rand + TypeName + Clone + Default + Eq,
>(
    c: &mut Criterion,
) where
    <P as ProofExtractable>::ProofNode: Debug + Clone + Default + Eq + Mergeable + Serializable,
{
    let name = P::get_name();
    const LEAF_NUM: u64 = 1_000_000;
    const TREE_HEIGHT: usize = 256;
    c.bench_function(
        &format!(
            "Build SMT({}) from {} leaves of {}",
            TREE_HEIGHT, LEAF_NUM, name
        ),
        |b| {
            b.iter(|| {
                println!("Start!");
                let time = Instant::now();
                let mut list: List<P> = Vec::new();
                let mut set: HashSet<TreeIndex> = HashSet::new();
                let mut sum = P::default();
                for _i in 0..LEAF_NUM {
                    sum.randomize();
                    loop {
                        let mut idx = TreeIndex::zero(TREE_HEIGHT);
                        idx.randomize();
                        if !set.contains(&idx) {
                            list.push((idx, sum.clone()));
                            set.insert(idx);
                            break;
                        }
                    }
                }
                println!("Finish in {:?} ms", time.elapsed().as_millis());
                println!("Start!");
                let time = Instant::now();
                let mut tree = SMT::new(TREE_HEIGHT);
                tree.build(&list, &ALL_ZEROS_SECRET);
                println!("Finish in {:?} ms", time.elapsed().as_millis());
            })
        },
    );
}

pub fn bench_update<
    P: 'static + Mergeable + Paddable + ProofExtractable + Rand + TypeName + Clone + Default,
>(
    c: &mut Criterion,
) where
    <P as ProofExtractable>::ProofNode: Debug + Clone + Default + Eq + Mergeable + Serializable,
{
    const LEAF_NUM: u64 = 1_000_000;
    const TREE_HEIGHT: usize = 32;
    let name = P::get_name();
    c.bench_function(
        &format!(
            "Build SMT({}) from {} leaves of {} by updating each leaf",
            TREE_HEIGHT, LEAF_NUM, name
        ),
        |b| {
            b.iter(|| {
                println!("Start!");
                let time = Instant::now();
                let mut list: List<P> = Vec::new();
                let mut set: HashSet<TreeIndex> = HashSet::new();
                let mut sum = P::default();
                for _i in 0..LEAF_NUM {
                    sum.randomize();
                    loop {
                        let mut idx = TreeIndex::zero(TREE_HEIGHT);
                        idx.randomize();
                        if !set.contains(&idx) {
                            list.push((idx, sum.clone()));
                            set.insert(idx);
                            break;
                        }
                    }
                }
                println!("Finish in {:?} ms", time.elapsed().as_millis());
                println!("Start!");
                let time = Instant::now();
                let mut tree = SMT::new(TREE_HEIGHT);
                for item in list.iter() {
                    tree.update(&item.0, item.1.clone(), &ALL_ZEROS_SECRET);
                }
                println!("Finish in {:?} ms", time.elapsed().as_millis());
            })
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
              bench_build<SumNodeSmt>,
              bench_build<HashNodeSmt::<blake3::Hasher>>,
              bench_build<HashNodeSmt<blake2::Blake2b>>,
              bench_build<HashNodeSmt<sha2::Sha256>>,
              bench_build<HashNodeSmt<sha3::Sha3_256>>
}
criterion_main!(benches);
