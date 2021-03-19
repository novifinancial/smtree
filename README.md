# SMTree :: Paddable Sparse Merkle Tree

SMTree is a flexible sparse tree accumulator that can support various tree types 
via traits for custom node-merging and tree-padding logic. The api supports inclusion
proofs for a single or multiple leaves (batch proofs), efficient logN padding to hide
number of leaves (implied by tree height) and random sampling 
by returning the closest leaf to the input index. 

The above functionality is required by applications utilizing sparse Merkle trees for hiding the 
leaf-population in a tree-based accumulator, such as the [HashWires](https://eprint.iacr.org/2021/297) range proof 
and [DAPOL](https://eprint.iacr.org/2020/468) auditing proof constructions. Similarly, one can easily implement tree 
constructions like Maxwell liability trees in Bitcoin, simple summation, XOR or alphabetically merged Merkle trees and try 
performance comparison with different hash functions.

Documentation
-------------

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

You can find reference implementations for various tree types in [node_template.rs](https://github.com/novifinancial/smtree/blob/master/src/node_template.rs).

If you want to enable random sampling for your sparse Merkle tree, you need to further
implement the ```PaddingProvable``` trait. We provide a reference implementation in the `HashNodeSmt` struct in [node_template.rs](https://github.com/novifinancial/smtree/blob/master/src/node_template.rs). 

Now you are all prepared to build your sparse Merkle tree!

Contributors
------------

The original authors of this code are Konstantinos Chalkias
([@kchalkias](https://github.com/kchalkias)) and Yan Ji ([@iseriohn](https://github.com/iseriohn)), with contributions 
from Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)) and Irakliy Khaburzaniya ([@irakliyk](https://github.com/irakliyk)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

License
-------

This project is [MIT licensed](./LICENSE).
