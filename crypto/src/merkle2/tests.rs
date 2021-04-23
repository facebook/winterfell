// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use proptest::prelude::*;

use super::*;
use crate::hash::Blake3_256;

static LEAVES4: [[u8; 32]; 4] = [
    [
        166, 168, 47, 140, 153, 86, 156, 86, 226, 229, 149, 76, 70, 132, 209, 109, 166, 193, 113,
        197, 42, 116, 170, 144, 74, 104, 29, 110, 220, 49, 224, 123,
    ],
    [
        243, 57, 40, 140, 185, 79, 188, 229, 232, 117, 143, 118, 235, 229, 73, 251, 163, 246, 151,
        170, 14, 243, 255, 127, 175, 230, 94, 227, 214, 5, 89, 105,
    ],
    [
        11, 33, 220, 93, 26, 67, 166, 154, 93, 7, 115, 130, 70, 13, 166, 45, 120, 233, 175, 86,
        144, 110, 253, 250, 67, 108, 214, 115, 24, 132, 45, 234,
    ],
    [
        47, 173, 224, 232, 30, 46, 197, 186, 215, 15, 134, 211, 73, 14, 34, 216, 6, 11, 217, 150,
        90, 242, 8, 31, 73, 85, 150, 254, 229, 244, 23, 231,
    ],
];

static LEAVES8: [[u8; 32]; 8] = [
    [
        115, 29, 176, 48, 97, 18, 34, 142, 51, 18, 164, 235, 236, 96, 113, 132, 189, 26, 70, 93,
        101, 143, 142, 52, 252, 33, 80, 157, 194, 52, 209, 129,
    ],
    [
        52, 46, 37, 214, 24, 248, 121, 199, 229, 25, 171, 67, 65, 37, 98, 142, 182, 72, 202, 42,
        223, 160, 136, 60, 38, 255, 222, 82, 26, 27, 130, 203,
    ],
    [
        130, 43, 231, 0, 59, 228, 152, 140, 18, 33, 87, 27, 49, 190, 44, 82, 188, 155, 163, 108,
        166, 198, 106, 143, 83, 167, 201, 152, 106, 176, 242, 119,
    ],
    [
        207, 158, 56, 143, 28, 146, 238, 47, 169, 32, 166, 97, 163, 238, 171, 243, 33, 209, 120,
        219, 17, 182, 96, 136, 13, 90, 6, 27, 247, 242, 49, 111,
    ],
    [
        179, 64, 123, 119, 226, 139, 161, 127, 36, 251, 218, 88, 20, 217, 212, 85, 112, 85, 185,
        193, 230, 181, 4, 22, 54, 219, 135, 98, 235, 180, 182, 7,
    ],
    [
        101, 240, 19, 44, 43, 213, 31, 138, 39, 26, 82, 147, 255, 96, 234, 51, 105, 6, 233, 144,
        255, 187, 242, 3, 157, 246, 55, 175, 98, 121, 92, 175,
    ],
    [
        25, 96, 149, 179, 94, 8, 170, 214, 169, 135, 12, 212, 224, 157, 182, 127, 233, 93, 151,
        214, 36, 183, 156, 212, 233, 152, 125, 244, 146, 161, 75, 128,
    ],
    [
        247, 43, 130, 141, 234, 172, 61, 187, 109, 31, 56, 30, 14, 232, 92, 158, 48, 161, 108, 234,
        170, 180, 233, 77, 200, 248, 45, 152, 125, 11, 1, 171,
    ],
];

#[test]
fn new_tree() {
    let leaves = LEAVES4.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);
    let root = hash_2x1(
        &hash_2x1(&LEAVES4[0], &LEAVES4[1]),
        &hash_2x1(&LEAVES4[2], &LEAVES4[3]),
    );
    assert_eq!(&root, tree.root());

    let leaves = LEAVES8.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);
    let root = hash_2x1(
        &hash_2x1(
            &hash_2x1(&LEAVES8[0], &LEAVES8[1]),
            &hash_2x1(&LEAVES8[2], &LEAVES8[3]),
        ),
        &hash_2x1(
            &hash_2x1(&LEAVES8[4], &LEAVES8[5]),
            &hash_2x1(&LEAVES8[6], &LEAVES8[7]),
        ),
    );
    assert_eq!(&root, tree.root());
}

#[test]
fn prove() {
    // depth 4
    let leaves = LEAVES4.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);

    let proof = vec![LEAVES4[1], LEAVES4[0], hash_2x1(&LEAVES4[2], &LEAVES4[3])];
    assert_eq!(proof, tree.prove(1));

    let proof = vec![LEAVES4[2], LEAVES4[3], hash_2x1(&LEAVES4[0], &LEAVES4[1])];
    assert_eq!(proof, tree.prove(2));

    // depth 5
    let leaves = LEAVES8.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);

    let proof = vec![
        LEAVES8[1],
        LEAVES8[0],
        hash_2x1(&LEAVES8[2], &LEAVES8[3]),
        hash_2x1(
            &hash_2x1(&LEAVES8[4], &LEAVES8[5]),
            &hash_2x1(&LEAVES8[6], &LEAVES8[7]),
        ),
    ];
    assert_eq!(proof, tree.prove(1));

    let proof = vec![
        LEAVES8[6],
        LEAVES8[7],
        hash_2x1(&LEAVES8[4], &LEAVES8[5]),
        hash_2x1(
            &hash_2x1(&LEAVES8[0], &LEAVES8[1]),
            &hash_2x1(&LEAVES8[2], &LEAVES8[3]),
        ),
    ];
    assert_eq!(proof, tree.prove(6));
}

#[test]
fn verify() {
    // depth 4
    let leaves = LEAVES4.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);
    let proof = tree.prove(1);
    assert_eq!(
        true,
        MerkleTree::<Blake3_256>::verify(*tree.root(), 1, &proof)
    );

    let proof = tree.prove(2);
    assert_eq!(
        true,
        MerkleTree::<Blake3_256>::verify(*tree.root(), 2, &proof)
    );

    // depth 5
    let leaves = LEAVES8.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);
    let proof = tree.prove(1);
    assert_eq!(
        true,
        MerkleTree::<Blake3_256>::verify(*tree.root(), 1, &proof)
    );

    let proof = tree.prove(6);
    assert_eq!(
        true,
        MerkleTree::<Blake3_256>::verify(*tree.root(), 6, &proof)
    );
}

#[test]
fn prove_batch() {
    let leaves = LEAVES8.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);

    // 1 index
    let proof = tree.prove_batch(&[1]);
    let expected_values = vec![LEAVES8[1]];
    let expected_nodes = vec![vec![
        LEAVES8[0],
        hash_2x1(&LEAVES8[2], &LEAVES8[3]),
        hash_2x1(
            &hash_2x1(&LEAVES8[4], &LEAVES8[5]),
            &hash_2x1(&LEAVES8[6], &LEAVES8[7]),
        ),
    ]];
    assert_eq!(expected_values, proof.values);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);

    // 2 indexes
    let proof = tree.prove_batch(&[1, 2]);
    let expected_values = vec![LEAVES8[1], LEAVES8[2]];
    let expected_nodes = vec![
        vec![
            LEAVES8[0],
            hash_2x1(
                &hash_2x1(&LEAVES8[4], &LEAVES8[5]),
                &hash_2x1(&LEAVES8[6], &LEAVES8[7]),
            ),
        ],
        vec![LEAVES8[3]],
    ];
    assert_eq!(expected_values, proof.values);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);

    // 2 indexes on opposite sides
    let proof = tree.prove_batch(&[1, 6]);
    let expected_values = vec![LEAVES8[1], LEAVES8[6]];
    let expected_nodes = vec![
        vec![LEAVES8[0], hash_2x1(&LEAVES8[2], &LEAVES8[3])],
        vec![LEAVES8[7], hash_2x1(&LEAVES8[4], &LEAVES8[5])],
    ];
    assert_eq!(expected_values, proof.values);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);

    // all indexes
    let proof = tree.prove_batch(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let expected_values = LEAVES8.to_vec();
    let expected_nodes: Vec<Vec<[u8; 32]>> = vec![vec![], vec![], vec![], vec![]];
    assert_eq!(expected_values, proof.values);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);
}

#[test]
fn verify_batch() {
    let leaves = LEAVES8.to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves);

    let proof = tree.prove_batch(&[1]);
    assert_eq!(true, MerkleTree::verify_batch(tree.root(), &[1], &proof));
    assert_eq!(false, MerkleTree::verify_batch(tree.root(), &[2], &proof));

    let proof = tree.prove_batch(&[1, 2]);
    assert_eq!(true, MerkleTree::verify_batch(tree.root(), &[1, 2], &proof));
    assert_eq!(false, MerkleTree::verify_batch(tree.root(), &[1], &proof));
    assert_eq!(
        false,
        MerkleTree::verify_batch(tree.root(), &[1, 3], &proof)
    );
    assert_eq!(
        false,
        MerkleTree::verify_batch(tree.root(), &[1, 2, 3], &proof)
    );

    let proof = tree.prove_batch(&[1, 6]);
    assert_eq!(true, MerkleTree::verify_batch(tree.root(), &[1, 6], &proof));

    let proof = tree.prove_batch(&[1, 3, 6]);
    assert_eq!(
        true,
        MerkleTree::verify_batch(tree.root(), &[1, 3, 6], &proof)
    );

    let proof = tree.prove_batch(&[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        true,
        MerkleTree::verify_batch(tree.root(), &[0, 1, 2, 3, 4, 5, 6, 7], &proof)
    );
}

proptest! {
    #[test]
    fn prove_n_verify(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        for proof_index in proof_indices{
            let proof = tree.prove(proof_index.index(128));
            prop_assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), proof_index.index(128), &proof))
        }
    }

    #[test]
    fn prove_batch_n_verify(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        let mut indices: Vec<usize> = proof_indices.iter().map(|idx| idx.index(128)).collect();
        indices.sort_unstable(); indices.dedup();
        let proof = tree.prove_batch(&indices[..]);
        prop_assert!(MerkleTree::verify_batch(tree.root(), &indices[..], &proof));
    }

    #[test]
    fn batch_proof_from_paths(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        let mut indices: Vec<usize> = proof_indices.iter().map(|idx| idx.index(128)).collect();
        indices.sort_unstable(); indices.dedup();
        let proof1 = tree.prove_batch(&indices[..]);

        let mut paths = Vec::new();
        for &idx in indices.iter() {
            paths.push(tree.prove(idx));
        }
        let proof2 = BatchMerkleProof::from_paths(&paths, &indices);

        prop_assert!(proof1 == proof2);
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------
fn hash_2x1(v1: &[u8; 32], v2: &[u8; 32]) -> [u8; 32] {
    Blake3_256::merge(&[*v1, *v2])
}

pub fn random_blake3_merkle_tree(
    leave_count: usize,
) -> impl Strategy<Value = MerkleTree<Blake3_256>> {
    prop::collection::vec(any::<[u8; 32]>(), leave_count)
        .prop_map(|leaves| MerkleTree::<Blake3_256>::new(leaves))
}
