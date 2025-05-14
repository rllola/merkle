use criterion::{black_box, criterion_group, criterion_main, Criterion};
use merkle::MerkleTree;
use rand::RngCore;
use sha2::{Digest, Sha256};

fn bench_create_merkle_tree(c: &mut Criterion) {
    c.bench_function("create merkle tree and calculate root", |b| {
        b.iter(|| {
            let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

            let mtree = MerkleTree::new(&contents);
            let _root = mtree.root_hash();
        })
    });
}

fn bench_generate_proof(c: &mut Criterion) {
    c.bench_function("create merkle proofs and verify", |b| {
        b.iter(|| {
            let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

            let i = contents.len() / 2;

            let mid = contents[i].as_bytes();
            let hash = Sha256::digest(&mid);

            let mtree = MerkleTree::new(&contents);

            let proofs = mtree.generate_proofs(hash.as_ref()).unwrap();
            let expected_root = mtree.root_hash();

            let root = MerkleTree::verify(mid.to_vec(), proofs);

            assert_eq!(&root, expected_root);
        })
    });
}

fn bench_create_merkle_tree_1234(c: &mut Criterion) {
    c.bench_function("create merkle tree - 1234", |b| {
        b.iter(|| {
            let contents = black_box(vec!["one", "two", "three", "four"]);

            let _mtree = MerkleTree::new(&contents);
        })
    });
}

fn bench_generate_proof_1234(c: &mut Criterion) {
    c.bench_function("generate merkle proof - 1234", |b| {
        let contents = vec!["one", "two", "three", "four"];

        let tmp = contents.clone();
        let mtree = MerkleTree::new(&contents);

        b.iter(|| {
            for value in &tmp {
                let hash = Sha256::digest(value);
                let _proofs = mtree.generate_proofs(black_box(hash.as_ref())).unwrap();
            }
        })
    });
}

fn bench_create_merkle_tree_big(c: &mut Criterion) {
    c.bench_function("create merkle tree - big", |b| {
        b.iter(|| {
            let mut contents: Vec<&[u8]> = vec![&[0u8; 256]; 160];
            let mut rng = rand::rng();

            for v in &mut contents {
                rng.fill_bytes(&mut v.to_owned());
            }

            let _mtree = MerkleTree::new(black_box(&contents));
        })
    });
}

fn bench_generate_proof_big(c: &mut Criterion) {
    c.bench_function("generate merkle proof - big", |b| {
        let mut contents: Vec<&[u8]> = vec![&[0u8; 256]; 160];
        let mut rng = rand::rng();

        for v in &mut contents {
            rng.fill_bytes(&mut v.to_owned());
        }
        let mtree = MerkleTree::new(&contents);

        b.iter(|| {
            for value in &contents {
                let hash = Sha256::digest(value);
                let _proofs = mtree.generate_proofs(black_box(hash.as_ref())).unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    bench_create_merkle_tree,
    bench_generate_proof,
    bench_create_merkle_tree_1234,
    bench_generate_proof_1234,
    bench_create_merkle_tree_big,
    bench_generate_proof_big,
);
criterion_main!(benches);
