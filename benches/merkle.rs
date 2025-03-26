use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};
use merkle::merkle::MerkleTree;
use rand::RngCore;

fn bench_create_merkle_tree(c: &mut Criterion) {
    c.bench_function("create merkle tree and calculate root", |b| {
        b.iter(|| {
            let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

            let mut hashes: Vec<[u8; 32]> = vec![];
            for data in contents {
                let hash = Sha256::digest(data.as_bytes()).into();
                hashes.push(hash);
            }

            let mtree = MerkleTree::new(hashes);
            let _root = mtree.root_hash();
        })
    });
}

fn bench_generate_proof(c: &mut Criterion) {
    c.bench_function("create merkle proofs and verify", |b| {
        b.iter(|| {
            let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

            let mut hashes: Vec<[u8; 32]> = vec![];
            for data in &contents {
                let hash = Sha256::digest(data.as_bytes()).into();
                hashes.push(hash);
            }

            let i = contents.len() / 2;

            let hash = hashes[i].clone();

            let mtree = MerkleTree::new(hashes);

            let proofs = mtree.generate_proofs(hash).unwrap();
            let expected_root = mtree.root_hash();

            let root = MerkleTree::verify(contents[i].as_bytes().to_vec(), proofs);

            assert_eq!(&root, expected_root);
        })
    });
}

fn bench_create_merkle_tree_1234(c: &mut Criterion) {
    c.bench_function("create merkle tree - 1234", |b| {
        b.iter(|| {
            let contents = black_box(vec!["one", "two", "three", "four"]);

            let mut hashes: Vec<[u8; 32]> = vec![];
            for data in contents {
                let hash = Sha256::digest(data.as_bytes()).into();
                hashes.push(hash);
            }

            let _mtree = MerkleTree::new(hashes);
        })
    });
}

fn bench_generate_proof_1234(c: &mut Criterion) {
    c.bench_function("generate merkle proof - 1234", |b| {
        let contents = vec!["one", "two", "three", "four"];

        let mut hashes: Vec<[u8; 32]> = vec![];
        for data in contents {
            let hash = Sha256::digest(data.as_bytes()).into();
            hashes.push(hash);
        }

        let tmp = hashes.clone();
        let mtree = MerkleTree::new(hashes);

        b.iter(|| {
            for value in &tmp {
                let hash = black_box(value).clone();
                let _proofs = mtree.generate_proofs(hash).unwrap();
            }

        })
    });
}

fn bench_create_merkle_tree_big(c: &mut Criterion) {
    c.bench_function("create merkle tree - big", |b| {
        let mut contents = vec![vec![0u8; 256]; 160];
        let mut rng = rand::rng();

        for mut v in &mut contents {
            rng.fill_bytes(&mut v);
        }

        b.iter(|| {
            let mut hashes: Vec<[u8; 32]> = vec![];
            for data in &contents {
                let hash = Sha256::digest(data).into();
                hashes.push(hash);
            }

            let _mtree = MerkleTree::new(hashes);
        })
    });
}

fn bench_generate_proof_big(c: &mut Criterion) {
    c.bench_function("generate merkle proof - big", |b| {
        let mut contents = vec![vec![0u8; 256]; 160];
        let mut rng = rand::rng();

        for mut v in &mut contents {
            rng.fill_bytes(&mut v);
        }

        let mut hashes: Vec<[u8; 32]> = vec![];
        for data in &contents {
            let hash = Sha256::digest(data).into();
            hashes.push(hash);
        }
        let tmp = hashes.clone();
        let mtree = MerkleTree::new(hashes);

        b.iter(|| {
            for value in &tmp {
                let hash = black_box(value.clone());
                let _proofs = mtree.generate_proofs(hash).unwrap();
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
