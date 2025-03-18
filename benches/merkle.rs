use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hmac_sha256::Hash;
use merkle::merkle::MerkleTree;

fn bench_create_merkle_tree(c: &mut Criterion) {
    c.bench_function("create merkle tree", |b| b.iter(|| {
        let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

        let mut hashes: Vec<[u8; 32]> = vec![];
        for data in contents {
            let hash = Hash::hash(data.as_bytes());
            hashes.push(hash);
        }

        let mtree = MerkleTree::new(hashes);
        let _root = mtree.root_hash();
    }));
}

fn bench_generate_proof(c: &mut Criterion) {
    c.bench_function("create merkle proofs and verify", |b| b.iter(|| {
        let contents = black_box(vec!["a", "b", "c", "d", "e", "f", "g"]);

        let mut hashes: Vec<[u8; 32]> = vec![];
        for data in &contents {
            let hash = Hash::hash(data.as_bytes());
            hashes.push(hash);
        }

        // // generate a number to pick which hash index we are generating the proof for
        // let mut rng = rand::thread_rng();
        // let i: usize = rng.gen::<usize>() % contents.len();

        let i = contents.len() / 2;

        let hash = hashes[i].clone();

        let mtree = MerkleTree::new(hashes);

        let proofs = mtree.generate_proofs(hash).unwrap();
        let expected_root = mtree.root_hash();

        let root = MerkleTree::verify(contents[i].as_bytes().to_vec(), proofs);

        assert_eq!(&root, expected_root);
    }));
}

fn bench_create_merkle_tree_1234(c: &mut Criterion) {
    c.bench_function("create merkle tree - 1234", |b| b.iter(|| {
        let contents = black_box(vec!["one", "two", "three", "four"]);

        let mut hashes: Vec<[u8; 32]> = vec![];
        for data in contents {
            let hash = Hash::hash(data.as_bytes());
            hashes.push(hash);
        }

        let _mtree = MerkleTree::new(hashes);
        // let _root = mtree.root_hash();
    }));
}


criterion_group!(
    benches,
    bench_create_merkle_tree,
    bench_generate_proof,
    bench_create_merkle_tree_1234,
);
criterion_main!(benches);