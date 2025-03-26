use merkle::merkle::MerkleTree;
use sha2::{Digest, Sha256};
use rand::RngCore;
use std::time::Instant;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();
    let start = Instant::now();
    
    let mut contents = vec![vec![0u8; 256]; 100000];
    let mut rng = rand::rng();

    for mut v in &mut contents {
        rng.fill_bytes(&mut v);
    }

    let mut hashes: Vec<[u8; 32]> = vec![];
    for data in &contents {
        let hash = Sha256::digest(data).into();
        hashes.push(hash);
    }

    let _mtree = MerkleTree::new(hashes);

    println!("Time elapsed : {:?}", start.elapsed());
}
