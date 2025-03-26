use merkle_other::MerkleTree;
use rand::RngCore;
use ring::digest::{Algorithm, SHA256};
use std::time::Instant;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;
static DIGEST: &Algorithm = &SHA256;

fn main() {
    let _profiler = dhat::Profiler::new_heap();
    let start = Instant::now();

    let mut contents = vec![vec![0u8; 256]; 100000];
    let mut rng = rand::rng();

    for mut v in &mut contents {
        rng.fill_bytes(&mut v);
    }

    let _mtree = MerkleTree::from_vec(DIGEST, contents);

    println!("Time elapsed : {:?}", start.elapsed());

}
