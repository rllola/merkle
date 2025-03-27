use merkle::merkle::MerkleTree;
use rand::RngCore;
use std::time::Instant;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();
    let start = Instant::now();

    let mut contents: Vec<&[u8]> = vec![&[0u8; 256]; 100000];
    let mut rng = rand::rng();

    for v in &mut contents {
        rng.fill_bytes(&mut v.to_owned());
    }

    let _mtree = MerkleTree::new(&contents);

    println!("Time elapsed : {:?}", start.elapsed());
}
