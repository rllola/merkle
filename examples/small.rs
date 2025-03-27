use merkle::merkle::MerkleTree;
use sha2::{Digest, Sha256};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

    let mtree = MerkleTree::new(&contents);

    for value in &contents {
        let hash = Sha256::digest(value).into();
        dbg!(hex::encode(&hash));
        let _proofs = mtree.generate_proofs(hash).unwrap();
    }
}
