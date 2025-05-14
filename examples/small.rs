use merkle::MerkleTree;
use sha2::{Digest, Sha256};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let contents = vec!["Hello", "Hi", "Hey", "Hola"];

    let mtree = MerkleTree::new(&contents);

    for value in &contents {
        let hash = Sha256::digest(value);
        let _proofs = mtree.generate_proofs(hash.as_ref()).unwrap();
    }
}
