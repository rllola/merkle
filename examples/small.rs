use merkle::merkle::MerkleTree;
use sha2::{Sha256, Digest};

fn main() {
    let contents = vec!["Hello", "Hi", "Hey", "Hola"];

    let mut hashes: Vec<[u8; 32]> = vec![];
    for data in contents {
        let hash = Sha256::digest(data.as_bytes()).into();
        hashes.push(hash);
    }

    let _mtree = MerkleTree::new(hashes);

}