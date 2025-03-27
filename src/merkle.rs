use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;
use std::rc::Weak;

pub struct MerkleTree {
    root: Rc<Node>,
    leaves: Vec<Rc<Node>>,
}

impl MerkleTree {
    pub fn new(values: &Vec<&[u8]>) -> Self {
        let nodes: Vec<Rc<Node>> = values
            .into_iter()
            .map(|value| {
                let hash = Sha256::digest(value).into();
                Rc::new(Node::Leaf {
                    hash,
                    parent: RefCell::new(Weak::new()),
                })
            })
            .collect();

        let mut tree = Self::build_tree(&nodes);
        tree.leaves.extend(nodes);

        return tree;
    }

    fn build_tree(items: &Vec<Rc<Node>>) -> Self {
        if items.len() == 1 {
            return Self {
                root: Rc::clone(&items[0]),
                leaves: vec![],
            };
        }

        let mut nodes: Vec<Rc<Node>> = vec![];
        for i in (0..items.len()).step_by(2) {
            let n: Rc<Node>;
            if i + 1 >= items.len() {
                // if we have an odd number of nodes we duplicate the last one to calculate the hash
                let hash =
                    Sha256::digest(&[items[i].hash().to_vec(), items[i].hash().to_vec()].concat())
                        .into();
                let left = Rc::clone(&items[i]);
                let right = Rc::new(Node::Empty);

                n = Rc::new(Node::Node {
                    hash,
                    parent: RefCell::new(Weak::new()),
                    left,
                    right,
                });

                // update parent nodes
                items[i].set_parent(&n);
            } else {
                let hash = Sha256::digest(
                    &[items[i].hash().to_vec(), items[i + 1].hash().to_vec()].concat(),
                )
                .into();
                let left = Rc::clone(&items[i]);
                let right = Rc::clone(&items[i + 1]);

                n = Rc::new(Node::Node {
                    hash,
                    parent: RefCell::new(Weak::new()),
                    left,
                    right,
                });

                // update parent nodes
                items[i].set_parent(&n);
                items[i + 1].set_parent(&n);
            }

            nodes.push(n);
        }

        Self::build_tree(&nodes)
    }

    pub fn root_hash(&self) -> &[u8; 32] {
        self.root.hash()
    }

    pub fn root(&self) -> &Node {
        self.root.as_ref()
    }

    pub fn generate_proofs(
        &self,
        hash: [u8; 32],
    ) -> Result<Vec<([u8; 32], u8)>, Box<dyn Error + 'static>> {
        // lookup for our leaf
        let mut n: &Node = self.root();
        for l in &self.leaves {
            if l.hash() == &hash {
                n = &l;
                break;
            }
        }

        let leaf_proof: Vec<([u8; 32], u8)> = vec![];
        let proofs = Self::gen_proof(&n, leaf_proof);

        Ok(proofs)
    }

    fn gen_proof(n: &Node, proofs: Vec<([u8; 32], u8)>) -> Vec<([u8; 32], u8)> {
        let mut new_proof: Vec<([u8; 32], u8)> = vec![];
        if let None = n.parent() {
            return proofs;
        }

        if let Node::Node { hash, .. } | Node::Leaf { hash, .. } = n {
            let p = n.parent().unwrap(); // unwrap here is not great neither but should work fine.
            let pleft = p.get_left().unwrap(); // We should always have left

            if hash == pleft.hash() {
                // sibling is right then
                let pright = p.get_right().unwrap_or(pleft); // If right is empty we duplicate left
                new_proof.push((pright.hash().clone(), 1));
            } else {
                new_proof.push((pleft.hash().clone(), 0));
            }

            return Self::gen_proof(p.as_ref(), [proofs, new_proof].concat());
        }

        return vec![];
    }

    pub fn verify(data: Vec<u8>, proofs: Vec<([u8; 32], u8)>) -> [u8; 32] {
        let mut hash = Sha256::digest(&data).into();

        for proof in proofs {
            if proof.1 == 1 {
                hash = Sha256::digest(&[hash, proof.0].concat()).into();
            } else {
                hash = Sha256::digest(&[proof.0, hash].concat()).into();
            }
        }

        return hash;
    }
}

#[derive(Debug, Clone)]
pub enum Node {
    Empty,
    Node {
        hash: [u8; 32],
        parent: RefCell<Weak<Node>>,
        left: Rc<Node>,
        right: Rc<Node>,
    },
    Leaf {
        hash: [u8; 32],
        parent: RefCell<Weak<Node>>,
    },
}

impl Node {
    pub fn hash(&self) -> &[u8; 32] {
        match self {
            Node::Node { hash, .. } => hash,
            Node::Leaf { hash, .. } => hash,
            _ => &[0u8; 32],
        }
    }

    pub fn set_parent(&self, p: &Rc<Node>) {
        match self {
            Node::Node { parent, .. } => *parent.borrow_mut() = Rc::downgrade(p), // need to fix this unwrap because we can't set parrent on root.
            Node::Leaf { parent, .. } => *parent.borrow_mut() = Rc::downgrade(p),
            _ => panic!("Empty and root doesnt have a parent"),
        };
    }

    pub fn get_left(&self) -> Option<&Self> {
        match self {
            Node::Node { left, .. } => Some(left),
            _ => None,
        }
    }

    pub fn get_right(&self) -> Option<&Self> {
        match self {
            Node::Node { right, .. } => {
                if let Node::Empty = right.as_ref() {
                    None
                } else {
                    Some(right)
                }
            }
            _ => None,
        }
    }

    pub fn parent(&self) -> Option<Rc<Self>> {
        match self {
            Node::Node { parent, .. } => parent.borrow().upgrade(),
            Node::Leaf { parent, .. } => parent.borrow().upgrade(),
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    // use hmac_sha256::Hash;
    use sha2::{Digest, Sha256};

    use super::MerkleTree;

    #[test]
    fn test_merkle_root() {
        let expected_hash =
            hex::decode("5f30cc80133b9394156e24b233f0c4be32b24e44bb3381f02c7ba52619d0febc")
                .unwrap();
        let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

        let mtree = MerkleTree::new(&contents);

        assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    }

    #[test]
    fn test_proofs_0() {
        let expected_hash =
            hex::decode("5f30cc80133b9394156e24b233f0c4be32b24e44bb3381f02c7ba52619d0febc")
                .unwrap();
        let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

        let first = contents.first().unwrap();
        let hash = Sha256::digest(&first).into();

        let mtree = MerkleTree::new(&contents);

        let proofs = mtree.generate_proofs(hash).unwrap();
        let expected_root = mtree.root_hash();

        assert_eq!(expected_root.to_vec(), expected_hash);

        let root = MerkleTree::verify(first.to_vec(), proofs);

        assert_eq!(&root, expected_root);
    }

    #[test]
    fn test_proofs_1() {
        let expected_hash =
            hex::decode("5f30cc80133b9394156e24b233f0c4be32b24e44bb3381f02c7ba52619d0febc")
                .unwrap();
        let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

        let second = contents[1];
        let hash = Sha256::digest(&second).into();

        let mtree = MerkleTree::new(&contents);

        let proofs = mtree.generate_proofs(hash).unwrap();
        let expected_root = mtree.root_hash();

        assert_eq!(expected_root.to_vec(), expected_hash);

        let root = MerkleTree::verify(second.to_vec(), proofs);

        assert_eq!(&root, expected_root);
    }

    #[test]
    fn test_proofs_2() {
        let expected_hash =
            hex::decode("5f30cc80133b9394156e24b233f0c4be32b24e44bb3381f02c7ba52619d0febc")
                .unwrap();
        let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

        let third = contents[1];
        let hash = Sha256::digest(&third).into();

        let mtree = MerkleTree::new(&contents);

        let proofs = mtree.generate_proofs(hash).unwrap();
        let expected_root = mtree.root_hash();

        assert_eq!(expected_root.to_vec(), expected_hash);

        let root = MerkleTree::verify(third.to_vec(), proofs);

        assert_eq!(&root, expected_root);
    }

    #[test]
    fn test_proofs_3() {
        let expected_hash =
            hex::decode("5f30cc80133b9394156e24b233f0c4be32b24e44bb3381f02c7ba52619d0febc")
                .unwrap();
        let contents = vec!["Hello".as_bytes(), "Hi".as_bytes(), "Hey".as_bytes(), "Hola".as_bytes()];

        let last = contents.last().unwrap();
        let hash = Sha256::digest(&last).into();

        let mtree = MerkleTree::new(&contents);

        let proofs = mtree.generate_proofs(hash).unwrap();
        let expected_root = mtree.root_hash();

        assert_eq!(expected_root.to_vec(), expected_hash);

        let root = MerkleTree::verify(last.to_vec(), proofs);

        assert_eq!(&root, expected_root);
    }

    #[test]
    fn test_root_other_set() {
        // Test from https://github.com/olivmath/merkly/blob/main/test/merkle_root/test_merkle_root.py#L99
        let expected_hash =
            hex::decode("14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7")
                .unwrap();
        let contents = vec!["a".as_bytes(), "b".as_bytes(), "c".as_bytes(), "d".as_bytes()];

        let mtree = MerkleTree::new(&contents);

        assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    }

    #[test]
    fn test_root_other_set_1() {
        let expected_hash =
            hex::decode("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a")
                .unwrap();
        let contents = vec!["a".as_bytes(), "b".as_bytes()];

        let mtree = MerkleTree::new(&contents);

        assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    }

    // #[test]
    // fn test_root_other_set_2() {
    //     let expected_hash = hex::decode("d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba").unwrap();
    //     let contents = vec!["a", "b", "c", "d", "e"];

    //     let mut hashes: Vec<[u8; 32]> = vec![];
    //     for data in contents {
    //         let hash = Sha256::digest(data.as_bytes());
    //         hashes.push(hash);
    //     }

    //     let mtree = MerkleTree::new(hashes);

    //     assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    // }

    #[test]
    fn test_root_other_set_3() {
        // test from https://github.com/merkletreejs/merkletreejs/blob/master/test/MerkleTree.test.js#L188
        let expected_hash =
            hex::decode("44205acec5156114821f1f71d87c72e0de395633cd1589def6d4444cc79f8103")
                .unwrap();
        let contents = vec!["a".as_bytes(), "b".as_bytes(), "c".as_bytes(), "d".as_bytes(), "e".as_bytes(), "f".as_bytes()];

        let mtree = MerkleTree::new(&contents);

        assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    }

    #[test]
    fn test_root_other_set_4() {
        // test from https://github.com/merkletreejs/merkletreejs/blob/master/test/MerkleTree.test.js#L218
        let expected_hash =
            hex::decode("d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe")
                .unwrap();
        let contents = vec!["a".as_bytes(), "b".as_bytes(), "c".as_bytes()];

        let mtree = MerkleTree::new(&contents);

        assert_eq!(mtree.root_hash().to_vec(), expected_hash);
    }
}
