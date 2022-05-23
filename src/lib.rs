use tiny_keccak::{Hasher, Keccak};

pub struct MerkleTree {}

impl MerkleTree {
    pub fn new() -> Self {
        Self {}
    }
}

pub fn verify_proof(root: [u8; 32], proof: Vec<[u8; 32]>, leaf: [u8; 32]) -> bool {
    let mut current = leaf;
    for elem in proof {
        if current <= elem {
            current = keccak256(&[current, elem].concat());
        } else {
            current = keccak256(&[elem, current].concat());
        }
    }
    return current == root;
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    return output;
}
