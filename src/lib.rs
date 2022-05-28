use tiny_keccak::{Hasher, Keccak};

pub struct MerkleTree {
    pub layers: Vec<Vec<[u8; 32]>>,
    pub data: Vec<String>,
}

impl MerkleTree {
    pub fn new(items: Vec<&str>) -> Self {
        let mut leaves: Vec<[u8; 32]> = items.iter().map(|i| keccak256(i.as_bytes())).collect();
        // Sort leaves for easier verification
        leaves.sort();
        let layers = build_tree(leaves);
        Self {
            data: items.iter().map(|i| i.to_string()).collect(),
            layers,
        }
    }

    pub fn get_root(&self) -> [u8; 32] {
        return self.layers[0][0];
    }

    // @todo Make prettier :)
    pub fn generate_proof(&self, item: &str) -> Vec<[u8; 32]> {
        let mut proof = Vec::<[u8; 32]>::new();
        let leaf = keccak256(item.as_bytes());
        let leaves = self.layers.last().unwrap();
        let leaf_index = leaves.iter().position(|e| e == &leaf).unwrap();

        // Current index used for traversal, represents the index in the entire tree and not in the layer
        let mut current_index =
            (2 as usize).pow((self.layers.len() - 1).try_into().unwrap()) - 1 + leaf_index;

        for layer_index in (1..self.layers.len()).rev() {
            let layer = &self.layers[layer_index];
            // Internal index represents the index in the current layer
            let internal_index =
                current_index - ((2 as usize).pow((layer_index).try_into().unwrap()) - 1);
            let sibling = if internal_index % 2 == 0 {
                layer[internal_index + 1]
            } else {
                layer[internal_index - 1]
            };
            proof.push(sibling);

            current_index = (current_index - 1) / 2;
        }
        return proof;
    }
}

fn build_tree(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let count = (2 * leaves.len() - 1) as f32;
    let layer_count = count.log2().floor() as usize;
    let mut layers = vec![leaves.to_vec()];
    for layer_index in 1..layer_count + 1 {
        let mut layer = Vec::<[u8; 32]>::new();
        let previous_layer = &layers[layer_index - 1];
        for i in (0..previous_layer.len()).step_by(2) {
            let left = previous_layer[i];
            let right = if i + 1 < previous_layer.len() {
                previous_layer[i + 1]
            } else {
                // Duplicate hash in case of odd number of leaves / unbalanced tree
                left
            };
            let mut combined = [left, right];
            // Sort pairs for easier verification
            combined.sort();
            let node = keccak256(&combined.concat());
            layer.push(node);
        }
        layers.push(layer);
    }
    // Reverse to get root at the first layer
    layers.reverse();
    return layers;
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

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    return output;
}
