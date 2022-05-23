#[cfg(test)]
mod tests {

    use rust_merkletree::{verify_proof, MerkleTree};

    fn strip_hex_prefix (s: &str) -> &str {
        if &s[0..2] == "0x" {
            return &s[2..];
        }
        return s;
    }

    fn hex_to_u8 (s: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        assert_eq!(hex::decode_to_slice(strip_hex_prefix(s), &mut bytes), Ok(()));
        return bytes;
    }

    #[test]
    fn test_verify_proof() {
        let proof = [
            "0x28589ba9f30d1e08cb23a0bf483827c65c67d600b92867ea4faaa451efc36fef",
            "0x7c17a1b0f46e7348cf166eecf704942a8504bfaef555a69f880bc300ae0b3cb6",
            "0xcfae0eb2269180cff88da7eef192030c90dc8714fadb4c38160130e3baa6c5e6",
            "0x6f61d33efd53dd8555d3f2493e297ed5281610f707c2a6fffad0d95c9b3fb3f8",
            "0x85283092dd129ad6c80d873a9a1e77fb691571e683903f9f3ccc27f2d225ca69",
            "0xd3140478bc3b340b2f1f33b7ad3fff0298a807a0c905827e672cf0c38b36e67a",
            "0x72f7d980577b8b9103144730c648d6b7f065e131e2ade842a634a5ab2c135dec",
            "0xbfc32e5e5cddfa03a5fa151d1d90a35c873b694768a808fc3ea1f33a7d847ce9",
            "0xfc234652b54e7b0255b5cf12757ad4c8be2601055726495e75f13853c9ef0e85",
            "0x4f854e8bfbfbd1e82a4ed2c1abfdecd897062fce419b3c07cfe37f04d57e309d",
            "0xd7821c799898785cdfff135d498f2ee0dbd69477b41661d122622d791b7f26c7",
            "0xb223ca49ed3875a37446feb211bc0610cc35ba3d5e59349e8adffadaf7529f85",
            "0x1fe2900f87574dfd51c79cfda30dc8173acae447c9a57a29c3bb6f8c6cb09a37",
            "0x0432d89baffd3d97db8bdac0bae49e19da604e130e45f024e4fee755f689e9f3",
            "0x8ed08cac37d39e938a05e17bd4d501a8fd4aea8d482301e85c696aa5e149728e",
        ].into_iter().map(|x| hex_to_u8(x)).collect();
        let leaf = hex_to_u8("0x60e2ab95d8401a01f79a5ef99732da234912df7d9d6a20b72b129c7504256cac");
        let root = hex_to_u8("0xadbd1f4ac8653b35d3e4e3383beeea3a616b3efaa94932a654035a03c49313e6");
        let result = verify_proof(root, proof, leaf);
        assert_eq!(result, true);
    }
}
