use sha2::{Digest, Sha256};

// unused
// pub fn to_hex_string(bytes: &[u8]) -> String {
//     let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
//     strs.join("")
// }

pub fn checksum(data: &[u8]) -> Vec<u8> {
    let hash_once = Sha256::digest(&data);
    let hash_twice = Sha256::digest(&hash_once);
    hash_twice.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_checksum(data: &[u8], expected: &[u8; 32]) {
        let entropy = hex::decode(data).expect("hex decode failed: ");
        let result = checksum(&entropy);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_functionality_checksum() {
        let expected_bytes: [u8; 32] = [
            129, 252, 73, 37, 97, 218, 86, 131, 47, 154, 60, 225, 208, 86, 158, 161, 0, 199, 105,
            73, 84, 93, 59, 98, 84, 241, 8, 106, 51, 183, 20, 19,
        ];
        test_checksum(b"00000000000000000000000000000000", &expected_bytes)
    }
}
