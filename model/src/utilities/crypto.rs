use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};
use base58::{ToBase58};

pub fn checksum(data: &[u8]) -> Vec<u8> {
    let hash_once = Sha256::digest(&data);
    let hash_twice = Sha256::digest(&hash_once);
    hash_twice.to_vec()
}

pub fn hash160(bytes: &[u8]) -> Vec<u8> {
    let sha256 = Sha256::digest(&bytes);
    let ripemd160 = Ripemd160::digest(&sha256);
    ripemd160.to_vec()
}

pub fn base58_encode_check(bytes: &[u8]) -> String {
    let mut check = [0u8; 32];
    let mut sha = Sha256::new();
    sha.input(bytes);
    check.copy_from_slice(sha.result().as_slice());
    sha = Sha256::new();
    sha.input(&check);
    check.copy_from_slice(sha.result().as_slice());

    let mut output = bytes.to_vec();
    for &b in check.iter().take(4) {
        output.push(b);
    }

    output.to_base58()
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

    fn test_checksum(data: &[u8], expected: &[u8; 32]) {
        let entropy = hex::decode(data).expect("hex decode failed: ");
        let result = checksum(&entropy);
        assert_eq!(result, expected);
    }

    fn test_hash160(data: &[u8], expected: &[u8; 20]) {
        let entropy = hex::decode(data).expect("hex decode failed: ");
        let result = hash160(&entropy);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_functionality_checksum() {
        let expected_bytes : [u8; 32] = [129, 252, 73, 37, 97, 218, 86, 131, 47, 154, 60, 225, 208, 86, 158, 161, 0, 199, 105, 73, 84, 93, 59, 98, 84, 241, 8, 106, 51, 183, 20, 19];
        test_checksum(
            b"00000000000000000000000000000000",
            &expected_bytes
        )
    }

    #[test]
    fn test_functionality_hash160() {
        let expected_bytes : [u8; 20] = [228, 53, 47, 114, 53, 109, 181, 85, 114, 22, 81, 170, 97, 46, 0, 55, 145, 103, 179, 15];
        test_hash160(
            b"00000000000000000000000000000000",
            &expected_bytes
        )
    }
}