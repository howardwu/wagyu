use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};

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
