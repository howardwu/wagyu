use keypair::KeyPair;
use std::fmt;
use utils:: {to_hex_string, to_checksum_address};
use tiny_keccak::keccak256;

/// Represents an Ethereum Address
#[derive(Serialize, Debug)]
pub struct Address {
    pub address: String,
}

impl Address {

    /// Returns an Address given a KeyPair object
    pub fn from_key_pair(key_pair: &KeyPair) -> Address {
        let public_key = key_pair.to_public_key().serialize_uncompressed();
		let hash = keccak256(&public_key[1..]);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        let address = to_hex_string(&address_bytes).to_lowercase();
        let checksum_address = to_checksum_address(&address);
        
        Address {
            address: checksum_address,
        }
    }
    
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", self.address)
    }
}