//! Monero Wallet generator
use network::{Network, get_prefix};

use std::fmt;


use super::prelude::*;
use arrayvec::ArrayVec;
use base58::ToBase58;
use ed25519::{keypair_from_bytes, PublicKey};
use hex_slice::HexSlice;
use openssl::bn::BigNumContext;
use openssl::rand::rand_bytes;
use tiny_keccak::keccak256;


/// Represents Monero keypairs
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MoneroWallet {
    /// public monero address
    pub address: String, 
    /// private spend key
    pub spend_private_key: String,
    /// public spend key
    pub spend_public_key: String,
    /// private view key
    pub view_private_key: String,
    /// public view key
    pub view_public_key: String,
}

impl MoneroWallet {
    /// Generates a new MoneroWallet for a given `network`
    pub fn new(network: Network) -> Result<MoneroWallet> {
        let mut seed = [0; 32];
        rand_bytes(&mut seed[..])?;

        let mut ctx = BigNumContext::new()?;

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address = MoneroWallet::generate_address(network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address: address,
            spend_private_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            spend_public_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            view_private_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            view_public_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }

    /// Generates a MoneroWallet for a given `network` from a seed.
    pub fn from_seed(network: Network, seed: [u8; 32]) -> Result<MoneroWallet> {

        let mut ctx = BigNumContext::new()?;

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address = MoneroWallet::generate_address(network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address: address,
            spend_private_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            spend_public_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            view_private_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            view_public_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }


    /// Generate the Cryptonote wallet address from the two public keys
    /// reference: https://gitlab.com/standard-mining/wallet-gen/blob/master/src/cryptonote.rs
    pub fn generate_address(network: Network, spend_key: &PublicKey, view_key: &PublicKey) -> Result<String> {
        let mut bytes = ArrayVec::<[u8; 72]>::new();

        // Add coin prefix
        match get_prefix(network) {
            Some(prefix) => bytes.extend(prefix.iter().cloned()),
            None => panic!("Invalid prefix"), // make more descriptive
        };


        // Add public keys
        bytes.extend(spend_key.iter().cloned());
        bytes.extend(view_key.iter().cloned());

        // Add checksum
        let hash = &keccak256(bytes.as_slice())[..4];
        bytes.extend(hash.iter().cloned());

        // Convert to base58 in 8 byte chunks
        let mut base58 = String::new();
        for chunk in bytes.as_slice().chunks(8) {
            let mut part = chunk.to_base58();
            let exp_len = match chunk.len() {
                8 => 11,
                6 => 9,
                5 => 7,
                _ => panic!("Invalid chunk length: {}", chunk.len()),
            };
            let missing = exp_len - part.len();
            if missing > 0 {
                part.insert_str(0, &"11111111111"[..missing]);
            }
            base58.push_str(&part);
        }

        Ok(base58)
    }

    /// returns public address
    pub fn address(&self) -> &String {
        &self.address
    }

    /// returns spend private key
    pub fn spend_private_key(&self) -> &String {
        &self.spend_private_key
    }

    /// returns spend public key
    pub fn spend_public_key(&self) -> &String {
        &self.spend_public_key
    }

    /// returns view private key
    pub fn view_private_key(&self) -> &String {
        &self.view_private_key
    }

    /// returns view public key
    pub fn view_public_key(&self) -> &String {
        &self.view_public_key
    }

    // pub fn to_json(&self) -> String {
    //     to_string_pretty(&self).unwrap()
    // }
}

impl fmt::Display for MoneroWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
        Address:              {}
        Spend Private Key:    {}
        Spend Public Key:     {}
        View Private Key:     {}
        View Public Key:      {}
        ",
            self.address(),
            self.spend_private_key(),
            self.spend_public_key(),
            self.view_private_key(),
            self.view_public_key()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_new_wallet() {
        println!("Monero {:?}", MoneroWallet::new(Network::Mainnet).unwrap())
    }

    // #[test]
    // fn test_from_seed() {

    //     let seed = [
    //         0xbd, 0xb2, 0x5d, 0x9d, 0x7b, 0xdb, 0xda, 0x38, 0x97, 0xf6, 0xc9, 0x42, 0x7a, 0xd6, 0x57,
    //         0xd1, 0x56, 0x75, 0xa9, 0x4a, 0x06, 0xf0, 0xdb, 0x66, 0xb9, 0xb0, 0x53, 0xb0, 0xb2, 0x78,
    //         0xa8, 0x00,
    //     ];

    //     let wallet = MoneroWallet::from_seed(Network::Mainnet, seed).unwrap();

    //     assert_eq!(
    //         &wallet.address,
    //         "4B5hMDhQyxb3aCpo7aQjrN8WCVfW3fRZwYGwDiMYBuHdPSfxSxxk5PG7arpdLpLi91N8ozt129c4w2vxhfQURRP8JQHmbvi");
    // }

    // #[test]
    // fn test_generate_from() {






    //     let wallet = MoneroWallet::generate_address(
    //         Network::Mainnet,
    //         PublicKey::Target("f99782b370c9100f613e341bf2577f2cdc28d6a3795e86bafabcc0cd3fb05486"),
    //         PublicKey::Target("2cf5e093e437e3275ca066fdf27fdc7e5b1ae7c6fe98600b8a72dc213294b39a"),
    //     ).unwrap();
    //     assert_eq!(wallet, "4B5hMDhQyxb3aCpo7aQjrN8WCVfW3fRZwYGwDiMYBuHdPSfxSxxk5PG7arpdLpLi91N8ozt129c4w2vxhfQURRP8JQHmbvi");
    // }
}
